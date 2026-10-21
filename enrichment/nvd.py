import os
import json
import hashlib
import requests
from typing import List, Dict, Any, Optional
from core.models import Finding, AssetCriticality
from core.cpe import parse_cpe

class NVDEngine:
    """
    Proactive NVD API 2.0 polling engine.
    Queries the National Vulnerability Database using discovered CPE strings
    to catch newly disclosed CVEs and Zero-Days before scanners update signatures.
    """
    CACHE_DIR = os.path.join("cache", "nvd")
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @classmethod
    def _cpe_cache_path(cls, cpe_str: str) -> str:
        os.makedirs(cls.CACHE_DIR, exist_ok=True)
        h = hashlib.sha256(cpe_str.encode("utf-8")).hexdigest()[:16]
        return os.path.join(cls.CACHE_DIR, f"{h}.json")

    @classmethod
    def query_cpe(cls, cpe_str: str) -> List[Dict[str, Any]]:
        """
        Queries NVD for a specific CPE string, using local disk cache when available.
        """
        cache_path = cls._cpe_cache_path(cpe_str)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        parsed = parse_cpe(cpe_str)
        if not parsed:
            return []

        # NVD API 2.0 prefers CPE 2.3 format
        query_cpe = parsed.to_cpe23()
        results = []

        try:
            headers = {"User-Agent": "Vuln2Risk-Prioritization-Pipeline"}
            api_key = os.environ.get("NVD_API_KEY")
            if api_key:
                headers["apiKey"] = api_key

            params = {"cpeName": query_cpe, "resultsPerPage": 20}
            res = requests.get(cls.API_URL, params=params, headers=headers, timeout=6)
            
            if res.status_code == 200:
                data = res.json()
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    if not cve_id:
                        continue

                    cvss = None
                    metrics = cve_data.get("metrics", {})
                    # Try CVSS v3.1, v3.0, then v2
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics and metrics[key]:
                            cvss_data = metrics[key][0].get("cvssData", {})
                            cvss = cvss_data.get("baseScore")
                            if cvss:
                                break

                    desc = ""
                    descriptions = cve_data.get("descriptions", [])
                    if descriptions:
                        desc = descriptions[0].get("value", "")

                    results.append({
                        "cve_id": cve_id,
                        "cvss_base": float(cvss) if cvss else None,
                        "description": desc
                    })

                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(results, f)
        except requests.RequestException:
            # Fallback gracefully if NVD is rate-limited or offline
            pass

        return results

    @classmethod
    def discover_unpatched_cves(cls, findings: List[Finding]) -> List[Finding]:
        """
        Cross-references findings against NVD to proactively discover
        unpatched CVEs on discovered CPEs not detected by the original scanners.
        """
        existing_host_port_cves = {
            (f.target_host, f.target_port, f.cve_id) for f in findings if f.cve_id
        }

        proactive_findings = []
        cpes_seen = set()

        for f in findings:
            if not f.cpe or f.cpe in cpes_seen:
                continue
            cpes_seen.add(f.cpe)

            nvd_vulns = cls.query_cpe(f.cpe)
            for v in nvd_vulns:
                cve_id = v["cve_id"]
                if (f.target_host, f.target_port, cve_id) not in existing_host_port_cves:
                    proactive_findings.append(Finding(
                        title=f"{f.service_name or 'Service'} (NVD Proactive): {cve_id}",
                        target_host=f.target_host,
                        target_port=f.target_port,
                        protocol=f.protocol,
                        tool_source="nvd_proactive",
                        cve_id=cve_id,
                        service_name=f.service_name,
                        service_version=f.service_version,
                        cvss_base=v["cvss_base"],
                        description=v["description"],
                        cpe=f.cpe,
                        cpes=list(f.cpes),
                        is_internet_facing=f.is_internet_facing,
                        asset_criticality=f.asset_criticality
                    ))
                    existing_host_port_cves.add((f.target_host, f.target_port, cve_id))

        return proactive_findings
