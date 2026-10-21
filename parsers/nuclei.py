import json
from typing import List
from core.models import Finding

class NucleiParser:
    @staticmethod
    def parse(file_path: str) -> List[Finding]:
        findings = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "Unknown")
                    port = int(data.get("port", 0)) if data.get("port") else 0
                    info = data.get("info", {})
                    
                    classification = info.get("classification", {})
                    cve_ids = classification.get("cve-id", [])
                    if not cve_ids:
                        cve_ids = [None]
                        
                    cvss_score = classification.get("cvss-score", 0.0)
                    
                    # Extract CPE strings (can be string or list in Nuclei schema)
                    cpe_entry = classification.get("cpe")
                    cpes = []
                    if isinstance(cpe_entry, list):
                        cpes = [str(c).strip() for c in cpe_entry if c and str(c).strip()]
                    elif isinstance(cpe_entry, str) and cpe_entry.strip():
                        cpes = [cpe_entry.strip()]

                    primary_cpe = cpes[0] if cpes else None
                    
                    for cve in cve_ids:
                        findings.append(Finding(
                            title=f"Nuclei: {info.get('name', data.get('template-id', 'Unknown'))}",
                            target_host=host,
                            target_port=port,
                            protocol="tcp",
                            tool_source="nuclei",
                            cve_id=cve,
                            service_name=data.get("type", "unknown"),
                            raw_evidence=data.get("extracted-results", [""])[0] if data.get("extracted-results") else info.get("description", ""),
                            cvss_base=float(cvss_score) if cvss_score else None,
                            cpe=primary_cpe,
                            cpes=list(cpes)
                        ))
                except Exception:
                    continue
        return findings
