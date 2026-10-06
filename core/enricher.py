import os
import json
import requests
from datetime import datetime, timedelta

class EnrichmentEngine:
    CACHE_DIR = "cache"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API = "https://api.first.org/data/v1/epss"

    @classmethod
    def load_kev(cls) -> set:
        os.makedirs(cls.CACHE_DIR, exist_ok=True)
        kev_path = os.path.join(cls.CACHE_DIR, "cisa_kev.json")
        
        # Download if missing or older than 24 hours
        if not os.path.exists(kev_path) or datetime.fromtimestamp(os.path.getmtime(kev_path)) < datetime.now() - timedelta(days=1):
            try:
                response = requests.get(cls.KEV_URL, timeout=10)
                response.raise_for_status()
                with open(kev_path, "w") as f:
                    json.dump(response.json(), f)
            except requests.RequestException:
                pass # Fallback to existing cache if offline

        if os.path.exists(kev_path):
            with open(kev_path, "r") as f:
                data = json.load(f)
                return {vuln['cveID'] for vuln in data.get('vulnerabilities', [])}
        return set()

    @classmethod
    def batch_epss(cls, cve_ids: set) -> dict:
        epss_data = {}
        cve_list = list(cve_ids)
        chunk_size = 100 # Batch limit to respect API constraints
        
        for i in range(0, len(cve_list), chunk_size):
            chunk = cve_list[i:i + chunk_size]
            try:
                res = requests.get(f"{cls.EPSS_API}?cve={','.join(chunk)}", timeout=10)
                if res.status_code == 200:
                    for item in res.json().get('data', []):
                        epss_data[item['cve']] = float(item['epss'])
            except requests.RequestException:
                continue
                
        return epss_data

    @classmethod
    def enrich(cls, findings, is_internet_facing=False, asset_criticality="Medium"):
        kev_cves = cls.load_kev()
        unique_cves = {f.cve_id for f in findings if f.cve_id}
        epss_scores = cls.batch_epss(unique_cves)

        for finding in findings:
            finding.is_internet_facing = is_internet_facing
            finding.asset_criticality = asset_criticality
            
            if finding.cve_id:
                finding.is_in_cisa_kev = finding.cve_id in kev_cves
                finding.epss_score = epss_scores.get(finding.cve_id, 0.0)
                
        return findings