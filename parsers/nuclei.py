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
                    
                    cve_ids = info.get("classification", {}).get("cve-id", [])
                    if not cve_ids:
                        cve_ids = [None]
                        
                    cvss_score = info.get("classification", {}).get("cvss-score", 0.0)
                    
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
                            cvss_base=float(cvss_score) if cvss_score else None
                        ))
                except Exception:
                    continue
        return findings
