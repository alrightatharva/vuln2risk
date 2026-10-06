import xml.etree.ElementTree as ET
from core.models import Finding

class OpenVASParser:
    @staticmethod
    def parse(filepath: str) -> list:
        findings = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            for result in root.findall(".//result"):
                cve = result.find(".//cve")
                if cve is None or cve.text == "NOCVE":
                    continue
                    
                host = result.find(".//host")
                port = result.find(".//port")
                threat = result.find(".//threat")
                name = result.find(".//name")
                
                # Parse CVSS from OpenVAS format
                cvss = 0.0
                if threat is not None and threat.text in ['High', 'Critical']:
                    cvss = 8.0 # Fallback mapping if exact CVSS vector isn't extracted
                
                findings.append(Finding(
                    title=name.text if name is not None else "OpenVAS Finding",
                    target_host=host.text if host is not None else "Unknown",
                    target_port=int(port.text.split('/')[0]) if port is not None and '/' in port.text else 0,
                    protocol=port.text.split('/')[1] if port is not None and '/' in port.text else "tcp",
                    tool_source="openvas",
                    raw_evidence="",
                    cve_id=cve.text.strip(),
                    cvss_base=cvss
                ))
        except Exception:
            pass
            
        return findings