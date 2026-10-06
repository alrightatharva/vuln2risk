from typing import List, Optional
import xml.etree.ElementTree as ET
from core.models import Finding

class OpenVASParser:
    @staticmethod
    def parse(xml_file_path: str) -> List[Finding]:
        findings = []
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for result in root.findall(".//result"):
            name = result.findtext("name", default="OpenVAS Vulnerability")
            host = result.findtext("host", default="unknown")
            port_text = result.findtext("port", default="0/tcp")
            
            port = 0
            protocol = "tcp"
            if "/" in port_text:
                parts = port_text.split("/")
                if parts[0].isdigit(): port = int(parts[0])
                protocol = parts[1]

            nvt = result.find("nvt")
            cve_id: Optional[str] = None
            cvss_base: Optional[float] = None

            if nvt is not None:
                cve_tag = nvt.findtext("cve")
                if cve_tag and cve_tag.upper().startswith("CVE-"):
                    cve_id = cve_tag.strip()
                
                cvss_text = nvt.findtext("cvss_base")
                if not cvss_text:
                    cvss_text = result.findtext("severity")
                if cvss_text:
                    try:
                        cvss_val = float(cvss_text.strip())
                        if cvss_val > 0.0: cvss_base = cvss_val
                    except ValueError:
                        cvss_base = None

            findings.append(Finding(
                title=name, target_host=host, target_port=port, protocol=protocol,
                tool_source="OpenVAS", cve_id=cve_id, cvss_base=cvss_base
            ))
        return findings
