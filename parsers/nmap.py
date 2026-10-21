import xml.etree.ElementTree as ET
import re
from typing import List
from core.models import Finding

class NmapParser:
    @staticmethod
    def parse(file_path: str) -> List[Finding]:
        findings = []
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host in root.findall('host'):
            ip_addr = host.find("address[@addrtype='ipv4']")
            target_host = ip_addr.get('addr') if ip_addr is not None else "Unknown"

            for port in host.findall('.//port'):
                if port.find('state').get('state') != 'open':
                    continue
                    
                port_id = int(port.get('portid', 0))
                protocol = port.get('protocol', 'tcp')
                
                service = port.find('service')
                service_name = service.get('name', 'Unknown') if service is not None else 'Unknown'
                
                product = service.get('product', '') if service is not None else ''
                version = service.get('version', '') if service is not None else ''
                service_version = f"{product} {version}".strip() or "Unknown Version"

                # Extract CPE strings from service definition
                cpes = []
                if service is not None:
                    for cpe_elem in service.findall('cpe'):
                        if cpe_elem.text and cpe_elem.text.strip():
                            cpes.append(cpe_elem.text.strip())

                # Select primary CPE: prioritize application ('cpe:/a:'), then OS or first available
                primary_cpe = None
                for c in cpes:
                    if ":a:" in c or c.startswith("cpe:/a"):
                        primary_cpe = c
                        break
                if not primary_cpe and cpes:
                    primary_cpe = cpes[0]

                vuln_scripts = port.findall(".//script[@id='vulners']")
                
                if not vuln_scripts:
                    findings.append(Finding(
                        title=f"Open Port: {port_id}/{protocol}",
                        target_host=target_host,
                        target_port=port_id,
                        protocol=protocol,
                        tool_source="nmap",
                        cve_id=None,
                        service_name=service_name,
                        service_version=service_version,
                        raw_evidence="",
                        cpe=primary_cpe,
                        cpes=list(cpes)
                    ))
                    continue

                for script in vuln_scripts:
                    output = script.get('output', '')
                    lines = output.split('\n')
                    cve_found = False
                    
                    for line in lines:
                        # Extract CVE and CVSS score from Nmap vulners output
                        match = re.search(r'(CVE-\d{4}-\d+)\s+([\d\.]+)', line)
                        if match:
                            cve_id = match.group(1)
                            cvss_base = float(match.group(2))
                            cve_found = True
                            
                            findings.append(Finding(
                                title=f"{service_name}: {cve_id}",
                                target_host=target_host,
                                target_port=port_id,
                                protocol=protocol,
                                tool_source="nmap",
                                cve_id=cve_id,
                                service_name=service_name,
                                service_version=service_version,
                                raw_evidence=output,
                                cvss_base=cvss_base,
                                cpe=primary_cpe,
                                cpes=list(cpes)
                            ))
                            
                    if not cve_found:
                        findings.append(Finding(
                            title=f"Open Port: {port_id}/{protocol}",
                            target_host=target_host,
                            target_port=port_id,
                            protocol=protocol,
                            tool_source="nmap",
                            cve_id=None,
                            service_name=service_name,
                            service_version=service_version,
                            raw_evidence=output,
                            cpe=primary_cpe,
                            cpes=list(cpes)
                        ))

        return findings
