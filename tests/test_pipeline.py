import pytest
from core.cpe import parse_cpe, CPE
from core.models import Finding, AssetCriticality, SSVCDecision
from parsers.nmap import NmapParser
from parsers.nuclei import NucleiParser
from core.inventory import AssetInventory
from enrichment.eol import EOLEngine
from enrichment.exploit import ExploitEngine
from ssvc.decision import SSVCEngine
from reporters.generator import ReportGenerator

# ============================================================================
# 1. SSVC Decision Engine Tests
# ============================================================================

def test_ssvc_act_on_kev():
    finding = Finding(
        title="Test KEV Vuln", target_host="10.0.0.1", target_port=443,
        protocol="tcp", tool_source="Test", cve_id="CVE-2023-1234",
        is_in_cisa_kev=True, is_internet_facing=True, asset_criticality=AssetCriticality.High
    )
    assert SSVCEngine.evaluate(finding) == SSVCDecision.ACT
    assert finding.remediation_sla_days == 2

def test_ssvc_attend_on_kev_internal():
    finding = Finding(
        title="Internal KEV", target_host="10.0.0.1", target_port=443,
        protocol="tcp", tool_source="Test", cve_id="CVE-2023-1234",
        is_in_cisa_kev=True, is_internet_facing=False, asset_criticality=AssetCriticality.Low
    )
    assert SSVCEngine.evaluate(finding) == SSVCDecision.ATTEND

def test_ssvc_track_star_high_cvss():
    finding = Finding(
        title="High CVSS", target_host="10.0.0.1", target_port=443,
        protocol="tcp", tool_source="Test", cvss_base=7.5, epss_score=0.01,
        is_in_cisa_kev=False, is_internet_facing=True, asset_criticality=AssetCriticality.Medium
    )
    assert SSVCEngine.evaluate(finding) == SSVCDecision.TRACK_STAR

def test_ssvc_track_routine():
    finding = Finding(
        title="Routine", target_host="10.0.0.1", target_port=443,
        protocol="tcp", tool_source="Test", cvss_base=5.0, epss_score=0.01,
        is_in_cisa_kev=False, is_internet_facing=False, asset_criticality=AssetCriticality.Low
    )
    assert SSVCEngine.evaluate(finding) == SSVCDecision.TRACK

def test_ssvc_eol_escalation():
    finding = Finding(
        title="EOL Routine Issue",
        target_host="192.168.1.10",
        target_port=80,
        protocol="tcp",
        tool_source="nmap",
        cvss_base=5.0,
        is_internet_facing=True,
        asset_criticality=AssetCriticality.Medium,
        is_eol=True,
        eol_cycle="2.2"
    )
    decision = SSVCEngine.evaluate(finding)
    assert decision == SSVCDecision.ATTEND
    assert finding.remediation_sla_days == 14
    assert "End-of-Life" in finding.justification

def test_ssvc_weaponized_escalation():
    finding = Finding(
        title="Publicly Weaponized Internal Vuln",
        target_host="192.168.1.10",
        target_port=21,
        protocol="tcp",
        tool_source="nuclei",
        cve_id="CVE-2011-2523",
        has_public_exploit=True,
        exploit_references=["Metasploit: exploit/unix/ftp/vsftpd_234_backdoor"],
        is_internet_facing=False,
        asset_criticality=AssetCriticality.Low
    )
    decision = SSVCEngine.evaluate(finding)
    assert decision == SSVCDecision.ATTEND
    assert finding.remediation_sla_days == 14

# ============================================================================
# 2. CPE Parser & Normalizer Tests
# ============================================================================

def test_parse_cpe22_uri():
    cpe_str = "cpe:/a:openbsd:openssh:4.7p1"
    cpe = parse_cpe(cpe_str)
    assert cpe is not None
    assert cpe.raw == cpe_str
    assert cpe.part == "a"
    assert cpe.part_type == "Application"
    assert cpe.vendor == "openbsd"
    assert cpe.product == "openssh"
    assert cpe.version == "4.7p1"
    assert "Openssh 4.7p1" in cpe.human_name

def test_parse_cpe22_os():
    cpe_str = "cpe:/o:linux:linux_kernel"
    cpe = parse_cpe(cpe_str)
    assert cpe is not None
    assert cpe.part == "o"
    assert cpe.part_type == "Operating System"
    assert cpe.vendor == "linux"
    assert cpe.product == "linux_kernel"

def test_parse_cpe23_fs():
    cpe_str = "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"
    cpe = parse_cpe(cpe_str)
    assert cpe is not None
    assert cpe.part == "a"
    assert cpe.vendor == "vsftpd_project"
    assert cpe.product == "vsftpd"
    assert cpe.version == "2.3.4"
    assert cpe.part_type == "Application"

def test_cpe_conversions():
    cpe_str = "cpe:/a:apache:http_server:2.2.8"
    cpe = parse_cpe(cpe_str)
    assert cpe is not None
    cpe23 = cpe.to_cpe23()
    assert cpe23.startswith("cpe:2.3:a:apache:http_server:2.2.8:")
    cpe22 = cpe.to_cpe22()
    assert cpe22 == "cpe:/a:apache:http_server:2.2.8"

def test_cpe_matching():
    cpe = parse_cpe("cpe:/a:apache:http_server:2.2.8")
    assert cpe is not None
    assert cpe.matches("apache")
    assert cpe.matches("apache:http_server")
    assert cpe.matches("cpe:/a:apache:http_server:2.2.8")
    assert cpe.matches("cpe:/a:apache:http_server:*")
    assert not cpe.matches("nginx")
    assert not cpe.matches("apache:tomcat")

def test_cpe_invalid():
    assert parse_cpe(None) is None
    assert parse_cpe("") is None
    assert parse_cpe("invalid_cpe_string") is None

def test_finding_cpe_integration():
    f = Finding(
        title="OpenSSH Vuln",
        target_host="192.168.1.10",
        target_port=22,
        protocol="tcp",
        tool_source="nmap",
        cpe="cpe:/a:openbsd:openssh:4.7p1",
        cpes=["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"]
    )
    assert f.cpe == "cpe:/a:openbsd:openssh:4.7p1"
    assert len(f.cpes) == 2
    assert f.parsed_cpe is not None
    assert f.parsed_cpe.vendor == "openbsd"
    assert f.parsed_cpe.product == "openssh"

def test_nmap_parser_extracts_cpe():
    findings = NmapParser.parse("sample_data/nmap_scan.xml")
    assert len(findings) > 0
    ftp_findings = [f for f in findings if f.target_port == 21]
    assert len(ftp_findings) > 0
    assert any("vsftpd" in (f.cpe or "") for f in ftp_findings)
    ssh_findings = [f for f in findings if f.target_port == 22]
    assert len(ssh_findings) > 0
    assert any("openssh" in (f.cpe or "") for f in ssh_findings)
    assert any(len(f.cpes) >= 2 for f in ssh_findings)

def test_nuclei_parser_extracts_cpe():
    findings = NucleiParser.parse("sample_data/report1.json")
    assert len(findings) > 0
    findings_with_cpe = [f for f in findings if f.cpe is not None]
    assert len(findings_with_cpe) > 0
    vsftpd = [f for f in findings_with_cpe if "vsftpd" in f.cpe]
    assert len(vsftpd) > 0
    assert vsftpd[0].parsed_cpe.vendor == "vsftpd_project"

# ============================================================================
# 3. Asset Inventory & Lifecycle / Exploit Intelligence Tests
# ============================================================================

def test_inventory_cpe_matching():
    rules = {
        "cpes": {
            "cpe:/a:apache:http_server": {
                "criticality": "Critical",
                "internet_facing": True
            },
            "cpe:/a:openbsd:openssh": {
                "criticality": "High"
            }
        },
        "hosts": {
            "192.168.1.50": {
                "criticality": "Low",
                "internet_facing": False
            }
        }
    }
    inv = AssetInventory(host_rules=rules["hosts"], cpe_rules=rules["cpes"])
    f_apache = Finding(
        title="Apache Vuln",
        target_host="192.168.1.50",
        target_port=80,
        protocol="tcp",
        tool_source="nmap",
        cpe="cpe:/a:apache:http_server:2.2.8",
        cpes=["cpe:/a:apache:http_server:2.2.8"]
    )
    meta = inv.match(f_apache, default_criticality=AssetCriticality.Medium, default_internet_facing=False)
    assert meta.criticality == AssetCriticality.Critical
    assert meta.internet_facing is True

def test_inventory_host_fallback():
    rules = {
        "hosts": {
            "10.0.0.1": {
                "criticality": "High",
                "internet_facing": True
            }
        }
    }
    inv = AssetInventory(host_rules=rules["hosts"])
    f = Finding(
        title="Unknown Service",
        target_host="10.0.0.1",
        target_port=9999,
        protocol="tcp",
        tool_source="nmap"
    )
    meta = inv.match(f, default_criticality=AssetCriticality.Low, default_internet_facing=False)
    assert meta.criticality == AssetCriticality.High
    assert meta.internet_facing is True

def test_eol_engine_apache_22():
    is_eol, cycle, eol_date = EOLEngine.check_eol(
        cpe_str="cpe:/a:apache:http_server:2.2.8",
        service_name="http",
        service_version="2.2.8"
    )
    assert is_eol is True
    assert cycle == "2.2"
    assert eol_date is not None

def test_eol_engine_openssh_47():
    is_eol, cycle, eol_date = EOLEngine.check_eol(
        cpe_str="cpe:/a:openbsd:openssh:4.7p1",
        service_name="ssh",
        service_version="4.7p1"
    )
    assert is_eol is True
    assert cycle == "4.7"

def test_exploit_engine_catalog():
    f = Finding(
        title="vsftpd backdoor",
        target_host="192.168.1.10",
        target_port=21,
        protocol="tcp",
        tool_source="nuclei",
        cve_id="CVE-2011-2523"
    )
    ExploitEngine.enrich(f)
    assert f.has_public_exploit is True
    assert any("Metasploit" in ref for ref in f.exploit_references)
    assert any("Exploit-DB" in ref for ref in f.exploit_references)

def test_exploit_engine_raw_evidence_extraction():
    f = Finding(
        title="Custom Exploit",
        target_host="192.168.1.10",
        target_port=8080,
        protocol="tcp",
        tool_source="custom",
        raw_evidence="Referenced at https://www.exploit-db.com/exploits/12345 and rapid7.com/db/modules/exploit/test/exploit_mod"
    )
    ExploitEngine.enrich(f)
    assert f.has_public_exploit is True
    assert "Exploit-DB: 12345" in f.exploit_references
    assert "Metasploit: exploit/test/exploit_mod" in f.exploit_references

# ============================================================================
# 4. Multi-Host & Component Rollup Consolidation Tests
# ============================================================================

def test_multihost_separation():
    f1 = Finding(
        title="Host A SSH Finding 1",
        target_host="192.168.1.10",
        target_port=22,
        protocol="tcp",
        tool_source="nmap",
        service_name="ssh",
        service_version="OpenSSH 8.0",
        ssvc_decision=SSVCDecision.TRACK
    )
    f2 = Finding(
        title="Host A SSH Finding 2",
        target_host="192.168.1.10",
        target_port=22,
        protocol="tcp",
        tool_source="nmap",
        service_name="ssh",
        service_version="OpenSSH 8.0",
        ssvc_decision=SSVCDecision.TRACK
    )
    f3 = Finding(
        title="Host B SSH Finding",
        target_host="192.168.1.20",
        target_port=22,
        protocol="tcp",
        tool_source="nmap",
        service_name="ssh",
        service_version="OpenSSH 8.0",
        ssvc_decision=SSVCDecision.TRACK
    )

    components = ReportGenerator.consolidate_components([f1, f2, f3])
    assert len(components) == 2

    hosts = {c["host"] for c in components}
    assert hosts == {"192.168.1.10", "192.168.1.20"}

    host_a_comp = [c for c in components if c["host"] == "192.168.1.10"][0]
    assert len(host_a_comp["vulns"]) == 2

    host_b_comp = [c for c in components if c["host"] == "192.168.1.20"][0]
    assert len(host_b_comp["vulns"]) == 1

def test_worst_decision_rollup():
    f_track = Finding(
        title="Low issue",
        target_host="10.0.0.1",
        target_port=80,
        protocol="tcp",
        tool_source="nmap",
        service_name="http",
        ssvc_decision=SSVCDecision.TRACK
    )
    f_attend = Finding(
        title="Medium issue",
        target_host="10.0.0.1",
        target_port=80,
        protocol="tcp",
        tool_source="nmap",
        service_name="http",
        ssvc_decision=SSVCDecision.ATTEND
    )
    f_act = Finding(
        title="Emergency zero-day",
        target_host="10.0.0.1",
        target_port=80,
        protocol="tcp",
        tool_source="nmap",
        service_name="http",
        ssvc_decision=SSVCDecision.ACT
    )

    components = ReportGenerator.consolidate_components([f_track, f_attend, f_act])
    assert len(components) == 1
    assert components[0]["worst_decision"] == "Act"
    assert components[0]["breakdown"] == {
        "Act": 1,
        "Attend": 1,
        "Track*": 0,
        "Track": 1
    }

def test_component_metrics_aggregation():
    f1 = Finding(
        title="Vuln 1",
        target_host="10.0.0.5",
        target_port=443,
        protocol="tcp",
        tool_source="nuclei",
        service_name="https",
        cve_id="CVE-2021-1111",
        epss_score=0.25,
        cvss_base=6.0,
        is_in_cisa_kev=True,
        is_eol=False,
        has_public_exploit=True,
        ssvc_decision=SSVCDecision.ACT
    )
    f2 = Finding(
        title="Vuln 2",
        target_host="10.0.0.5",
        target_port=443,
        protocol="tcp",
        tool_source="nuclei",
        service_name="https",
        cve_id="CVE-2021-2222",
        epss_score=0.91,
        cvss_base=9.8,
        is_in_cisa_kev=False,
        is_eol=True,
        has_public_exploit=False,
        ssvc_decision=SSVCDecision.ACT
    )

    components = ReportGenerator.consolidate_components([f1, f2])
    assert len(components) == 1
    comp = components[0]

    assert comp["unique_cves"] == ["CVE-2021-1111", "CVE-2021-2222"]
    assert comp["kev_count"] == 1
    assert comp["eol_count"] == 1
    assert comp["exploit_count"] == 1
    assert comp["max_epss"] == 0.91
    assert comp["max_cvss"] == 9.8
    assert len(comp["vulns"]) == 2

