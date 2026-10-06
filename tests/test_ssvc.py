import pytest
from core.models import AssetCriticality, Finding, SSVCDecision
from ssvc.decision import SSVCEngine

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
