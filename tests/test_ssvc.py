import pytest
from core.models import Finding, AssetCriticality, SSVCDecision
from ssvc.decision import SSVCEngine

def test_ssvc_act_decision():
    # Test a critical, internet-facing finding in the KEV catalog
    finding = Finding(
        title="Test Critical Flaw",
        target_host="10.0.0.1",
        target_port=443,
        protocol="tcp",
        tool_source="mock",
        raw_evidence="",
        cvss_base=9.8,
        is_in_cisa_kev=True,
        is_internet_facing=True,
        asset_criticality=AssetCriticality.High
    )
    
    decision = SSVCEngine.evaluate(finding)
    
    assert decision == SSVCDecision.Act
    assert finding.remediation_sla_days == 2

def test_ssvc_track_decision():
    # Test a low severity, internal finding not in KEV
    finding = Finding(
        title="Test Low Flaw",
        target_host="10.0.0.1",
        target_port=80,
        protocol="tcp",
        tool_source="mock",
        raw_evidence="",
        cvss_base=4.5,
        is_in_cisa_kev=False,
        is_internet_facing=False,
        asset_criticality=AssetCriticality.Low
    )
    
    decision = SSVCEngine.evaluate(finding)
    
    assert decision == SSVCDecision.Track
    assert finding.remediation_sla_days == 90
