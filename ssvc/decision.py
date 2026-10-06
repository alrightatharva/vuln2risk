from enum import Enum

class SSVCDecision(Enum):
    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"

class SSVCEngine:
    """
    Design Decision: Pure CVSS ranking is insufficient for operational prioritization.
    A CVSS 9.8 on an internal, isolated host with no public exploit is less urgent than
    a CVSS 7.0 vulnerability in the CISA KEV catalog on an internet-facing web server.
    
    This engine combines exploitation evidence (KEV + EPSS), exposure, and asset
    criticality to produce SLA-driven decisions rather than theoretical severity rankings.
    """
    
    @staticmethod
    def evaluate(finding) -> SSVCDecision:
        is_exploited = finding.is_in_cisa_kev or (finding.epss_score and finding.epss_score >= 0.5)
        is_critical_asset = finding.asset_criticality in ["High", "Critical"]
        
        if is_exploited:
            if is_critical_asset or finding.is_internet_facing:
                finding.remediation_sla_days = 2
                return SSVCDecision.ACT
            finding.remediation_sla_days = 14
            return SSVCDecision.ATTEND
            
        if finding.cvss_base and finding.cvss_base >= 7.0:
            if is_critical_asset and finding.is_internet_facing:
                finding.remediation_sla_days = 14
                return SSVCDecision.ATTEND
            finding.remediation_sla_days = 30
            return SSVCDecision.TRACK_STAR
            
        finding.remediation_sla_days = 90
        return SSVCDecision.TRACK
    