from core.models import AssetCriticality, Finding, SSVCDecision

class SSVCEngine:
    @staticmethod
    def evaluate(finding: Finding) -> SSVCDecision:
        has_active_exploitation = finding.is_in_cisa_kev or (finding.epss_score is not None and finding.epss_score >= 0.5)
        is_exposed = finding.is_internet_facing
        is_critical_asset = finding.asset_criticality in [AssetCriticality.High, AssetCriticality.Critical]

        # Build Explainability Justification
        reasons = []
        if finding.is_in_cisa_kev: reasons.append("✓ CISA KEV Listed")
        if finding.epss_score and finding.epss_score > 0.0: reasons.append(f"✓ EPSS: {finding.epss_score*100:.2f}%")
        if is_exposed: reasons.append("✓ Internet-facing")
        reasons.append(f"✓ Asset Criticality: {finding.asset_criticality.value}")
        if finding.cvss_base: reasons.append(f"✓ CVSS: {finding.cvss_base}")
        finding.justification = "\n".join(reasons)

        if has_active_exploitation:
            if is_exposed or is_critical_asset:
                finding.remediation_sla_days = 2
                return SSVCDecision.ACT
            finding.remediation_sla_days = 14
            return SSVCDecision.ATTEND

        if finding.cvss_base is not None and finding.cvss_base >= 7.0 and is_exposed:
            finding.remediation_sla_days = 30
            return SSVCDecision.TRACK_STAR

        finding.remediation_sla_days = 90
        return SSVCDecision.TRACK
