from core.models import AssetCriticality, Finding, SSVCDecision

class SSVCEngine:
    """
    SSVC-Inspired Decision Engine.

    Note on SSVC Alignment:
    The official CISA Stakeholder-Specific Vulnerability Categorization (SSVC)
    decision tree evaluates: Exploitation, Automatable, Technical Impact,
    Mission Prevalence, and Public Well-being Impact.

    In automated vulnerability pipelines, organizational human factors like
    'Public Well-being' or 'Mission Prevalence' cannot be directly extracted
    from scanner files. Vuln2Risk operationalizes SSVC principles into an
    automated, defensible decision tree tailored for CI/CD and SOC workflows:

      1. Exploitation: Evaluated via CISA KEV listing, public weaponization
         (Metasploit / Exploit-DB), or FIRST EPSS >= 0.50 (representing the
         highest probability tier of real-world exploitation).
      2. Exposure: Evaluated via asset network boundaries (Internet-facing DMZ
         vs. Internal network).
      3. Mission Impact: Evaluated via Asset Criticality (Critical, High, Medium, Low)
         mapped from asset inventories.
      4. Tech Debt & Lifecycle: Escalates unsupported End-of-Life (EOL) software
         where vendor security patches will never be published.

    Remediation SLAs:
      - ACT (48 Hours): Active exploitation on exposed/critical assets or EOL software.
      - ATTEND (14 Days): Active exploitation internal, or exposed unpatchable EOL debt.
      - TRACK* (30 Days): High CVSS (>=7.0) on exposed systems or unpatched internal EOL.
      - TRACK (90 Days): Routine maintenance cycle for low-risk findings.
    """

    @staticmethod
    def evaluate(finding: Finding) -> SSVCDecision:
        has_active_exploitation = (
            finding.is_in_cisa_kev or
            (finding.epss_score is not None and finding.epss_score >= 0.5) or
            finding.has_public_exploit
        )
        is_exposed = finding.is_internet_facing
        is_critical_asset = finding.asset_criticality in [AssetCriticality.High, AssetCriticality.Critical]

        # Build Explainability Justification
        reasons = []
        if finding.is_in_cisa_kev:
            reasons.append("✓ CISA KEV Listed")
        if finding.has_public_exploit and not finding.is_in_cisa_kev:
            if finding.exploit_references:
                reasons.append(f"✓ Public Exploit: {finding.exploit_references[0]}")
            else:
                reasons.append("✓ Weaponized Exploit Available")
        if finding.epss_score and finding.epss_score > 0.0:
            reasons.append(f"✓ EPSS: {finding.epss_score*100:.2f}%")
        if finding.is_eol:
            reasons.append(f"⚠ End-of-Life (EOL) Software ({finding.eol_cycle or 'Unsupported'})")
        if is_exposed:
            reasons.append("✓ Internet-facing")
        reasons.append(f"✓ Asset Criticality: {finding.asset_criticality.value}")
        if finding.cvss_base:
            reasons.append(f"✓ CVSS: {finding.cvss_base}")
        finding.justification = "\n".join(reasons)

        # SSVC Decision logic incorporating EOL and Weaponization
        if has_active_exploitation:
            if is_exposed or is_critical_asset or finding.is_eol:
                finding.remediation_sla_days = 2
                return SSVCDecision.ACT
            finding.remediation_sla_days = 14
            return SSVCDecision.ATTEND

        # Elevate EOL (unpatchable tech debt) on exposed or critical assets
        if finding.is_eol and (is_exposed or is_critical_asset):
            finding.remediation_sla_days = 14
            return SSVCDecision.ATTEND

        if finding.cvss_base is not None and finding.cvss_base >= 7.0 and is_exposed:
            finding.remediation_sla_days = 30
            return SSVCDecision.TRACK_STAR

        if finding.is_eol:
            finding.remediation_sla_days = 30
            return SSVCDecision.TRACK_STAR

        finding.remediation_sla_days = 90
        return SSVCDecision.TRACK
