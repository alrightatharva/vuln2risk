import json
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from core.models import AssetCriticality, Finding
from core.cpe import parse_cpe

@dataclass
class AssetMetadata:
    criticality: Optional[AssetCriticality] = None
    internet_facing: Optional[bool] = None
    owner: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    matched_by: str = ""

class AssetInventory:
    """
    Asset Inventory Manager supporting:
      1. Host-based matching (by IP or Hostname)
      2. CPE-based standardized matching (by exact CPE, prefix, or vendor:product pattern)
      3. Hybrid priority resolution
    """
    def __init__(self, host_rules: Dict[str, Dict[str, Any]] = None, cpe_rules: Dict[str, Dict[str, Any]] = None):
        self.host_rules = host_rules or {}
        self.cpe_rules = cpe_rules or {}

    @classmethod
    def load_from_file(cls, file_path: str) -> "AssetInventory":
        if not file_path or not os.path.exists(file_path):
            return cls()

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        host_rules = {}
        cpe_rules = {}

        if "hosts" in data or "cpes" in data:
            # Structured format
            host_rules = data.get("hosts", {})
            cpe_rules = data.get("cpes", {})
        else:
            # Flat format (auto-detect by key prefix)
            for k, v in data.items():
                if k.startswith("cpe:") or ":" in k and not (k.replace(".", "").isdigit() or "." in k):
                    cpe_rules[k] = v
                else:
                    host_rules[k] = v

        return cls(host_rules=host_rules, cpe_rules=cpe_rules)

    def match(self, finding: Finding, default_criticality: AssetCriticality, default_internet_facing: bool) -> AssetMetadata:
        """
        Matches a Finding against inventory rules.
        Precedence:
          - CPE-based rules allow specific software to define or elevate criticality.
          - Host-based rules define physical network exposure and host baseline.
        """
        matched_host_data = self.host_rules.get(finding.target_host)
        matched_cpe_rule = None
        matched_cpe_key = ""

        # Check CPE matches across all finding CPEs
        all_finding_cpes = list(finding.cpes) if finding.cpes else []
        if finding.cpe and finding.cpe not in all_finding_cpes:
            all_finding_cpes.insert(0, finding.cpe)

        parsed_finding_cpes = [parse_cpe(c) for c in all_finding_cpes if parse_cpe(c)]

        for rule_key, rule_data in self.cpe_rules.items():
            # 1. Exact string match
            if rule_key in all_finding_cpes:
                matched_cpe_rule = rule_data
                matched_cpe_key = rule_key
                break

            # 2. Pattern / component match using CPE helper
            matched = False
            for p_cpe in parsed_finding_cpes:
                if p_cpe and p_cpe.matches(rule_key):
                    matched_cpe_rule = rule_data
                    matched_cpe_key = rule_key
                    matched = True
                    break
            if matched:
                break

        # Resolve Criticality
        final_criticality = default_criticality
        matched_sources = []

        if matched_host_data and "criticality" in matched_host_data:
            try:
                final_criticality = AssetCriticality[matched_host_data["criticality"]]
                matched_sources.append(f"host:{finding.target_host}")
            except KeyError:
                pass

        if matched_cpe_rule and "criticality" in matched_cpe_rule:
            try:
                cpe_crit = AssetCriticality[matched_cpe_rule["criticality"]]
                # CPE rule can override or elevate criticality
                final_criticality = cpe_crit
                matched_sources.append(f"cpe:{matched_cpe_key}")
            except KeyError:
                pass

        # Resolve Internet Facing status
        final_exposure = default_internet_facing
        if matched_host_data and "internet_facing" in matched_host_data:
            final_exposure = bool(matched_host_data["internet_facing"])
            if f"host:{finding.target_host}" not in matched_sources:
                matched_sources.append(f"host:{finding.target_host}")

        if matched_cpe_rule and "internet_facing" in matched_cpe_rule:
            final_exposure = bool(matched_cpe_rule["internet_facing"])
            if f"cpe:{matched_cpe_key}" not in matched_sources:
                matched_sources.append(f"cpe:{matched_cpe_key}")

        # Tags and Owner
        tags = []
        owner = None
        if matched_host_data:
            tags.extend(matched_host_data.get("tags", []))
            owner = matched_host_data.get("owner")
        if matched_cpe_rule:
            tags.extend(matched_cpe_rule.get("tags", []))
            if not owner:
                owner = matched_cpe_rule.get("owner")

        return AssetMetadata(
            criticality=final_criticality,
            internet_facing=final_exposure,
            owner=owner,
            tags=list(set(tags)),
            matched_by=" + ".join(matched_sources) if matched_sources else "default"
        )
