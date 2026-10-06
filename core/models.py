from dataclasses import dataclass
from enum import Enum
from typing import Optional

class AssetCriticality(Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

class SSVCDecision(Enum):
    Track = "Track"
    TrackStar = "Track*"
    Attend = "Attend"
    Act = "Act"

@dataclass
class Finding:
    title: str
    target_host: str
    target_port: int
    protocol: str
    tool_source: str
    raw_evidence: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    cvss_base: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_in_cisa_kev: bool = False
    is_internet_facing: bool = False
    asset_criticality: AssetCriticality = AssetCriticality.Medium
    ssvc_decision: Optional[SSVCDecision] = None
    remediation_sla_days: Optional[int] = None
    remediation_guidance: Optional[str] = None
