from dataclasses import dataclass
from enum import Enum
from typing import Optional

class AssetCriticality(Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

class SSVCDecision(Enum):
    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"

class FindingStatus(Enum):
    OPEN = "Open"
    VALIDATED = "Validated"
    REMEDIATION = "Remediating"
    RETEST = "Retesting"
    FIXED = "Fixed"

@dataclass
class Finding:
    title: str
    target_host: str
    target_port: int
    protocol: str
    tool_source: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_base: Optional[float] = None
    epss_score: Optional[float] = 0.0
    is_in_cisa_kev: bool = False
    is_internet_facing: bool = False
    asset_criticality: AssetCriticality = AssetCriticality.Medium
    ssvc_decision: Optional[SSVCDecision] = None
    remediation_sla_days: Optional[int] = None
    status: FindingStatus = FindingStatus.OPEN
    justification: str = ""
    
    # Restored original parser fields
    raw_evidence: Optional[str] = None
    description: Optional[str] = None
