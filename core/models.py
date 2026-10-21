from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
from core.cpe import parse_cpe, CPE

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

    # CPE integration
    cpe: Optional[str] = None
    cpes: List[str] = field(default_factory=list)

    # Lifecycle & EOL tracking
    is_eol: bool = False
    eol_cycle: Optional[str] = None
    eol_date: Optional[str] = None

    # Weaponization & Exploit intelligence
    has_public_exploit: bool = False
    exploit_references: List[str] = field(default_factory=list)

    @property
    def parsed_cpe(self) -> Optional[CPE]:
        """Returns structured CPE object for the primary CPE if present."""
        return parse_cpe(self.cpe) if self.cpe else None

    @property
    def vendor(self) -> str:
        """Returns the vendor identifier derived from CPE or service name."""
        if self.parsed_cpe and self.parsed_cpe.vendor and self.parsed_cpe.vendor not in ("*", "-"):
            return self.parsed_cpe.vendor
        return self.service_name or "unknown"
