from enum import Enum
from pydantic import BaseModel, Field


class MitreTactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class MitreMapping(BaseModel):
    technique_id: str = Field(..., pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str
    tactic: MitreTactic
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: str


class AlertMitreReport(BaseModel):
    mappings: list[MitreMapping] = Field(default_factory=list)