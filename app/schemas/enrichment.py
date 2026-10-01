from enum import Enum
from pydantic import BaseModel, Field


class ReputationVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IoCEnrichment(BaseModel):
    ioc: str
    ioc_type: str
    verdict: ReputationVerdict = ReputationVerdict.UNKNOWN
    score: int = Field(default=0, ge=0, le=100, description="Confidence/Threat score 0-100")
    provider: str
    details: dict = Field(default_factory=dict)
    raw_response: dict = Field(default_factory=dict)


class AlertEnrichmentReport(BaseModel):
    enrichments: list[IoCEnrichment] = Field(default_factory=list)
    malicious_count: int = 0
    suspicious_count: int = 0
    benign_count: int = 0
    unknown_count: int = 0