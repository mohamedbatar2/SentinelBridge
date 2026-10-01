from enum import Enum
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactor(BaseModel):
    rule: str
    delta: int
    description: str


class RiskAssessment(BaseModel):
    score: int = Field(default=0, ge=0, le=100)
    level: RiskLevel = RiskLevel.LOW
    reasons: list[str] = Field(default_factory=list)
    factors: list[RiskFactor] = Field(default_factory=list)