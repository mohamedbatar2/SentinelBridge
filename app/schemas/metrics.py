from pydantic import BaseModel, Field


class SOCMetricsSummary(BaseModel):
    total_alerts: int = 0
    total_incidents: int = 0
    escalation_rate_percent: float = 0.0
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    incidents_by_status: dict[str, int] = Field(default_factory=dict)
    top_mitre_techniques: dict[str, int] = Field(default_factory=dict)
    average_risk_score: float = 0.0