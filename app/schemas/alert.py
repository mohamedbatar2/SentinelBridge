from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator
from app.schemas.ioc import ExtractedIoCSet
# pyrefly: ignore [missing-import]
from app.schemas.enrichment import AlertEnrichmentReport
from app.schemas.risk import RiskAssessment
from app.schemas.mitre import AlertMitreReport


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HostInfo(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip: str | None = Field(default=None, max_length=45)


class ProcessInfo(BaseModel):
    command_line: str = Field(..., min_length=1)
    process_id: int | None = None
    parent_process_id: int | None = None
    image_path: str | None = None


class RawIoCs(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class AlertIngest(BaseModel):
    source: str = Field(..., min_length=2, max_length=50)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity
    rule_id: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=3)
    host: HostInfo
    process: ProcessInfo | None = None
    iocs: RawIoCs = Field(default_factory=RawIoCs)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class NormalizedAlert(AlertIngest):
    alert_id: UUID = Field(default_factory=uuid4)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(default="accepted")
    extracted_iocs: ExtractedIoCSet = Field(default_factory=ExtractedIoCSet)
    enrichment: AlertEnrichmentReport = Field(default_factory=AlertEnrichmentReport)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    mitre: AlertMitreReport = Field(default_factory=AlertMitreReport)