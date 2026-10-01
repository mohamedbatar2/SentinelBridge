from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from app.schemas.alert import AlertSeverity, HostInfo
from app.schemas.enrichment import AlertEnrichmentReport
from app.schemas.ioc import ExtractedIoCSet
from app.schemas.mitre import AlertMitreReport
from app.schemas.risk import RiskAssessment


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentTimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: str
    actor: str = "SYSTEM_SOAR"
    notes: str | None = None


class Incident(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    title: str
    severity: AlertSeverity
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Core Security Context
    host: HostInfo
    risk: RiskAssessment
    extracted_iocs: ExtractedIoCSet
    enrichment: AlertEnrichmentReport
    mitre: AlertMitreReport
    
    # Operations & Auditing
    ticket_id: str | None = None
    assigned_analyst: str | None = None
    timeline: list[IncidentTimelineEntry] = Field(default_factory=list)
    analyst_notes: list[str] = Field(default_factory=list)


class IncidentUpdateStatus(BaseModel):
    new_status: IncidentStatus
    actor: str
    notes: str | None = None