from datetime import datetime, timezone
from enum import Enum
from uuid import UUID
from pydantic import BaseModel, Field


class NotificationChannel(str, Enum):
    CONSOLE = "console"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"


class NotificationMessage(BaseModel):
    incident_id: UUID
    title: str
    severity: str
    risk_score: int
    hostname: str
    summary: str
    top_iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NotificationDeliveryReceipt(BaseModel):
    channel: NotificationChannel
    delivered: bool
    status_code: int | None = None
    details: str | None = None