from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class TicketPriority(str, Enum):
    LOW = "P4"
    MEDIUM = "P3"
    HIGH = "P2"
    CRITICAL = "P1"


class TicketPayload(BaseModel):
    title: str
    description: str
    severity: str
    priority: TicketPriority
    tags: list[str] = Field(default_factory=list)
    source_incident_id: UUID
    artifacts: list[dict[str, str]] = Field(default_factory=list)


class TicketRecord(BaseModel):
    ticket_id: str
    provider: str
    external_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "OPEN"
    payload: TicketPayload