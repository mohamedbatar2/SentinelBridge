from sys import float_repr_style
from uuid import UUID

from pydantic import BaseModel


class AlertIngestResponse(BaseModel):
    alert_id: UUID
    status: str
    message: str
    incident_promoted: bool = False
