from abc import ABC, abstractmethod
from uuid import UUID

from app.schemas.alert import NormalizedAlert


class AlertRepositoryInterface(ABC):
    @abstractmethod
    async def save(self, alert: NormalizedAlert) -> NormalizedAlert:
        """Persist a normalized alert."""

    @abstractmethod
    async def get_by_id(self, alert_id: UUID) -> NormalizedAlert | None:
        """Retrieve an alert by its unique UUID."""
