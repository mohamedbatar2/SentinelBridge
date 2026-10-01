from uuid import UUID

from app.schemas.alert import NormalizedAlert
from app.storage.base import AlertRepositoryInterface


class InMemoryAlertRepository(AlertRepositoryInterface):
    def __init__(self) -> None:
        self._store: dict[UUID, NormalizedAlert] = {}

    async def save(self, alert: NormalizedAlert) -> NormalizedAlert:
        self._store[alert.alert_id] = alert
        return alert

    async def get_by_id(self, alert_id: UUID) -> NormalizedAlert | None:
        return self._store.get(alert_id)

    def clear(self) -> None:
        """Used in test fixtures for isolation."""
        self._store.clear()


# Default singleton for Phase 1 in-memory run
alert_repository = InMemoryAlertRepository()
