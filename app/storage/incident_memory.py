from abc import ABC, abstractmethod
from uuid import UUID
from app.schemas.incident import Incident


class IncidentRepositoryInterface(ABC):
    @abstractmethod
    async def save(self, incident: Incident) -> Incident:
        """Persist or update an incident."""
        pass

    @abstractmethod
    async def get_by_id(self, incident_id: UUID) -> Incident | None:
        """Retrieve an incident by unique UUID."""
        pass

    @abstractmethod
    async def get_by_alert_id(self, alert_id: UUID) -> Incident | None:
        """Retrieve an incident correlated to a specific alert ID."""
        pass

    @abstractmethod
    async def list_all(self) -> list[Incident]:
        """List all active incidents."""
        pass


class InMemoryIncidentRepository(IncidentRepositoryInterface):
    def __init__(self) -> None:
        self._store: dict[UUID, Incident] = {}

    async def save(self, incident: Incident) -> Incident:
        self._store[incident.incident_id] = incident
        return incident

    async def get_by_id(self, incident_id: UUID) -> Incident | None:
        return self._store.get(incident_id)

    async def get_by_alert_id(self, alert_id: UUID) -> Incident | None:
        for inc in self._store.values():
            if inc.alert_id == alert_id:
                return inc
        return None

    async def list_all(self) -> list[Incident]:
        return list(self._store.values())

    def clear(self) -> None:
        self._store.clear()


incident_repository = InMemoryIncidentRepository()