from abc import ABC, abstractmethod
from app.schemas.incident import Incident
from app.schemas.ticketing import TicketRecord


class TicketingProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the ticketing backend."""
        pass

    @abstractmethod
    async def create_ticket(self, incident: Incident) -> TicketRecord:
        """Transforms an incident and persists a ticket in the target system."""
        pass

    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        """Retrieves ticket data by ID."""
        pass