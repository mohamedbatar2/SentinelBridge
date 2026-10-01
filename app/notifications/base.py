from abc import ABC, abstractmethod
from app.schemas.incident import Incident
from app.schemas.notification import NotificationDeliveryReceipt


class NotificationProvider(ABC):
    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Identifier for the notification channel."""
        pass

    @abstractmethod
    async def send_incident_alert(self, incident: Incident) -> NotificationDeliveryReceipt:
        """Formats and delivers an incident notification."""
        pass