import logging
from datetime import datetime, timezone
from uuid import UUID
from app.connectors.ticketing.base import TicketingProvider
from app.notifications.base import NotificationProvider
from app.schemas.alert import AlertSeverity, NormalizedAlert
from app.schemas.incident import Incident, IncidentStatus, IncidentTimelineEntry
from app.storage.incident_memory import IncidentRepositoryInterface

logger = logging.getLogger("sentinelbridge.incident")


class IncidentStateError(ValueError):
    pass


class IncidentService:
    ALLOWED_TRANSITIONS = {
        IncidentStatus.NEW: {IncidentStatus.TRIAGED, IncidentStatus.FALSE_POSITIVE},
        IncidentStatus.TRIAGED: {IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE},
        IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED, IncidentStatus.FALSE_POSITIVE},
        IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED},
        IncidentStatus.RESOLVED: set(),
        IncidentStatus.FALSE_POSITIVE: set(),
    }

    def __init__(
        self,
        incident_repo: IncidentRepositoryInterface,
        ticketing_provider: TicketingProvider | None = None,
        notification_provider: NotificationProvider | None = None,
        auto_escalate_threshold: int = 70,
    ) -> None:
        self.incident_repo = incident_repo
        self.ticketing_provider = ticketing_provider
        self.notification_provider = notification_provider
        self.auto_escalate_threshold = auto_escalate_threshold

    def should_escalate(self, alert: NormalizedAlert) -> bool:
        if alert.risk.score >= self.auto_escalate_threshold:
            return True
        if alert.severity == AlertSeverity.CRITICAL:
            return True
        if alert.enrichment.malicious_count > 0:
            return True
        return False

    async def evaluate_and_promote(self, alert: NormalizedAlert) -> Incident | None:
        if not self.should_escalate(alert):
            return None

        existing = await self.incident_repo.get_by_alert_id(alert.alert_id)
        if existing:
            return existing

        initial_timeline = [
            IncidentTimelineEntry(
                action="INCIDENT_CREATED",
                actor="SYSTEM_SOAR",
                notes=f"Escalated from alert {alert.alert_id} (Risk Score: {alert.risk.score})",
            )
        ]

        incident = Incident(
            alert_id=alert.alert_id,
            title=f"Incident: {alert.title} on {alert.host.hostname}",
            severity=alert.severity,
            status=IncidentStatus.NEW,
            host=alert.host,
            risk=alert.risk,
            extracted_iocs=alert.extracted_iocs,
            enrichment=alert.enrichment,
            mitre=alert.mitre,
            timeline=initial_timeline,
        )

        # 1. Ticketing Integration
        if self.ticketing_provider:
            try:
                ticket = await self.ticketing_provider.create_ticket(incident)
                incident.ticket_id = ticket.ticket_id
                incident.timeline.append(
                    IncidentTimelineEntry(
                        action="TICKET_DISPATCHED",
                        actor=self.ticketing_provider.provider_name,
                        notes=f"Created ticket {ticket.ticket_id} ({ticket.external_url})",
                    )
                )
            except Exception as exc:
                logger.error(f"Ticketing dispatch failed for incident {incident.incident_id}: {exc}")
                incident.timeline.append(
                    IncidentTimelineEntry(
                        action="TICKET_DISPATCH_FAILED",
                        actor="SYSTEM_SOAR",
                        notes=f"Failed to generate external ticket: {str(exc)}",
                    )
                )

        # 2. Notification Integration
        if self.notification_provider:
            try:
                receipt = await self.notification_provider.send_incident_alert(incident)
                incident.timeline.append(
                    IncidentTimelineEntry(
                        action="NOTIFICATION_DISPATCHED",
                        actor=self.notification_provider.channel_name,
                        notes=f"Delivered: {receipt.delivered} (HTTP {receipt.status_code})",
                    )
                )
            except Exception as exc:
                logger.error(f"Notification dispatch failed for incident {incident.incident_id}: {exc}")
                incident.timeline.append(
                    IncidentTimelineEntry(
                        action="NOTIFICATION_FAILED",
                        actor=self.notification_provider.channel_name,
                        notes=str(exc),
                    )
                )

        return await self.incident_repo.save(incident)

    async def transition_status(
        self,
        incident_id: UUID,
        new_status: IncidentStatus,
        actor: str,
        notes: str | None = None,
    ) -> Incident:
        incident = await self.incident_repo.get_by_id(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID {incident_id} not found")

        valid_targets = self.ALLOWED_TRANSITIONS.get(incident.status, set())
        if new_status not in valid_targets:
            raise IncidentStateError(
                f"Invalid lifecycle transition: Cannot move from {incident.status.value} to {new_status.value}"
            )

        incident.status = new_status
        incident.updated_at = datetime.now(timezone.utc)
        incident.timeline.append(
            IncidentTimelineEntry(
                action=f"STATUS_CHANGED_TO_{new_status.value}",
                actor=actor,
                notes=notes,
            )
        )
        if notes:
            incident.analyst_notes.append(f"[{actor}]: {notes}")

        return await self.incident_repo.save(incident)