from fastapi import APIRouter, Depends, status
from app.connectors.ticketing.local import LocalTicketProvider
from app.core.security import verify_api_key
from app.enrichment.mock import MockThreatIntelProvider
from app.notifications.console import ConsoleNotificationProvider
from app.schemas.alert import AlertIngest
from app.schemas.response import AlertIngestResponse
from app.services.alert_service import AlertService
from app.services.enrichment_service import EnrichmentService
from app.services.incident_service import IncidentService
from app.storage.incident_memory import incident_repository
from app.storage.memory import alert_repository

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def get_alert_service() -> AlertService:
    ti_provider = MockThreatIntelProvider()
    enrichment_service = EnrichmentService(provider=ti_provider)
    ticketing_provider = LocalTicketProvider()
    notification_provider = ConsoleNotificationProvider()

    incident_service = IncidentService(
        incident_repo=incident_repository,
        ticketing_provider=ticketing_provider,
        notification_provider=notification_provider,
        auto_escalate_threshold=70,
    )

    return AlertService(
        repository=alert_repository,
        enrichment_service=enrichment_service,
        incident_service=incident_service,
    )


@router.post(
    "",
    response_model=AlertIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a security detection alert",
    dependencies=[Depends(verify_api_key)],
)
async def ingest_alert(
    alert_in: AlertIngest,
    service: AlertService = Depends(get_alert_service),
) -> AlertIngestResponse:
    persisted, incident_promoted = await service.process_and_ingest(alert_in)
    return AlertIngestResponse(
        alert_id=persisted.alert_id,
        status="accepted",
        message="Alert accepted for processing",
        incident_promoted=incident_promoted,
    )