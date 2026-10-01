from fastapi import APIRouter, Depends
from app.core.security import verify_api_key
from app.schemas.metrics import SOCMetricsSummary
from app.services.metrics_service import MetricsService
from app.storage.incident_memory import incident_repository
from app.storage.memory import alert_repository

router = APIRouter(prefix="/metrics", tags=["Metrics"])


def get_metrics_service() -> MetricsService:
    return MetricsService(alert_repo=alert_repository, incident_repo=incident_repository)


@router.get(
    "",
    response_model=SOCMetricsSummary,
    summary="Retrieve real-time SOC operational triage metrics",
    dependencies=[Depends(verify_api_key)],
)
async def get_soc_metrics(
    service: MetricsService = Depends(get_metrics_service),
) -> SOCMetricsSummary:
    return await service.get_metrics()