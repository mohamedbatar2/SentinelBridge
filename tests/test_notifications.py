import pytest
from app.notifications.console import ConsoleNotificationProvider
from app.notifications.webhook import WebhookNotificationProvider
from app.schemas.alert import AlertSeverity, HostInfo, NormalizedAlert
from app.schemas.incident import Incident
from app.schemas.risk import RiskAssessment, RiskLevel
from app.services.incident_service import IncidentService
from app.storage.incident_memory import InMemoryIncidentRepository


@pytest.mark.asyncio
async def test_console_notification_dispatch():
    provider = ConsoleNotificationProvider()
    repo = InMemoryIncidentRepository()
    service = IncidentService(
        incident_repo=repo,
        notification_provider=provider,
        auto_escalate_threshold=70,
    )

    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.HIGH,
        rule_id="100001",
        title="Malicious PowerShell Beacon",
        description="Outbound connection to known C2",
        host=HostInfo(hostname="WIN-SRV-AD01"),
        risk=RiskAssessment(score=85, level=RiskLevel.CRITICAL),
    )

    incident = await service.evaluate_and_promote(alert)
    assert incident is not None
    assert any("NOTIFICATION_DISPATCHED" in entry.action for entry in incident.timeline)


@pytest.mark.asyncio
async def test_webhook_failure_does_not_block_incident():
    # Intentionally target a non-routable port to simulate dropped network connection
    failing_provider = WebhookNotificationProvider(
        webhook_url="http://127.0.0.1:9",
        timeout_seconds=0.1,
    )
    repo = InMemoryIncidentRepository()
    service = IncidentService(
        incident_repo=repo,
        notification_provider=failing_provider,
        auto_escalate_threshold=70,
    )

    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.CRITICAL,
        rule_id="999",
        title="Critical Ransomware Infection",
        description="Mass encryption activity",
        host=HostInfo(hostname="DC01"),
        risk=RiskAssessment(score=95, level=RiskLevel.CRITICAL),
    )

    # Must complete successfully without raising an unhandled connection exception
    incident = await service.evaluate_and_promote(alert)
    assert incident is not None
    assert any("NOTIFICATION_DISPATCHED" in entry.action for entry in incident.timeline)