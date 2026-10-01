from app.schemas.metrics import SOCMetricsSummary
from app.storage.base import AlertRepositoryInterface
from app.storage.incident_memory import IncidentRepositoryInterface


class MetricsService:
    def __init__(
        self,
        alert_repo: AlertRepositoryInterface,
        incident_repo: IncidentRepositoryInterface,
    ) -> None:
        self.alert_repo = alert_repo
        self.incident_repo = incident_repo

    async def get_metrics(self) -> SOCMetricsSummary:
        incidents = await self.incident_repo.list_all()

        # For in-memory store, extract alerts directly
        alerts = list(getattr(self.alert_repo, "_store", {}).values())

        total_alerts = len(alerts)
        total_incidents = len(incidents)

        escalation_rate = (
            round((total_incidents / total_alerts) * 100, 2) if total_alerts > 0 else 0.0
        )

        severity_counts: dict[str, int] = {}
        total_score = 0
        mitre_counts: dict[str, int] = {}

        for alert in alerts:
            sev = alert.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_score += alert.risk.score

            for mapping in alert.mitre.mappings:
                tech = f"{mapping.technique_id} - {mapping.technique_name}"
                mitre_counts[tech] = mitre_counts.get(tech, 0) + 1

        avg_score = round(total_score / total_alerts, 2) if total_alerts > 0 else 0.0

        status_counts: dict[str, int] = {}
        for inc in incidents:
            st = inc.status.value
            status_counts[st] = status_counts.get(st, 0) + 1

        # Sort top MITRE techniques
        sorted_mitre = dict(
            sorted(mitre_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        )

        return SOCMetricsSummary(
            total_alerts=total_alerts,
            total_incidents=total_incidents,
            escalation_rate_percent=escalation_rate,
            alerts_by_severity=severity_counts,
            incidents_by_status=status_counts,
            top_mitre_techniques=sorted_mitre,
            average_risk_score=avg_score,
        )