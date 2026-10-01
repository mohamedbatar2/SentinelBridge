from app.schemas.alert import AlertIngest, NormalizedAlert
from app.schemas.enrichment import AlertEnrichmentReport
from app.services.enrichment_service import EnrichmentService
from app.services.incident_service import IncidentService
from app.services.ioc_extractor import IoCExtractor
from app.services.mitre_mapper import MitreMapper
from app.services.risk_engine import RiskEngine
from app.storage.base import AlertRepositoryInterface


class AlertService:
    def __init__(
        self,
        repository: AlertRepositoryInterface,
        enrichment_service: EnrichmentService | None = None,
        incident_service: IncidentService | None = None,
    ) -> None:
        self.repository = repository
        self.enrichment_service = enrichment_service
        self.incident_service = incident_service

    async def process_and_ingest(self, alert_in: AlertIngest) -> tuple[NormalizedAlert, bool]:
        """
        Executes the detection pipeline:
        Corpus -> Extract IoCs -> Threat Intel -> MITRE ATT&CK -> Risk Engine -> Store -> Incident Promotion
        Returns: (NormalizedAlert, incident_promoted: bool)
        """
        # 1. Unstructured text corpus assembly
        text_corpus = f"{alert_in.title} {alert_in.description}"
        if alert_in.process:
            text_corpus += f" {alert_in.process.command_line}"
            if alert_in.process.image_path:
                text_corpus += f" {alert_in.process.image_path}"

        text_corpus += " " + " ".join(alert_in.iocs.ips)
        text_corpus += " " + " ".join(alert_in.iocs.domains)
        text_corpus += " " + " ".join(alert_in.iocs.hashes)

        # 2. Extract IoCs
        extracted = IoCExtractor.extract_from_text(text_corpus)

        # 3. TI Enrichment
        enrichment_report = None
        if self.enrichment_service:
            enrichment_report = await self.enrichment_service.enrich_ioc_set(extracted)

        # 4. Construct normalized object
        normalized = NormalizedAlert(
            **alert_in.model_dump(),
            extracted_iocs=extracted,
            enrichment=enrichment_report or AlertEnrichmentReport(),
        )

        # 5. MITRE ATT&CK Mapping
        normalized.mitre = MitreMapper.map_alert(normalized)

        # 6. Evaluate Risk Score
        normalized.risk = RiskEngine.calculate_risk(normalized)

        # 7. Persist Alert
        saved_alert = await self.repository.save(normalized)

        # 8. Incident Promotion Assessment
        incident_promoted = False
        if self.incident_service:
            incident = await self.incident_service.evaluate_and_promote(saved_alert)
            if incident is not None:
                incident_promoted = True

        return saved_alert, incident_promoted