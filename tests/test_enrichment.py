import pytest
from app.enrichment.mock import MockThreatIntelProvider
from app.schemas.enrichment import ReputationVerdict
from app.schemas.ioc import ExtractedIoCSet
from app.services.enrichment_service import EnrichmentService


@pytest.mark.asyncio
async def test_opsec_filter_blocks_rfc1918():
    service = EnrichmentService(provider=MockThreatIntelProvider())
    assert service.is_routable_public_ip("192.168.1.1") is False
    assert service.is_routable_public_ip("10.0.0.15") is False
    assert service.is_routable_public_ip("172.16.5.2") is False
    assert service.is_routable_public_ip("127.0.0.1") is False
    assert service.is_routable_public_ip("8.8.8.8") is True
    assert service.is_routable_public_ip("198.51.100.23") is True


@pytest.mark.asyncio
async def test_enrichment_service_flow():
    provider = MockThreatIntelProvider()
    service = EnrichmentService(provider=provider)

    iocs = ExtractedIoCSet(
        ips=["192.168.1.50", "198.51.100.23"],  # One private, one known malicious
        domains=["malicious-c2.internal", "safe-site.com"],
        sha256=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )

    report = await service.enrich_ioc_set(iocs)

    # 192.168.1.50 must be skipped by OPSEC guard
    enriched_ips = [e.ioc for e in report.enrichments if e.ioc_type == "ipv4"]
    assert "192.168.1.50" not in enriched_ips
    assert "198.51.100.23" in enriched_ips

    # Counts
    assert report.malicious_count >= 2  # Known IP, known domain, known hash
    
    # Verify hash verdict
    hash_enrichment = next(e for e in report.enrichments if e.ioc_type == "hash")
    assert hash_enrichment.verdict == ReputationVerdict.MALICIOUS
    assert hash_enrichment.score == 100