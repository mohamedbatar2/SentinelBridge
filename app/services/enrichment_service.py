import ipaddress
import logging
from app.enrichment.base import ThreatIntelProvider
from app.schemas.enrichment import AlertEnrichmentReport, IoCEnrichment, ReputationVerdict
from app.schemas.ioc import ExtractedIoCSet

logger = logging.getLogger("sentinelbridge.enrichment")


class EnrichmentService:
    # Explicit enterprise non-routable / internal CIDR ranges to block
    INTERNAL_NETWORKS = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("127.0.0.0/8"),       # Loopback
        ipaddress.IPv4Network("169.254.0.0/16"),    # Link-Local
        ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
        ipaddress.IPv4Network("0.0.0.0/8"),        # Unspecified
    )

    def __init__(self, provider: ThreatIntelProvider) -> None:
        self.provider = provider

    @classmethod
    def is_routable_public_ip(cls, ip_str: str) -> bool:
        """
        OPSEC guard: Validates that an IP does not belong to RFC 1918 private space,
        loopback, link-local, or multicast before dispatching to external threat intel.
        Permits documentation/lab test networks (RFC 5737) for deterministic analysis.
        """
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return not any(ip in net for net in cls.INTERNAL_NETWORKS)
        except ipaddress.AddressValueError:
            return False

    async def enrich_ioc_set(self, iocs: ExtractedIoCSet) -> AlertEnrichmentReport:
        report = AlertEnrichmentReport()

        # 1. Enrich public IPv4s
        for ip in iocs.ips:
            if not self.is_routable_public_ip(ip):
                logger.debug(f"Skipping TI lookup for non-public IP: {ip}")
                continue

            try:
                res = await self.provider.lookup_ip(ip)
                report.enrichments.append(res)
            except Exception as exc:
                logger.error(f"Error enriching IP {ip} via {self.provider.provider_name}: {exc}")

        # 2. Enrich Domains
        for domain in iocs.domains:
            try:
                res = await self.provider.lookup_domain(domain)
                report.enrichments.append(res)
            except Exception as exc:
                logger.error(f"Error enriching Domain {domain} via {self.provider.provider_name}: {exc}")

        # 3. Enrich Hashes (MD5, SHA1, SHA256)
        all_hashes = iocs.md5 + iocs.sha1 + iocs.sha256
        for file_hash in all_hashes:
            try:
                res = await self.provider.lookup_hash(file_hash)
                report.enrichments.append(res)
            except Exception as exc:
                logger.error(f"Error enriching hash {file_hash} via {self.provider.provider_name}: {exc}")

        # Calculate summary metrics
        for item in report.enrichments:
            if item.verdict == ReputationVerdict.MALICIOUS:
                report.malicious_count += 1
            elif item.verdict == ReputationVerdict.SUSPICIOUS:
                report.suspicious_count += 1
            elif item.verdict == ReputationVerdict.BENIGN:
                report.benign_count += 1
            else:
                report.unknown_count += 1

        return report