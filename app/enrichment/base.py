from abc import ABC, abstractmethod
from app.schemas.enrichment import IoCEnrichment


class ThreatIntelProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider for tracking and auditing."""
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> IoCEnrichment:
        """Query reputation for an IPv4 address."""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> IoCEnrichment:
        """Query reputation for a domain/FQDN."""
        pass

    @abstractmethod
    async def lookup_hash(self, file_hash: str) -> IoCEnrichment:
        """Query reputation for an MD5, SHA1, or SHA256 hash."""
        pass