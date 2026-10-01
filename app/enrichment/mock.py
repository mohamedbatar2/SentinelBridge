from app.enrichment.base import ThreatIntelProvider
from app.schemas.enrichment import IoCEnrichment, ReputationVerdict


class MockThreatIntelProvider(ThreatIntelProvider):
    """
    Deterministic Threat Intel provider for isolated lab runs,
    integration testing, and offline environments.
    """

    KNOWN_MALICIOUS_IPS = {
        "198.51.100.23": {"score": 90, "campaign": "CobaltStrike_C2"},
        "203.0.113.195": {"score": 85, "campaign": "AsyncRAT"},
    }

    KNOWN_MALICIOUS_DOMAINS = {
        "malicious-c2.internal": {"score": 95, "family": "PowerShell_Empire"},
        "evil-beacon.org": {"score": 88, "family": "Sliver"},
    }

    KNOWN_MALICIOUS_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "score": 100,
            "threat": "Mimikatz_Artifact",
        }
    }

    @property
    def provider_name(self) -> str:
        return "MockThreatIntel"

    async def lookup_ip(self, ip: str) -> IoCEnrichment:
        if ip in self.KNOWN_MALICIOUS_IPS:
            data = self.KNOWN_MALICIOUS_IPS[ip]
            return IoCEnrichment(
                ioc=ip,
                ioc_type="ipv4",
                verdict=ReputationVerdict.MALICIOUS,
                score=data["score"],
                provider=self.provider_name,
                details={"threat_info": data},
            )
        return IoCEnrichment(
            ioc=ip,
            ioc_type="ipv4",
            verdict=ReputationVerdict.UNKNOWN,
            score=0,
            provider=self.provider_name,
            details={"message": "No match in threat intel feed"},
        )

    async def lookup_domain(self, domain: str) -> IoCEnrichment:
        if domain in self.KNOWN_MALICIOUS_DOMAINS:
            data = self.KNOWN_MALICIOUS_DOMAINS[domain]
            return IoCEnrichment(
                ioc=domain,
                ioc_type="domain",
                verdict=ReputationVerdict.MALICIOUS,
                score=data["score"],
                provider=self.provider_name,
                details={"threat_info": data},
            )
        return IoCEnrichment(
            ioc=domain,
            ioc_type="domain",
            verdict=ReputationVerdict.BENIGN if domain.endswith((".com", ".org", ".net")) else ReputationVerdict.UNKNOWN,
            score=10 if domain.endswith((".com", ".org", ".net")) else 0,
            provider=self.provider_name,
            details={"message": "No negative reputation observed"},
        )

    async def lookup_hash(self, file_hash: str) -> IoCEnrichment:
        hash_lower = file_hash.lower()
        if hash_lower in self.KNOWN_MALICIOUS_HASHES:
            data = self.KNOWN_MALICIOUS_HASHES[hash_lower]
            return IoCEnrichment(
                ioc=file_hash,
                ioc_type="hash",
                verdict=ReputationVerdict.MALICIOUS,
                score=data["score"],
                provider=self.provider_name,
                details={"threat_info": data},
            )
        return IoCEnrichment(
            ioc=file_hash,
            ioc_type="hash",
            verdict=ReputationVerdict.UNKNOWN,
            score=0,
            provider=self.provider_name,
            details={"message": "Hash not recognized in database"},
        )