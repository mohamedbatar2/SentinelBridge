import ipaddress
import re
from urllib.parse import urlparse
from app.schemas.ioc import ExtractedIoCSet


class IoCExtractor:
    # Regex patterns with strict word boundaries
    # Candidate IPv4 regex (structure only; octet range validated via ipaddress)
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    
    # URL pattern supporting common schemes
    URL_PATTERN = re.compile(
        r"\b(?:https?|ftp)://[^\s/$.?#].[^\s]*",
        re.IGNORECASE,
    )
    
    # FQDN pattern: requires at least two labels, second label 2+ alpha chars
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    
    # Hashes (hexadecimal)
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

    @classmethod
    def refang(cls, text: str) -> str:
        """
        Normalizes defanged IoCs commonly found in threat reports and telemetry.
        Example: hxxp://bad[.]com -> http://bad.com
        """
        cleaned = text.replace("[.]", ".").replace("(.)", ".")
        cleaned = re.sub(r"\bhxxp", "http", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\[:\]", ":", cleaned)
        return cleaned

    @classmethod
    def extract_from_text(cls, raw_text: str) -> ExtractedIoCSet:
        if not raw_text:
            return ExtractedIoCSet()

        text = cls.refang(raw_text)

        # 1. Extract URLs first to prevent URL fragments from polluting domain/IP lists
        found_urls = set(cls.URL_PATTERN.findall(text))
        
        # 2. Extract and validate IPv4 addresses
        found_ips: set[str] = set()
        for candidate_ip in cls.IPV4_PATTERN.findall(text):
            try:
                ip_obj = ipaddress.IPv4Address(candidate_ip)
                # Omit loopback and unspecified addresses from general IOCs
                if not (ip_obj.is_loopback or ip_obj.is_unspecified):
                    found_ips.add(str(ip_obj))
            except ipaddress.AddressValueError:
                # Discards invalid octets like 999.999.999.999
                continue

        # 3. Extract Domains (excluding matches already identified as valid IPs or inside URLs)
        extracted_domains: set[str] = set()
        for candidate_domain in cls.DOMAIN_PATTERN.findall(text):
            candidate_lower = candidate_domain.lower()
            # Verify candidate is not an IP
            try:
                ipaddress.IPv4Address(candidate_lower)
                continue
            except ipaddress.AddressValueError:
                pass
            
            # Avoid trailing dot or invalid file extension artifacts
            if candidate_lower.endswith((".exe", ".dll", ".sys", ".ps1", ".vbs", ".bat")):
                continue

            extracted_domains.add(candidate_lower)

        # Also collect hostnames/domains present in the found URLs
        for url in found_urls:
            parsed = urlparse(url)
            if parsed.hostname:
                try:
                    ipaddress.IPv4Address(parsed.hostname)
                except ipaddress.AddressValueError:
                    extracted_domains.add(parsed.hostname.lower())

        # 4. Extract Hashes (prioritizing longer hashes to prevent SHA256 substrings matching MD5)
        text_lower = text.lower()
        sha256_candidates = set(cls.SHA256_PATTERN.findall(text_lower))
        sha1_candidates = set(cls.SHA1_PATTERN.findall(text_lower)) - sha256_candidates
        md5_candidates = set(cls.MD5_PATTERN.findall(text_lower)) - sha256_candidates - sha1_candidates

        return ExtractedIoCSet(
            ips=sorted(list(found_ips)),
            domains=sorted(list(extracted_domains)),
            urls=sorted(list(found_urls)),
            md5=sorted(list(md5_candidates)),
            sha1=sorted(list(sha1_candidates)),
            sha256=sorted(list(sha256_candidates)),
        )