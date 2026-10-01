from enum import Enum
from pydantic import BaseModel, Field


class IoCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class ExtractedIoC(BaseModel):
    value: str
    ioc_type: IoCType
    is_private: bool = False  # Relevant for IP addresses


class ExtractedIoCSet(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    md5: list[str] = Field(default_factory=list)
    sha1: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)