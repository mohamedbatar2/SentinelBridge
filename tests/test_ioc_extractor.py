from app.services.ioc_extractor import IoCExtractor


def test_ipv4_extraction_valid_and_invalid():
    sample_text = (
        "Inbound connection from 198.51.100.45 and internal 10.0.0.1. "
        "Ignore invalid octets like 999.123.45.67 or 1.2.3."
    )
    result = IoCExtractor.extract_from_text(sample_text)
    assert "198.51.100.45" in result.ips
    assert "10.0.0.1" in result.ips
    assert "999.123.45.67" not in result.ips


def test_defanged_ioc_normalization():
    sample_text = "C2 contact via hxxp://c2-beacon[.]xyz:8080/payload from 203[.]0[.]113[.]195"
    result = IoCExtractor.extract_from_text(sample_text)
    assert any("c2-beacon.xyz" in url for url in result.urls)
    assert "c2-beacon.xyz" in result.domains
    assert "203.0.113.195" in result.ips


def test_hash_extraction_and_classification():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    text = f"Analyzed binaries: md5={md5}, sha1={sha1}, sha256={sha256}."
    result = IoCExtractor.extract_from_text(text)

    assert md5 in result.md5
    assert sha1 in result.sha1
    assert sha256 in result.sha256


def test_domain_filtering_avoids_executables():
    sample_text = "Process executed C:\\Windows\\System32\\svchost.exe communicating with evil-domain.org"
    result = IoCExtractor.extract_from_text(sample_text)
    assert "evil-domain.org" in result.domains
    assert "svchost.exe" not in result.domains