import json
import warnings

from titan_decoder.core.ioc_export import export_misp, export_stix_minimal

# IOC dict shaped like extract_iocs output: ipv4 is a superset of ipv4_public.
IOCS = {
    "ipv4": ["8.8.8.8", "192.168.1.1"],
    "ipv4_public": ["8.8.8.8"],
    "ipv4_private": ["192.168.1.1"],
    "urls": ["http://evil.com/a'b"],
    "domains": ["bad.com"],
    "emails": [],
    "hashes": [],
}


def test_misp_does_not_duplicate_overlapping_ip_buckets(tmp_path):
    out = tmp_path / "misp.json"
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        export_misp(IOCS, out)
    event = json.loads(out.read_text())
    ip_values = [
        a["value"] for a in event["Event"]["Attribute"] if a["type"] == "ip-dst"
    ]
    assert ip_values.count("8.8.8.8") == 1


def test_stix_escapes_quotes_in_values(tmp_path):
    out = tmp_path / "stix.json"
    export_stix_minimal(IOCS, out)
    bundle = json.loads(out.read_text())
    url_patterns = [
        o["pattern"] for o in bundle["objects"] if "url:value" in o["pattern"]
    ]
    assert url_patterns == ["[url:value = 'http://evil.com/a\\'b']"]


def test_stix_no_duplicate_ip_indicators(tmp_path):
    out = tmp_path / "stix.json"
    export_stix_minimal(IOCS, out)
    bundle = json.loads(out.read_text())
    patterns = [o["pattern"] for o in bundle["objects"]]
    assert len(patterns) == len(set(patterns))
    assert patterns.count("[ipv4-addr:value = '8.8.8.8']") == 1
