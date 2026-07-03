# Titan Decoder Engine

**Advanced payload decoding and forensic analysis framework for cybersecurity professionals, malware analysts, and law enforcement.**

[![Tests](https://github.com/pragmaconflux/titan1/actions/workflows/tests.yml/badge.svg)](https://github.com/pragmaconflux/titan1/actions/workflows/tests.yml) [![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()

## Safety / Privacy

- Don’t upload real incident data (logs, browser history DBs, reports) to public issues.
- This tool can process untrusted inputs; run in a sandboxed environment when possible.
- Outputs may contain sensitive artifacts extracted from samples (IOCs, emails, hostnames). Handle accordingly.
- Built-in hardening (decompression-bomb caps, DoS-resistant decoders, resource limits) and known trust boundaries are documented in [SECURITY.md](SECURITY.md).
- No warranty: see [LICENSE](LICENSE).

## 🚀 Quick Start (5 Minutes)

New here and feeling lost? Start with the practical walkthrough in [docs/USAGE.md](docs/USAGE.md).

Maintainers:
- Release checklist: [docs/RELEASING.md](docs/RELEASING.md)
- Community post templates: [docs/ANNOUNCEMENT.md](docs/ANNOUNCEMENT.md)

### 1. Install

```bash
# Clone repository
git clone https://github.com/pragmaconflux/titan1.git
cd titan1

# Install core (no external dependencies required)
pip install -e .

# Optional: install enrichment/advanced feature dependencies
pip install -e '.[enrichment]'
```

### 2. Analyze Your First File

```bash
# Quick analysis
titan-decoder --file suspicious.bin --out report.json

# With progress and detections
titan-decoder --file payload.dat --progress --enable-detections --out report.json

# Full law enforcement package
titan-decoder --file evidence.bin --profile full --enable-detections \\
    --forensics-out forensics.json --ioc-out iocs.json --ioc-format misp \\
    --report-out case_report.md --timeline-out timeline.csv

# Add IR evidence logs (DNS/Proxy/Firewall/VPN/Auth/DHCP) for correlation + pivots
titan-decoder --file suspicious.bin --out report.json \\
    --evidence dns:/path/dns.csv \\
    --evidence proxy:/path/proxy.csv \\
    --evidence firewall:/path/flows.csv
```

### 3. View Results

```bash
# Check the report (no jq required)
python -c 'import json; r=json.load(open("report.json")); print(r["node_count"]); print(r.get("iocs", {}))'

# View risk assessment
python -c 'import json; r=json.load(open("report.json")); print((r.get("risk_assessment") or {}).get("risk_score")); print(r.get("detections", []))'
```

**That's it!** You're analyzing malware.

---

## 📋 Features

### Core Capabilities
- **21 Built-in Decoders (+ plugins)** — 17 always on, 4 opt-in:
  - *Always on (17):* Base64, RecursiveBase64, Base64URL, PEM, Gzip, Bz2, LZMA, Zlib, Hex, XOR, ROT13, URL decode, HTML entities, Unicode escape, UTF-16, PDF, OLE
  - *Opt-in (4):* Base32, UUEncode, ASN.1, QuotedPrintable — see [Opt-in decoders](#opt-in-decoders) below
- **Smart Detection**: Auto-enables format-specific decoders
- **Recursive Analysis**: Handles nested encodings (configurable depth)
- **Archive Support**: ZIP, TAR with anti-zip-bomb protections
- **Binary Analysis**: PE, ELF metadata extraction
- **IOC Extraction**: IPs, URLs, domains, emails, hashes with normalization

### Forensics & Intelligence
- **Device Forensics**: VM detection, mobile IDs (IMEI/IMSI/ICCID), burner patterns
- **Normalized IR Evidence**: Ingest common log exports (DNS/Proxy/Firewall/VPN/Auth/DHCP) into a canonical Event/Indicator model
- **Top Pivots + Last Seen**: Evidence-backed pivots with provenance (multi-source indicators bubble up)
- **Evidence Links**: Reason codes + confidence for key correlations
- **7 Detection Rules**: Deep Base64 nesting, Office macro+network IOCs, LOLBin patterns, packed/encrypted payload heuristics, multi-stage infrastructure, XOR+C2, malicious PDF
- **Risk Scoring**: 0-100 heuristic threat assessment (CLEAN/LOW/MEDIUM/HIGH/CRITICAL)
- **Enrichment**: Geo/WHOIS/YARA (optional, requires config) with deterministic local cache + refresh control

### Export & Reporting
- **IOC Formats**: JSON, CSV, STIX 2.1, MISP
- **Case Reports**: Markdown/HTML summaries for investigators
- **Timeline Export**: CSV/JSON for Timesketch, Excel
- **Evidence Timeline Export**: CSV/JSON from normalized `--evidence` inputs
- **Graph Export**: JSON, DOT, Mermaid

### Workflow / Trust (CLI-first)
- **Doctor Self-Check**: `--doctor` prints a JSON diagnostic report
- **Quiet Mode**: `--quiet` suppresses non-error status output (clean pipelines)
- **JSONL Export**: `--jsonl-out events.jsonl` for easy ingestion
- **Local Vault**: `--vault-store` + `--vault-search <value>` for history/search

### Production Features
- **Batch Processing**: Analyze entire directories
- **PII Redaction**: Safe log sharing
- **Resource Limits**: Memory caps, timeouts, recursion/node/size bounds
- **DoS Resistance**: Bounded decompression (anti-bomb) and O(n)-by-design
  decoders that don't blow up on crafted input (see [SECURITY.md](SECURITY.md))
- **Signal Handling**: Clean shutdown (Ctrl+C)
- **Error Recovery**: Malformed archives, corrupt SQLite, and bad CSV/JSONL rows
  are skipped rather than crashing the run
- **No Required Dependencies**: Core runs on the stdlib; optional extras
  (`psutil`, enrichment) degrade gracefully when absent

## 📖 Usage Examples

### Command Line

**Basic Analysis**
```bash
titan-decoder --file payload.dat --out report.json --verbose
```

**Fast Triage** (depth=3, 50 max artifacts)
```bash
titan-decoder --file suspicious.bin --profile fast --progress --enable-detections
```

**Deep Analysis** (depth=8, 200 max artifacts)
```bash
titan-decoder --file malware.bin --profile full --enable-detections --enable-enrichment
```

**Law Enforcement Package**
```bash
titan-decoder --file evidence.bin --enable-detections \\
    --forensics-out forensics.json \\
    --ioc-out iocs.json --ioc-format misp \\
    --report-out case_report.md \\
    --timeline-out timeline.csv
```

**Batch Processing**
```bash
titan-decoder --batch ./input_dir --batch-pattern "*.bin" --out ./reports
```

### Python API

```python
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.core.risk_scoring import RiskScoringEngine
from titan_decoder.config import Config

# Basic analysis
engine = TitanEngine()
report = engine.run_analysis(data_bytes)

# With detections and risk scoring
rules = CorrelationRulesEngine()
detections = rules.evaluate_all(report, report['iocs'])

risk_engine = RiskScoringEngine()
risk = risk_engine.compute_risk_score(report, report['iocs'], detections)

print(f"Risk Level: {risk['risk_level']} ({risk['risk_score']}/100)")
print(f"Detections: {len(detections)}")
print(f"IOCs: {sum(len(v) for v in report['iocs'].values())}")
```

---

## ⚙️ Configuration

### Quick Config

Create `~/.titan_decoder/config.json`:

```json
{
    "max_recursion_depth": 5,
    "max_node_count": 100,
    "enable_logging": true,
    "log_level": "INFO"
}
```

### Full Configuration

```json
{
    "max_recursion_depth": 5,
    "max_node_count": 100,
    "max_data_size": 52428800,
    "analysis_timeout_seconds": 300,
    "max_memory_mb": 1024,
  
    "decoders": {
        "base64": true,
        "gzip": true,
        "hex": true,
        "xor": true,
        "pdf": true
    },
  
    "analyzers": {
        "zip": true,
        "tar": true,
        "pe": true,
        "elf": true
    },
  
    "enable_geo_enrichment": false,
    "enable_whois": false,
    "enable_yara": false,
    "yara_rules_path": "/path/to/rules.yar",
  
    "enable_logging": true,
    "log_level": "INFO"
}
```

Run `titan-decoder --help` for the full option list.

### Opt-in decoders

Four decoders ship disabled in the always-on set: **Base32**, **UUEncode**,
**ASN.1**, and **QuotedPrintable**.

**Why they're off by default.** Their format signatures are weak or ambiguous,
so running them on *every* node produces false-positive "decodes" and noisy
output on unrelated binary/text. For example, any run of `A–Z2–7` characters is
technically valid Base32, and ordinary text containing `=XX` sequences (URLs,
config files) looks like Quoted-Printable. Keeping them out of the default
chain makes normal runs precise instead of flooding the graph with spurious
branches.

**You usually don't need to do anything.** Smart detection runs on every node
and *auto-enables* the right one the moment it confidently identifies the
format (you'll see e.g. `Enabled Base32 decoder (confidence: 0.95)` in the
logs). So a real Base32/UU/ASN.1/QP payload is still decoded out of the box —
the decoder is simply activated on demand rather than tried blindly.

**Force them on** when you want them always active (e.g. triaging a corpus you
know is UUEncoded, or debugging why a borderline payload wasn't auto-detected).
Add a `decoders` block to `~/.titan_decoder/config.json`:

```json
{
    "decoders": {
        "base32": true,
        "uuencode": true,
        "asn1": true,
        "quoted_printable": true
    }
}
```

Set only the ones you need to `true`; omit or set `false` to leave a decoder on
its default (auto-detect) behavior. The effective decoder set for any run is
recorded in the report under `run_manifest.components.decoders`.

---

## 🧪 Testing

```bash
# Dev setup (installs pytest + ruff)
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Lint/format
python -m ruff check .
python -m ruff format --check .

# With coverage
pytest tests/ --cov=titan_decoder --cov-report=html

# Quick smoke test
tmpfile="$(mktemp)" && printf 'ZGF0YTogdGVzdA==' > "$tmpfile" && titan-decoder --file "$tmpfile" --out /tmp/titan_report.json && python -c 'import json; print(json.load(open("/tmp/titan_report.json"))["node_count"])'
```


## 📚 Documentation

- **This README** - Installation, usage, configuration examples
- **CLI help** - Run `titan-decoder --help` for the full option list

### Report schema

- JSON Schema for the report format: [docs/report.schema.json](docs/report.schema.json)

---

## 🔒 Safety Recommendations

**Analyze untrusted files safely:**

1. **Dedicated VM**: Run in a disposable virtual machine
2. **Snapshots**: Use snapshots and revert after analysis
3. **Network isolation**: Disconnect network before analysis
4. **Non-root**: Never run as root user
5. **Resource limits**: Set max_memory_mb and analysis_timeout_seconds

---

## 🏗️ Architecture

```
titan_decoder/
├── cli.py                    # Command-line interface
├── config.py                 # Configuration management
├── core/
│   ├── engine.py             # Main analysis engine
│   ├── detection_rules.py    # 7 starter detection rules
│   ├── risk_scoring.py       # Heuristic threat assessment
│   ├── enrichment.py         # Geo/WHOIS/YARA
│   ├── device_forensics.py   # VM/mobile/burner detection
│   ├── vault.py              # Local history/search store
│   ├── ioc_export.py         # JSON/CSV/STIX/MISP export
│   ├── case_report.py        # Markdown reports
│   ├── timeline.py           # Event timeline export
│   ├── correlation.py        # IOC correlation cache
│   ├── resource_manager.py   # Timeouts and limits
│   ├── secure_logging.py     # PII redaction
│   ├── smart_detection.py    # Format auto-detection
│   ├── scoring.py            # Decode scoring
│   ├── profiling.py          # Performance metrics
│   ├── graph_export.py       # Graph visualization
│   └── analyzers/
│       └── base.py           # ZIP, TAR, PE, ELF
├── decoders/
│   └── base.py               # 21 built-in decoders (17 on, 4 opt-in) (+ plugins)
├── plugins/                  # Plugin system
└── utils/
    └── helpers.py            # IOC extraction, entropy
```

---

## 🤝 Contributing

Contributions welcome! Please open a PR or issue to discuss changes (avoid
sensitive incident data in public issues). See [CONTRIBUTING.md](CONTRIBUTING.md)
for dev setup and PR guidelines, and [SECURITY.md](SECURITY.md) to report
security issues privately.

**Add a custom decoder:**
```python
from typing import Tuple

from titan_decoder.plugins import PluginDecoder

class MyDecoder(PluginDecoder):
    @property
    def name(self) -> str:
        return "MyFormat"

    def can_decode(self, data: bytes) -> bool:
        return data.startswith(b"MYMAGIC")

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        decoded = my_decode_logic(data)
        return decoded, True
```

Place in `~/.titan_decoder/plugins/my_decoder.py` and it's auto-loaded!

---

## 📄 License

License: MIT (see LICENSE).

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/pragmaconflux/titan1/issues)

---

## 🎯 Roadmap

- [ ] REST API for integration
- [ ] Watch mode for directory monitoring
- [ ] Artifact parsers (prefetch, shimcache)
- [ ] PyPI package
- [ ] Single-file executable
- [ ] Web UI

---

## 🙏 Credits

Titan Decoder Engine is built for — and with — the cybersecurity community: the
malware analysts, incident responders, digital forensics examiners, and law
enforcement teams who reverse-engineer hostile payloads every day. Thank you for
the bug reports, sample submissions, and field feedback that shape each release.

**Maintained by** [PragmaConflux](https://github.com/pragmaconflux) and released
under the [MIT License](LICENSE). Contributions are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) to get started, and please review our
[Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md).

**Core stack**
- Python 3.10+ — the decoding engine and all 21 core modules run on the standard
  library alone, with no external dependencies required.

**Optional integrations** (see [requirements-optional.txt](requirements-optional.txt))
enable enrichment and advanced analysis features:

| Library | Used for |
| --- | --- |
| [psutil](https://github.com/giampaolo/psutil) | Runtime resource governor (per-module CPU/memory limits) |
| [geoip2](https://github.com/maxmind/GeoIP2-python) | Geolocation enrichment of extracted network IOCs |
| [python-whois](https://github.com/richardpenman/whois) | Domain registration lookups during IOC enrichment |
| [yara-python](https://github.com/VirusTotal/yara-python) | Signature-based detection over decoded payloads |
| [requests](https://github.com/psf/requests) | Optional network-backed enrichment lookups |
| [PyYAML](https://github.com/yaml/pyyaml) | Loading detection rule packs and configuration |

Gratitude to the maintainers of these projects and to the broader open-source
security ecosystem their work makes possible.

---

**Ready to analyze? Start with:** `titan-decoder --file your_sample.bin --progress --enable-detections`
