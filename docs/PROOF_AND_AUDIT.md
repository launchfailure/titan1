# Proof, benchmarks, and audit readiness

The committed proof dashboard lives at `docs/proof/index.html`. Generate or
verify it with:

```console
python tools/publish_proof.py
python tools/publish_proof.py --check
python tools/bench.py --check
python fuzz/fuzz_decoders.py --seconds 30
```

`metrics.json` records calibration confusion metrics, the published benchmark
baseline, every fuzz seed's size and SHA-256, supported sharing formats, and
catalog size. The HTML is generated from that JSON without external assets or
network access. All output is byte-for-byte reproducible from committed inputs.

The benchmark corpus is publicly available with the source repository under
the project license. It combines golden transformation cases and larger
deterministic stress inputs. It is useful for regression and reproducibility;
it is not an independent malware-prevalence sample. Hardware-normalized timing
and exact work-volume gates are described in `tools/bench.py`.

`parser-audit-scope.json` freezes the decoder/analyzer inventory and source
hashes, specifies commands and security invariants, and provides fields for an
independent assessor and report URL. Its current status is deliberately
`ready-for-independent-review`: project automation can prepare and verify an
audit package, but it cannot truthfully manufacture third-party attestation.
Once an assessor publishes results, those fields should be updated and the
proof bundle regenerated.
