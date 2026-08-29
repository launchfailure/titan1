# Fuzzing

Titan has a fast decoder/analyzer gate for pull requests and a longer scheduled
campaign across six public-facing surfaces.

## Invariants (`invariants.py`)

Every decoder and analyzer must, on **any** input (random or malformed):

1. **Never raise uncaught** — signal failure via the `(data, False)` /
   empty-list contract, not exceptions.
2. **Never exceed the output cap** — bounded output (capped decoders honor
   `max_output_size`; the rest cannot balloon output).
3. **Always terminate quickly** — a single call finishes well under the
   engine's per-decode timeout.

`check_all(data)` runs one input through everything and raises `InvariantError`
on a violation.

## Running

Standalone, time-bounded (portable, no native deps):

```bash
python fuzz/fuzz_decoders.py --seconds 30
```

Cross-surface campaign:

```bash
python fuzz/fuzz_surfaces.py --seconds 300 --seed 145 --artifacts .fuzz-artifacts
```

The cross-surface harness covers decoder/analyzer contracts, evidence parsers,
plugin manifest and request transport, server request-length validation,
report loading and exports, and workspace load/save. It starts from the binary
corpus plus valid structured seeds so mutations reach both rejection and
successful-processing paths. Each run writes `summary.json` with its seed,
duration, iterations, unique inputs, surfaces, and violation categories.

The weekly GitHub Actions campaign runs for 30 minutes. On failure it retains
the exact input after deletion minimization, a metadata sidecar, and the run
summary for 30 days. The recorded seed makes the random stream reproducible.

In CI / pytest (bounded example budget + corpus replay):

```bash
pytest tests/test_fuzz_invariants.py
```

The property tests use [Hypothesis](https://hypothesis.readthedocs.io/) when it
is installed and are skipped otherwise; the corpus-replay test always runs.

## Corpus (`corpus/`)

Checked-in "interesting" seeds: empty input, format magic bytes with and
without valid structure, truncated CFB/PDF streams, nested base64, compression
containers, an XOR'd URL, PE/ELF stubs, UTF-16/URL/HTML/UU encodings, high-
entropy blobs, and mixed-magic junk. New crash-triggering inputs discovered by
the fuzzer should be minimized and added here as regression seeds. The
scheduled harness performs initial deletion minimization automatically; a
confirmed reproducer still belongs in this corpus with a focused regression
test.
