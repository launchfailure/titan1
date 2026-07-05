# Fuzzing

Fuzz harness for Titan's decoders and analyzers. The safety invariants are
easy to state and cheap to check, which makes this the highest-ROI robustness
work in the project.

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
the fuzzer should be minimized and added here as regression seeds.
