# Titan service mode

`titan-server` turns the deterministic engine into local pipeline
infrastructure without adding a web-framework dependency. It combines a REST
surface, a persistent SQLite work queue, hash-addressed artifact/report storage,
and one or more workers.

## Quick start

```console
titan-server --data-dir ./titan-data
```

The default binds only to `127.0.0.1:8787` and starts one worker. Submit raw
bytes and retrieve the eventual report:

```console
curl --data-binary @sample.bin http://127.0.0.1:8787/v1/jobs
curl http://127.0.0.1:8787/v1/jobs/<sha256>
curl http://127.0.0.1:8787/v1/jobs/<sha256>/report
```

Endpoints are `GET /v1/health`, `POST /v1/jobs`, `GET /v1/jobs/{sha256}`,
and `GET /v1/jobs/{sha256}/report`. Uploads default to 50 MiB maximum.

## Deployment shapes

The API and workers can run separately against a shared data directory:

```console
titan-server --mode serve --data-dir /srv/titan
titan-server --mode worker --workers 4 --worker-id worker-a --data-dir /srv/titan
```

SQLite transactions ensure one worker claims a queued artifact. A stopped
worker's claim returns to the queue after 15 minutes; Titan's default analysis
timeout is five minutes. The SHA-256 digest is both job identity and storage
key, so repeat submissions reuse queued, running, or completed work. Failed
jobs can be resubmitted.

The storage directory contains immutable blobs under `blobs/<prefix>/<hash>`,
canonical JSON reports under `reports/<hash>.json`, and `queue.sqlite3`.
Writes publish atomically. Horizontal workers therefore require a filesystem
and SQLite locking implementation that is safe for every participating host;
for multi-host production deployments, place this interface behind a durable
shared-volume/queue adapter.

## Network security

Non-loopback binding is rejected unless both `--allow-remote` and
`--api-token` are supplied. Send the token as `Authorization: Bearer <token>`.
This built-in server is an offline-first reference deployment; put TLS,
identity, request logging, and rate limiting at a trusted reverse proxy before
exposing it outside a controlled network.
