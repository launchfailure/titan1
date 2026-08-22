"""Dependency-free REST surface and worker command for ``titan server``."""

from __future__ import annotations

import argparse
import hmac
import json
import signal
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .service import TitanService


class TitanHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, service: TitanService, api_token: str | None = None):
        self.service = service
        self.api_token = api_token
        super().__init__(address, TitanHandler)


class TitanHandler(BaseHTTPRequestHandler):
    server: TitanHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _json(self, status: int, value) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if status == HTTPStatus.UNAUTHORIZED:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        expected = self.server.api_token
        if expected is None:
            return True
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {expected}")

    def _path(self) -> list[str]:
        return [part for part in urlsplit(self.path).path.split("/") if part]

    def do_GET(self):
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        parts = self._path()
        if parts == ["v1", "health"]:
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if len(parts) in (3, 4) and parts[:2] == ["v1", "jobs"]:
            job_id = parts[2]
            try:
                job = self.server.service.queue.get(job_id)
                if len(parts) == 4:
                    if parts[3] != "report":
                        raise KeyError(job_id)
                    if job["state"] != "completed":
                        self._json(
                            HTTPStatus.CONFLICT,
                            {"error": "report not ready", "state": job["state"]},
                        )
                        return
                    self._json(
                        HTTPStatus.OK, self.server.service.store.get_report(job_id)
                    )
                    return
                self._json(HTTPStatus.OK, job)
            except (KeyError, FileNotFoundError):
                self._json(HTTPStatus.NOT_FOUND, {"error": "job not found"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if self._path() != ["v1", "jobs"]:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        maximum = self.server.service.store.max_artifact_bytes
        if length <= 0 or length > maximum:
            self._json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "invalid artifact size", "max_bytes": maximum},
            )
            return
        data = self.rfile.read(length)
        try:
            job, created = self.server.service.submit(data)
        except ValueError as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        self._json(HTTPStatus.ACCEPTED if created else HTTPStatus.OK, job)


def _worker_loop(service: TitanService, worker: str, stop: threading.Event) -> None:
    while not stop.is_set():
        if service.work_once(worker) is None:
            stop.wait(0.2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="titan server")
    parser.add_argument("--mode", choices=("all", "serve", "worker"), default="all")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--data-dir", type=Path, default=Path(".titan-server"))
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--worker-id", default=socket.gethostname())
    parser.add_argument("--max-artifact-bytes", type=int, default=50 * 1024 * 1024)
    parser.add_argument("--api-token")
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.workers > 64:
        raise SystemExit("--workers must be between 1 and 64")
    if args.max_artifact_bytes < 1:
        raise SystemExit("--max-artifact-bytes must be positive")
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote:
        raise SystemExit("non-loopback binding requires --allow-remote")
    if args.allow_remote and not args.api_token:
        raise SystemExit("remote binding requires --api-token")
    service = TitanService(args.data_dir, max_artifact_bytes=args.max_artifact_bytes)
    stop = threading.Event()
    try:
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    except ValueError:
        pass
    threads = []
    if args.mode in {"all", "worker"}:
        for index in range(args.workers):
            thread = threading.Thread(
                target=_worker_loop,
                args=(service, f"{args.worker_id}:{index}", stop),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
    if args.mode in {"all", "serve"}:
        server = TitanHTTPServer((args.host, args.port), service, args.api_token)
        server.timeout = 0.2
        try:
            while not stop.is_set():
                server.handle_request()
        finally:
            server.server_close()
            stop.set()
    else:
        while not stop.wait(0.5):
            pass
    for thread in threads:
        thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
