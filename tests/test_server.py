import http.client
import json
import threading

import pytest

from titan_decoder.server.app import TitanHTTPServer, main
from titan_decoder.server.service import ArtifactStore, JobQueue, TitanService


def test_artifact_store_is_hash_addressed_bounded_and_atomic(tmp_path):
    store = ArtifactStore(tmp_path, max_artifact_bytes=8)
    digest, created = store.put(b"payload")
    assert created and store.get(digest) == b"payload"
    assert store.put(b"payload") == (digest, False)
    with pytest.raises(ValueError, match="size limit"):
        store.put(b"x" * 9)


def test_queue_deduplicates_and_leases_in_order(tmp_path):
    queue = JobQueue(tmp_path / "queue.sqlite3")
    first, created = queue.enqueue("a" * 64)
    assert created and first["state"] == "queued"
    assert queue.enqueue("a" * 64)[1] is False
    leased = queue.lease("worker-1")
    assert leased["id"] == "a" * 64 and leased["state"] == "running"
    assert queue.lease("worker-2") is None
    queue.complete(leased["id"])
    assert queue.get(leased["id"])["state"] == "completed"


def test_failed_job_can_be_resubmitted(tmp_path):
    queue = JobQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("b" * 64)
    leased = queue.lease("worker-1")
    queue.fail(leased["id"], "transient failure")
    retried, created = queue.enqueue(leased["id"])
    assert created
    assert retried["state"] == "queued"
    assert retried["error"] is None


def test_service_runs_job_and_reuses_completed_hash(tmp_path):
    service = TitanService(tmp_path)
    job, created = service.submit(b"https://server.example/gate")
    assert created
    finished = service.work_once("worker")
    assert finished["state"] == "completed"
    assert service.submit(b"https://server.example/gate")[1] is False
    report = service.store.get_report(job["id"])
    assert "https://server.example/gate" in report["iocs"]["urls"]


def test_http_submit_status_report_and_auth(tmp_path):
    service = TitanService(tmp_path)
    server = TitanHTTPServer(("127.0.0.1", 0), service, "secret")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request("GET", "/v1/health")
        unauthorized = connection.getresponse()
        assert unauthorized.status == 401
        unauthorized.read()
        connection.close()
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=5
        )
        headers = {"Authorization": "Bearer secret", "Content-Length": "7"}
        connection.request("POST", "/v1/jobs", body=b"payload", headers=headers)
        response = connection.getresponse()
        assert response.status == 202
        job = json.loads(response.read())
        service.work_once("test")
        connection.request("GET", f"/v1/jobs/{job['id']}/report", headers=headers)
        report_response = connection.getresponse()
        assert report_response.status == 200
        assert json.loads(report_response.read())["meta"]["analysis_id"]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_remote_binding_requires_explicit_authentication():
    with pytest.raises(SystemExit, match="requires --allow-remote"):
        main(["--mode", "serve", "--host", "0.0.0.0"])
    with pytest.raises(SystemExit, match="requires --api-token"):
        main(["--mode", "serve", "--host", "0.0.0.0", "--allow-remote"])
