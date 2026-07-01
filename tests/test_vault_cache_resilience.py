"""Regression tests: vault and enrichment cache must degrade on a corrupt DB.

Both open SQLite files via executescript/PRAGMA on connect. A corrupt or
non-SQLite file (truncated write, wrong path, disk corruption) previously
raised an unhandled sqlite3.DatabaseError — crashing the CLI with a traceback
for the vault, and able to abort a best-effort enrichment run for the cache.
"""

import sqlite3

import pytest

from titan_decoder.core.vault import VaultStore, VaultError
from titan_decoder.core.enrichment_cache import EnrichmentCache


def _corrupt(path):
    path.write_bytes(b"this is not a sqlite database " * 40)
    return path


def test_vault_raises_clean_error_on_corrupt_db(tmp_path):
    db = _corrupt(tmp_path / "vault.db")
    with pytest.raises(VaultError):
        with VaultStore(db):
            pass
    # It must be VaultError, not a raw sqlite3.DatabaseError.
    try:
        with VaultStore(db):
            pass
    except VaultError as e:
        assert not isinstance(e, sqlite3.DatabaseError)


def test_vault_still_works_on_valid_db(tmp_path):
    db = tmp_path / "vault.db"
    with VaultStore(db) as store:
        store.record_run("aid1", tmp_path / "r.json", node_count=2, ioc_count=1)
        store.record_iocs("aid1", {"urls": ["http://evil.test/x"]})
        assert len(store.search_value("http://evil.test/x")) == 1
        assert store.list_recent(10)[0]["analysis_id"] == "aid1"


def test_enrichment_cache_degrades_on_corrupt_db(tmp_path):
    db = _corrupt(tmp_path / "cache.db")
    cache = EnrichmentCache(db)
    # get -> miss, set -> no-op (returns a timestamp), stats -> error dict; no raise
    assert cache.get("virustotal", "ipv4_public", "1.2.3.4") is None
    assert isinstance(cache.set("virustotal", "ipv4_public", "1.2.3.4", {"x": 1}), str)
    stats = cache.stats()
    assert stats["entries"] == 0 and "error" in stats


def test_enrichment_cache_still_works_on_valid_db(tmp_path):
    cache = EnrichmentCache(tmp_path / "cache.db")
    cache.set("vt", "ipv4_public", "8.8.8.8", {"asn": 15169})
    hit = cache.get("vt", "ipv4_public", "8.8.8.8")
    assert hit is not None and hit.payload == {"asn": 15169}
    assert cache.stats()["entries"] == 1
