import json


def test_cli_fail_on_risk_level_high_exits_nonzero(tmp_path, monkeypatch):
    # Trigger Multi-Stage Infrastructure (high severity) by including urls +
    # ipv4 + domains + emails, and include enough *distinct* real IOCs that the
    # risk score reaches HIGH on genuine indicators alone (no reliance on
    # decoder artifacts).
    data = (
        b"http://example.com/a\n"
        b"https://malicious.example.net/b\n"
        b"http://cdn.bad.example.org/c\n"
        b"8.8.8.8\n"
        b"1.1.1.1\n"
        b"9.9.9.9\n"
        b"evil.example.com\n"
        b"c2.example.net\n"
        b"attacker@example.org\n"
        b"admin@bad.example.net\n"
    )

    sample = tmp_path / "sample.txt"
    sample.write_bytes(data)
    out = tmp_path / "report.json"

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--enable-detections",
            "--fail-on-risk-level",
            "HIGH",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 2

    report = json.loads(out.read_text())
    assert "risk_assessment" in report
    assert report["risk_assessment"]["risk_level"] in {"HIGH", "CRITICAL"}


def test_cli_fail_on_risk_level_high_allows_clean(tmp_path, monkeypatch):
    # A benign payload with no IOCs.
    data = b"just some harmless text\n"
    sample = tmp_path / "sample.txt"
    sample.write_bytes(data)
    out = tmp_path / "report.json"

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--enable-detections",
            "--fail-on-risk-level",
            "HIGH",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0
