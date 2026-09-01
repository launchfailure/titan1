from pathlib import Path


def test_scheduled_fuzz_uploads_hidden_artifacts() -> None:
    workflow = Path(".github/workflows/scheduled-fuzz.yml").read_text(encoding="utf-8")

    assert "path: .fuzz-artifacts" in workflow
    assert "if-no-files-found: error" in workflow
    assert "include-hidden-files: true" in workflow
