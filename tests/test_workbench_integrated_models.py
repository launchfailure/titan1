from titan_decoder.workbench_ui.models import AnalysisSnapshot, WorkbenchState


def test_snapshot_counts_iocs():
    snapshot = AnalysisSnapshot(report={"iocs": {"domains": ["a"], "ips": ["1", "2"]}})
    assert snapshot.ioc_count == 3


def test_state_defaults_offline():
    state = WorkbenchState()
    assert state.offline is True
    assert state.profile == "fast"
