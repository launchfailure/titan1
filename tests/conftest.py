import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--fail-on-skips",
        action="store_true",
        help="fail a successful test run when any test was skipped",
    )


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if not session.config.getoption("--fail-on-skips"):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = reporter.stats.get("skipped", ()) if reporter is not None else ()
    if skipped and exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter.write_sep(
            "=",
            f"{len(skipped)} skipped tests are prohibited by --fail-on-skips",
        )
