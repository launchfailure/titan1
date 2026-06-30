"""Tests for the performance profiler, especially graceful degradation when
the optional ``psutil`` dependency is not installed.

psutil lives in ``requirements-optional.txt``. Before the fix, ``profiling.py``
did a hard top-level ``import psutil``, so importing the module (and therefore
``titan-decoder --perf-profile``) crashed with ``ModuleNotFoundError`` on any
environment without psutil. These tests pin the degraded-but-working behavior.
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def _reload_profiling_without_psutil(monkeypatch):
    """Reload titan_decoder.core.profiling with psutil import forced to fail."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psutil" or name.startswith("psutil."):
            raise ImportError("No module named 'psutil' (simulated)")
        return real_import(name, *args, **kwargs)

    # Drop any cached psutil + the target module so the import runs fresh.
    monkeypatch.delitem(sys.modules, "psutil", raising=False)
    monkeypatch.delitem(sys.modules, "titan_decoder.core.profiling", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    module = importlib.import_module("titan_decoder.core.profiling")
    return importlib.reload(module)


def test_profiling_imports_without_psutil(monkeypatch):
    mod = _reload_profiling_without_psutil(monkeypatch)
    assert mod.psutil is None


def test_profiler_runs_without_psutil(monkeypatch):
    mod = _reload_profiling_without_psutil(monkeypatch)

    profiler = mod.PerformanceProfiler()
    assert profiler.process is None

    with profiler.profile(enable_cprofile=True) as metrics:
        # Trigger a memory sample to make sure the no-op path is exercised.
        profiler.record_memory_sample()
        total = sum(i * i for i in range(1000))

    # Timing / cProfile still produce real numbers.
    assert metrics.execution_time >= 0.0
    assert metrics.function_calls >= 0
    # Memory/CPU degrade cleanly to zero rather than crashing.
    assert metrics.memory_peak == 0.0
    assert metrics.memory_average == 0.0
    assert metrics.cpu_percent == 0.0
    assert total > 0


def test_record_memory_sample_no_psutil_is_noop(monkeypatch):
    mod = _reload_profiling_without_psutil(monkeypatch)
    profiler = mod.PerformanceProfiler()
    profiler.record_memory_sample()
    profiler.record_memory_sample()
    assert profiler.memory_samples == []


@pytest.fixture(autouse=True)
def _restore_profiling_module():
    """Ensure later tests see a normally-imported profiling module."""
    yield
    sys.modules.pop("titan_decoder.core.profiling", None)
    importlib.import_module("titan_decoder.core.profiling")
