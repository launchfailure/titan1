"""Resource management and timeout enforcement for safe analysis."""

from __future__ import annotations

import signal
import threading
from contextlib import contextmanager
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class TimeoutError(Exception):
    """Raised when an operation exceeds its timeout."""

    pass


class ResourceManager:
    """Manages resource limits and timeouts for analysis operations."""

    def __init__(self, config: dict):
        self.config = config

    @contextmanager
    def timeout_context(self, seconds: int, operation_name: str = "operation"):
        """Context manager for enforcing timeouts on operations.

        SIGALRM-based timeouts only work on POSIX and only from the main
        thread. Elsewhere (Windows, worker threads) ``signal.signal`` raises,
        and since the engine swallows per-decoder exceptions that would
        silently disable every decoder/analyzer — so fall back to running the
        operation unguarded instead. The run-level wall-clock deadline and
        memory checks in the engine still bound the overall analysis.
        """
        sigalrm = getattr(signal, "SIGALRM", None)
        alarm = getattr(signal, "alarm", None)
        can_use_alarm = sigalrm is not None and callable(alarm) and (
            threading.current_thread() is threading.main_thread()
        )
        if not can_use_alarm or seconds <= 0:
            if not can_use_alarm:
                logger.debug(
                    "SIGALRM unavailable (platform/thread); running %s without "
                    "a per-operation timeout",
                    operation_name,
                )
            yield
            return

        assert sigalrm is not None
        assert callable(alarm)

        def timeout_handler(signum, frame):
            raise TimeoutError(f"{operation_name} exceeded {seconds}s timeout")

        # Set up the timeout
        old_handler = signal.signal(sigalrm, timeout_handler)
        alarm(seconds)

        try:
            yield
        finally:
            # Restore original handler and cancel alarm
            alarm(0)
            signal.signal(sigalrm, old_handler)

    def check_memory_usage(self) -> float:
        """Check current memory usage in MB."""
        try:
            import psutil

            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            # psutil not available, can't check memory
            return 0.0
        except Exception as e:
            logger.warning(f"Could not check memory usage: {e}")
            return 0.0

    def should_abort_due_to_memory(self, max_memory_mb: Optional[int] = None) -> bool:
        """Check if analysis should abort due to memory pressure."""
        if max_memory_mb is None:
            max_memory_mb = self.config.get("max_memory_mb", 1024)  # 1GB default

        current_mb = self.check_memory_usage()
        if current_mb > max_memory_mb:
            logger.error(
                f"Memory limit exceeded: {current_mb:.1f}MB > {max_memory_mb}MB"
            )
            return True
        return False
