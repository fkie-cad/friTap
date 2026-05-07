"""Unit tests for the friTap debug-log subsystem (friTap.fritap_utility)."""

import logging
import os
import tempfile
import threading
import warnings

import pytest

from friTap import fritap_utility as fu


@pytest.fixture(autouse=True)
def _isolated_debug_log():
    """Ensure each test starts and ends with no live writer."""
    fu.close_debug_log()
    yield
    fu.close_debug_log()


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestOpenDebugLog:
    def test_open_creates_file_with_header(self, tmp_path):
        path = str(tmp_path / "fritap.log")
        result = fu.open_debug_log(path)
        assert result == path
        # Force the writer thread to drain.
        fu.close_debug_log()
        body = _read(path)
        assert body.startswith("# friTap debug log")
        assert "python=" in body

    def test_pid_suffix_when_no_override(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Clear FRITAP_DEBUG_LOG so the cwd path is chosen.
        monkeypatch.delenv("FRITAP_DEBUG_LOG", raising=False)
        path = fu.open_debug_log()
        assert os.path.basename(path).startswith("fritap_debug_")
        assert path.endswith(f"_{os.getpid()}.log")
        fu.close_debug_log()


class TestAttachFileHandlers:
    def test_logger_warning_lands_in_file(self, tmp_path):
        path = str(tmp_path / "h.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        logging.getLogger("friTap.smoke").warning("token-FT-W1")
        fu.close_debug_log()
        assert "token-FT-W1" in _read(path)

    def test_third_party_logger_at_root_lands_once(self, tmp_path):
        path = str(tmp_path / "h2.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        logging.getLogger("h11").error("token-H11-E1")
        fu.close_debug_log()
        body = _read(path)
        assert body.count("token-H11-E1") == 1


class TestWarningCapture:
    def test_warnings_warn_lands_in_file_once(self, tmp_path):
        path = str(tmp_path / "warn.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        fu.enable_warning_capture()
        warnings.warn("token-pyw-uniq", DeprecationWarning, stacklevel=1)
        fu.close_debug_log()
        body = _read(path)
        # warnings.warn emits one logger record whose body includes BOTH the
        # formatted message and the source line; both contain the token, so
        # substring count >= 2 is fine. The invariant is one logger record.
        assert "token-pyw-uniq" in body
        # Count records, not substrings.
        record_lines = [
            l for l in body.splitlines()
            if "py.warnings:" in l
        ]
        assert len(record_lines) == 1, body


class TestExceptHook:
    def test_thread_exception_lands_in_file(self, tmp_path):
        path = str(tmp_path / "exc.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        fu.install_global_excepthook()

        def _bad():
            raise RuntimeError("token-thread-Z1")

        t = threading.Thread(target=_bad, name="UnitSmokeThread")
        t.start()
        t.join()
        fu.close_debug_log()
        body = _read(path)
        assert "token-thread-Z1" in body
        assert "RuntimeError" in body
        assert "Traceback" in body


class TestMuteConsoleHandlers:
    def test_console_handler_level_restored_on_exit(self):
        # Build a fresh logger with a single stderr StreamHandler.
        log = logging.getLogger("friTap.unit-mute-test")
        log.handlers.clear()
        import sys
        h = logging.StreamHandler(sys.stderr)
        h.setLevel(logging.WARNING)
        log.addHandler(h)

        with fu.mute_console_handlers(["friTap.unit-mute-test"]):
            assert h.level > logging.CRITICAL
        # After exit, original level restored.
        assert h.level == logging.WARNING


class TestConcurrentWriters:
    """Stress-test the async writer thread under heavy multi-threaded load.

    Confirms that (a) every record makes it to disk, (b) no record is
    interleaved with another mid-line (each line ends with the marker
    we put on it), and (c) no exception escapes from the writer thread
    even under contention with EventBus prose blocks.
    """

    def test_eight_threads_thousand_records_each_no_truncation(self, tmp_path):
        # setup_fritap_logging is called in production BEFORE open_debug_log
        # and sets friTap.propagate=False so records are not double-logged
        # via root. Mirror that order here so the count assertion is exact.
        fu.setup_fritap_logging()
        path = str(tmp_path / "concurrent.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        fu.enable_warning_capture()

        N_THREADS = 8
        N_PER_THREAD = 1000
        TOKEN = "ZZ-CONCUR-MARK"

        log = logging.getLogger("friTap.concurrent")

        def _hammer(thread_idx: int) -> None:
            for j in range(N_PER_THREAD):
                # Trailing marker lets us assert no line was truncated mid-write.
                log.warning("%s-T%dN%04d <END>", TOKEN, thread_idx, j)

        threads = [
            threading.Thread(target=_hammer, args=(i,), name=f"hammer-{i}")
            for i in range(N_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        fu.close_debug_log()

        body = _read(path)
        records = [l for l in body.splitlines() if TOKEN in l]
        assert len(records) == N_THREADS * N_PER_THREAD, (
            f"expected {N_THREADS * N_PER_THREAD} records, got {len(records)}"
        )
        # Every record line must end with the marker — i.e. no record was
        # truncated by another thread's write interleaving in the middle.
        for line in records:
            assert line.endswith("<END>"), f"truncated line: {line!r}"

    def test_logger_writes_interleave_with_eventbus_prose_safely(self, tmp_path):
        """Mix logger.warning calls with raw writer.write() calls (the
        path the EventBus prose subscription uses) and assert both
        forms appear, none are corrupted, and the file is well-formed.
        """
        fu.setup_fritap_logging()
        path = str(tmp_path / "interleave.log")
        fu.open_debug_log(path)
        fu.attach_file_handlers()
        writer = fu.get_debug_log_writer()
        assert writer is not None

        log = logging.getLogger("friTap.interleave")

        def _logger_calls():
            for i in range(500):
                log.warning("LOG-LINE-%04d <END>", i)

        def _prose_calls():
            for i in range(500):
                writer.write(f"PROSE-BLOCK-{i:04d}\n  k=v\n  data=<{i} bytes>\n\n")

        t1 = threading.Thread(target=_logger_calls, name="logger")
        t2 = threading.Thread(target=_prose_calls, name="prose")
        t1.start(); t2.start(); t1.join(); t2.join()
        fu.close_debug_log()

        body = _read(path)
        log_records = [l for l in body.splitlines() if "LOG-LINE-" in l]
        prose_records = [l for l in body.splitlines() if "PROSE-BLOCK-" in l]
        assert len(log_records) == 500
        assert len(prose_records) == 500
        for line in log_records:
            assert line.endswith("<END>"), f"truncated logger line: {line!r}"
