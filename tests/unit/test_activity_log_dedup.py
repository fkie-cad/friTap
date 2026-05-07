"""Unit tests for the 2-second dedup window in ActivityLog.

ActivityLog is a Textual RichLog subclass. We can't instantiate it
without a running Textual app, but we CAN exercise the dedup state
machine in isolation by binding the methods to a stub object that
mimics the parts of self that ``log_warning`` / ``log_error`` touch.
"""

import logging
import time
import types

import pytest


def _make_stub_log():
    """Build a minimal stub that mimics ActivityLog enough for dedup logic.

    Pulls the unbound methods straight off the ActivityLog class so the
    real dedup state machine runs against the stub.
    """
    try:
        from friTap.tui.widgets.activity_log import ActivityLog
    except ImportError:
        pytest.skip("textual not installed")

    stub = types.SimpleNamespace()
    stub._plain_lines = []
    stub._dedup_state = (None, 0.0, 0, "")
    stub._MAX_LINES = 10_000
    stub._DEDUP_WINDOW_SEC = ActivityLog._DEDUP_WINDOW_SEC
    stub.written: list = []
    stub.write = lambda s: stub.written.append(str(s))

    # Bind the unbound methods so they operate on stub.
    stub._dedup_should_suppress = ActivityLog._dedup_should_suppress.__get__(stub)
    stub._emit_dedup_summary = ActivityLog._emit_dedup_summary.__get__(stub)
    stub._trim_lines = ActivityLog._trim_lines.__get__(stub)
    stub.log_warning = ActivityLog.log_warning.__get__(stub)
    stub.log_error = ActivityLog.log_error.__get__(stub)
    stub.log_info = ActivityLog.log_info.__get__(stub)
    return stub


@pytest.fixture
def stub_log():
    return _make_stub_log()


class TestDedupSuppressionWithinWindow:
    def test_identical_warnings_within_window_collapse(self, stub_log, monkeypatch):
        # Pin time so the test is deterministic.
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        stub_log.log_warning("Parser X failed: boom")
        fake_now[0] += 0.5
        stub_log.log_warning("Parser X failed: boom")
        fake_now[0] += 0.5
        stub_log.log_warning("Parser X failed: boom")

        # Only the first write should have happened — the next two are suppressed.
        warning_writes = [w for w in stub_log.written if "WARN" in w and "Parser X failed" in w]
        assert len(warning_writes) == 1
        # plain_lines mirrors the visible state; same invariant.
        warning_plain = [l for l in stub_log._plain_lines if "Parser X failed" in l]
        assert len(warning_plain) == 1

    def test_different_warning_breaks_dedup(self, stub_log, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        stub_log.log_warning("Parser X failed")
        fake_now[0] += 0.1
        stub_log.log_warning("Parser X failed")  # suppressed
        fake_now[0] += 0.1
        stub_log.log_warning("Parser Y failed")  # NEW key — emits + flushes summary

        repeat_writes = [w for w in stub_log.written if "REPEAT" in w]
        warn_writes = [w for w in stub_log.written if "WARN" in w]
        # One REPEAT summary line ("repeated 1 more time(s)") plus two
        # distinct WARN lines (Parser X first instance + Parser Y).
        assert len(repeat_writes) == 1
        assert "1 more time" in repeat_writes[0]
        assert len(warn_writes) == 2

    def test_warning_outside_window_is_not_suppressed(self, stub_log, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        stub_log.log_warning("Parser X failed")
        fake_now[0] += stub_log._DEDUP_WINDOW_SEC + 0.5
        stub_log.log_warning("Parser X failed")  # window expired → emits
        warn_writes = [w for w in stub_log.written if "WARN" in w]
        assert len(warn_writes) == 2


class TestDedupAppliesOnlyToWarnError:
    def test_log_info_is_not_deduped(self, stub_log, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        for _ in range(5):
            stub_log.log_info("session ready")
            fake_now[0] += 0.1
        info_writes = [w for w in stub_log.written if "INFO" in w]
        assert len(info_writes) == 5

    def test_warning_and_error_are_independent_keys(self, stub_log, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        stub_log.log_warning("X")
        stub_log.log_error("X")
        # Different level → different key → not deduped.
        warn_writes = [w for w in stub_log.written if "WARN" in w]
        err_writes = [w for w in stub_log.written if "ERROR" in w]
        assert len(warn_writes) == 1
        assert len(err_writes) == 1


class TestDedupSummaryEmission:
    def test_summary_includes_suppressed_count(self, stub_log, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])

        stub_log.log_warning("noisy")
        for _ in range(4):
            fake_now[0] += 0.1
            stub_log.log_warning("noisy")  # 4 suppressed
        # Trigger flush by changing the key.
        fake_now[0] += 0.1
        stub_log.log_warning("different")
        repeat_writes = [w for w in stub_log.written if "REPEAT" in w]
        assert len(repeat_writes) == 1
        # 4 suppressed × → "repeated 4 more time(s)"
        assert "4 more time" in repeat_writes[0]
