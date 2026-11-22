"""Rendering of the agent's DetachReport (friTap/detach_report.py)."""

from __future__ import annotations

from unittest.mock import MagicMock

from friTap import detach_report as dr

NSS_STEP = {"name": "teardown:nss-key-callbacks", "ok": True, "ms": 2,
            "summary": {"owned": 4, "toApp": 3, "toNull": 1, "stale": 0, "failed": 0}}
FAILED_STEP = {"name": "interceptor-detach-all", "ok": False, "ms": 1.5,
               "error": "access violation"}
OK_STEP = {"name": "pre-shutdown-flush", "ok": True, "ms": 0}


def _report(*steps, logs=(), dropped=0):
    return {"version": 1, "repeat": False, "total_ms": 12.5, "steps": list(steps),
            "logs": list(logs), "dropped_logs": dropped}


def test_none_report():
    assert dr.summary_line(None) == "Agent detach: agent returned no detach report"
    assert dr.step_lines(None) == dr.failed_step_lines(None) == dr.agent_log_lines(None) == []


def test_repeat_report():
    assert dr.summary_line({"repeat": True, "steps": []}) == dr.REPEAT_MESSAGE


def test_all_ok_summary():
    line = dr.summary_line(_report(OK_STEP, OK_STEP))
    assert line == "Agent detach: 2/2 steps ok, 0 failed, total 12.5 ms"


def test_failed_step_counts_and_warns():
    report = _report(OK_STEP, FAILED_STEP)
    assert "1/2 steps ok, 1 failed" in dr.summary_line(report)
    assert dr.failed_step_lines(report) == [
        "Agent detach step interceptor-detach-all failed: access violation"]
    assert dr.step_lines(report)[1] == (
        "Agent detach step interceptor-detach-all: FAILED 1.5 ms access violation")


def test_nss_summary_phrase():
    report = _report(OK_STEP, NSS_STEP)
    assert dr.summary_line(report).endswith(
        "; NSS callbacks restored app=3 null=1 stale=0 failed=0")
    assert dr.step_lines(report)[1] == (
        "Agent detach step teardown:nss-key-callbacks: ok 2 ms "
        "owned=4 toApp=3 toNull=1 stale=0 failed=0")


def test_nss_summary_phrase_carries_ech_dual_count():
    step = {"name": "teardown:nss-key-callbacks", "ok": True, "ms": 2,
            "summary": {"owned": 2, "toApp": 1, "toNull": 1, "stale": 0, "failed": 0, "echDual": 7}}
    assert dr.summary_line(_report(OK_STEP, step)).endswith(
        "; NSS callbacks restored app=1 null=1 stale=0 failed=0 echDual=7")


def test_agent_logs_and_dropped_count():
    report = _report(logs=[{"level": "debug", "msg": "restored 3"}], dropped=2)
    assert dr.agent_log_lines(report) == [
        "[agent:debug] restored 3", "[agent] 2 further teardown log line(s) dropped"]


def test_agent_log_lines_render_every_level_including_unknown():
    logs = [{"level": "info", "msg": "a"}, {"level": "debug", "msg": "b"},
            {"level": "warn", "msg": "c"}, {"level": "error", "msg": "d"},
            {"level": "trace", "msg": "e"}, {"msg": "f"}]
    assert dr.agent_log_lines(_report(logs=logs)) == [
        "[agent:info] a", "[agent:debug] b", "[agent:warn] c", "[agent:error] d",
        "[agent:trace] e", "[agent:info] f"]


def test_malformed_report_does_not_raise():
    report = {"steps": "nope", "logs": None, "total_ms": None}
    assert dr.summary_line(report) == "Agent detach: 0/0 steps ok, 0 failed, total ? ms"
    assert dr.step_lines(report) == []


def test_log_detach_report_levels():
    logger = MagicMock()
    dr.log_detach_report(logger, _report(NSS_STEP, FAILED_STEP,
                                         logs=[{"level": "info", "msg": "x"}]))
    assert logger.info.call_count == 1
    assert logger.debug.call_count == 3  # two steps + one agent log line
    logger.warning.assert_called_once_with(
        "Agent detach step interceptor-detach-all failed: access violation")


def test_log_detach_report_agent_warn_error_at_warning_rest_at_debug():
    import logging

    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append((record.levelno, record.getMessage()))

    logger = logging.getLogger("friTap")
    handler = _Collect(level=logging.DEBUG)
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        dr.log_detach_report(logger, _report(logs=[
            {"level": "info", "msg": "i"}, {"level": "debug", "msg": "d"},
            {"level": "warn", "msg": "w"}, {"level": "error", "msg": "e"},
            {"level": "trace", "msg": "t"}], dropped=1))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
    by_msg = {msg: level for level, msg in records}
    assert by_msg["[agent:warn] w"] == logging.WARNING
    assert by_msg["[agent:error] e"] == logging.WARNING
    for msg in ("[agent:info] i", "[agent:debug] d", "[agent:trace] t",
                "[agent] 1 further teardown log line(s) dropped"):
        assert by_msg[msg] == logging.DEBUG
