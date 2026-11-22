"""The agent's detach report reaches the JSON document and the JSONL stdout stream."""

import io
import json
from types import SimpleNamespace

from friTap.events import DetachReportEvent, EventBus
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.json_handler import JsonOutputHandler
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler

REPORT = {"version": 1, "repeat": False, "total_ms": 12,
          "steps": [{"name": "detachAll", "ok": True, "ms": 3}],
          "logs": [], "dropped_logs": 0}


def _json_doc(tmp_path, event, **kw):
    path = str(tmp_path / "out.json")
    bus = EventBus()
    handler = JsonOutputHandler(path, session_info={"target_app": "x"}, **kw)
    handler.setup(bus)
    if event is not None:
        bus.emit(event)
    handler.close()
    return json.loads((tmp_path / "out.json").read_text())


def test_json_report_present(tmp_path):
    doc = _json_doc(tmp_path, DetachReportEvent(report=REPORT))
    assert doc["detach_report"] == REPORT
    assert "detach_report_status" not in doc


def test_json_report_none_with_status(tmp_path):
    doc = _json_doc(tmp_path, DetachReportEvent(report=None, status="timeout"))
    assert doc["detach_report"] is None
    assert doc["detach_report_status"] == "timeout"


def test_json_without_event_has_no_key(tmp_path):
    assert "detach_report" not in _json_doc(tmp_path, None)


def test_json_auxiliary_ignores_report(tmp_path):
    doc = _json_doc(tmp_path, DetachReportEvent(report=REPORT), auxiliary=True)
    assert "detach_report" not in doc


def _jsonl(event):
    out = io.StringIO()
    bus = EventBus()
    handler = JsonlStdoutHandler(stream=out)
    handler.setup(bus)
    bus.emit(event)
    handler.close()
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_jsonl_report_record_before_stream_end():
    records = _jsonl(DetachReportEvent(report=REPORT))
    kinds = [r["type"] for r in records]
    assert kinds.index("detach_report") < kinds.index("stream_end")
    assert records[kinds.index("detach_report")]["report"] == REPORT


def test_jsonl_report_none_with_status():
    rec = next(r for r in _jsonl(DetachReportEvent(status="failed"))
               if r["type"] == "detach_report")
    assert rec["report"] is None and rec["status"] == "failed"


def _logger_stub(outcome, report):
    emitted, order = [], []
    stub = SimpleNamespace(
        _graceful_detach_outcome=outcome, detach_report=report,
        GRACEFUL_OK=SSL_Logger.GRACEFUL_OK, GRACEFUL_SKIPPED=SSL_Logger.GRACEFUL_SKIPPED,
        script=object(),
        logger=SimpleNamespace(debug=lambda *a, **k: None),
        _event_bus=SimpleNamespace(emit=lambda e: (emitted.append(e), order.append("emit"))),
        _handlers_active=True,
        _output_handlers=[SimpleNamespace(close=lambda: order.append("close"))],
    )
    stub._emit_detach_report = lambda: SSL_Logger._emit_detach_report(stub)
    return stub, emitted, order


def test_close_emits_report_before_closing_outputs():
    stub, emitted, order = _logger_stub(SSL_Logger.GRACEFUL_OK, REPORT)
    SSL_Logger.close_output_handlers(stub)
    assert order == ["emit", "close"]
    assert emitted[0].report == REPORT and emitted[0].status is None


def test_close_emits_status_when_no_report():
    stub, emitted, _ = _logger_stub(SSL_Logger.GRACEFUL_TIMEOUT, None)
    SSL_Logger.close_output_handlers(stub)
    assert emitted[0].report is None and emitted[0].status == "timeout"


def test_no_report_record_when_no_agent_was_ever_loaded():
    """A spawn that fails before any script exists has nothing to report:
    the outputs must not get a detach_report record (machine-output contract)."""
    stub, emitted, _ = _logger_stub(SSL_Logger.GRACEFUL_SKIPPED, None)
    stub.script = None
    SSL_Logger._emit_detach_report(stub)
    assert emitted == []


def test_skipped_report_is_emitted_when_the_target_died():
    stub, emitted, _ = _logger_stub(SSL_Logger.GRACEFUL_SKIPPED, None)
    SSL_Logger._emit_detach_report(stub)
    assert len(emitted) == 1 and emitted[0].report is None and emitted[0].status == SSL_Logger.GRACEFUL_SKIPPED
