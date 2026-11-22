#!/usr/bin/env python3
"""``<pcap>.request_contexts.jsonl``: the -f --attribute-sdk request-context sidecar."""

import json
import logging
import types

from friTap.config import FriTapConfig
from friTap.events import EventBus, RequestContextEvent
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.request_context_sidecar import (
    RequestContextSidecar,
    read_request_context_rows,
    request_context_row,
    request_contexts_sidecar_path,
)
from friTap.pcap import PCAP


def _event(**overrides):
    fields = dict(
        timestamp=1700000000.25, event="start", req_id="rc-1", stack_kind="cronet",
        url="https://api.example.com/v1/x?a=1", method="POST",
        frames=["com.sdk.Net.call", "com.app.Main.run"], thread="main", tid=4242,
        t_ms=1700000000123.0,
    )
    fields.update(overrides)
    return RequestContextEvent(**fields)


def test_sidecar_path_is_pcap_plus_suffix():
    assert request_contexts_sidecar_path("/x/cap.pcap") == "/x/cap.pcap.request_contexts.jsonl"


def test_row_has_public_fields_only():
    row = request_context_row(_event())
    assert "_cancelled" not in row
    assert RequestContextEvent(**row) == _event()
    assert row["timestamp"] == 1700000000.25 and row["t_ms"] == 1700000000123.0
    assert row["protocol"] == "tls" and row["req_id"] == "rc-1"


def test_round_trip_through_bus(tmp_path):
    path = tmp_path / "cap.pcap.request_contexts.jsonl"
    bus = EventBus()
    sidecar = RequestContextSidecar(str(path))
    sidecar.attach(bus)
    first = _event()
    second = _event(event="end", url="", method="", frames=[], error="net::ERR_ABORTED", t_ms=None)
    bus.emit(first)
    bus.emit(second)
    sidecar.close()
    bus.emit(_event(req_id="rc-after-close"))

    assert sidecar.rows_written == 2
    assert [json.loads(line)["req_id"] for line in path.read_text().splitlines()] == ["rc-1", "rc-1"]
    assert list(read_request_context_rows(str(path))) == [
        request_context_row(first), request_context_row(second)]


def test_no_event_leaves_no_file(tmp_path):
    path = tmp_path / "cap.pcap.request_contexts.jsonl"
    sidecar = RequestContextSidecar(str(path))
    sidecar.close()
    assert not path.exists()


def test_reader_skips_garbage_and_unknown_fields(tmp_path):
    path = tmp_path / "s.jsonl"
    row = dict(request_context_row(_event()), future_field=1)
    path.write_text("not json\n[1]\n" + json.dumps(row) + "\n")
    assert list(read_request_context_rows(str(path))) == [request_context_row(_event())]


def test_write_failure_warns_once_and_never_raises(tmp_path, fritap_log_records):
    logger = logging.getLogger("test_request_context_sidecar.fail")
    records = fritap_log_records(logger.name)
    sidecar = RequestContextSidecar(str(tmp_path / "missing" / "s.jsonl"), logger)
    sidecar.on_event(_event())
    sidecar.on_event(_event())
    assert sidecar.rows_written == 0
    assert [r.levelno for r in records] == [logging.WARNING]


# --- SSL_Logger wiring ---

def _logger(tmp_path, *, full_capture=True, attribute_sdk=True, plaintext_hooks_disabled=False,
            keylog=True):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._config = FriTapConfig.from_legacy_params(app="a", attribute_sdk=attribute_sdk)
    obj._config.output.full_capture = full_capture
    obj._config.output.keylog = "keys.log" if keylog else None
    obj._config.output.plaintext_hooks_disabled = plaintext_hooks_disabled
    obj._event_bus = EventBus()
    obj.logger = logging.getLogger("test_request_context_sidecar.wiring")
    obj.pcap_obj = types.SimpleNamespace(
        pcap_file_name=str(tmp_path / "cap.pcap"), recorded=[],
    )
    obj.pcap_obj.set_request_contexts_path = obj.pcap_obj.recorded.append
    return obj


def test_logger_writes_sidecar_and_hands_path_to_pcap(tmp_path):
    obj = _logger(tmp_path)
    obj._attach_request_context_sidecar()
    obj._event_bus.emit(_event())
    obj._close_request_context_sidecar()
    expected = str(tmp_path / "cap.pcap.request_contexts.jsonl")
    assert obj.pcap_obj.recorded == [expected]
    assert len(open(expected).read().splitlines()) == 1


def test_logger_without_events_hands_nothing(tmp_path):
    obj = _logger(tmp_path)
    obj._attach_request_context_sidecar()
    obj._close_request_context_sidecar()
    assert obj.pcap_obj.recorded == []


def test_logger_skips_sidecar_when_not_wanted(tmp_path):
    for kwargs in ({"full_capture": False}, {"attribute_sdk": False},
                   {"plaintext_hooks_disabled": True}, {"keylog": False}):
        obj = _logger(tmp_path, **kwargs)
        obj._attach_request_context_sidecar()
        assert obj._request_context_sidecar is None, kwargs


# --- manifest ---

def _manifest_stub(pcap_file_name):
    stub = types.SimpleNamespace()
    stub.pcap_file_name = pcap_file_name
    stub.logger = logging.getLogger("test_request_context_sidecar.manifest")
    stub._observed_server_ports = {"tcp": {443}, "udp": set()}
    stub.keylog_path = None
    stub.capture_protocol = "tls"
    stub.memory_scan_keylogs = {}
    stub._request_contexts_path = None
    stub._write_capture_manifest = PCAP._write_capture_manifest.__get__(stub)
    stub.set_request_contexts_path = PCAP.set_request_contexts_path.__get__(stub)
    for name, attr in vars(PCAP).items():
        if isinstance(attr, staticmethod):
            setattr(stub, name, attr.__func__)
    return stub


def _manifest(pcap):
    with open(f"{pcap}.fritap.json", encoding="utf-8") as fh:
        return json.load(fh)


def test_manifest_records_request_contexts(tmp_path):
    pcap = tmp_path / "cap.pcap"
    sidecar = tmp_path / "cap.pcap.request_contexts.jsonl"
    sidecar.write_text(json.dumps(request_context_row(_event())) + "\n")
    stub = _manifest_stub(str(pcap))
    stub.set_request_contexts_path(str(sidecar))
    stub._write_capture_manifest()
    assert _manifest(pcap)["request_contexts"] == str(sidecar)


def test_manifest_omits_missing_or_empty_sidecar(tmp_path):
    pcap = tmp_path / "cap.pcap"
    stub = _manifest_stub(str(pcap))
    stub._write_capture_manifest()
    assert "request_contexts" not in _manifest(pcap)

    empty = tmp_path / "cap.pcap.request_contexts.jsonl"
    empty.write_text("")
    stub.set_request_contexts_path(str(empty))
    stub._write_capture_manifest()
    assert "request_contexts" not in _manifest(pcap)


def test_read_skips_an_oversized_sidecar_and_overlong_lines(tmp_path, monkeypatch):
    import friTap.output.request_context_sidecar as sidecar_module

    path = tmp_path / "ctx.jsonl"
    good = json.dumps(request_context_row(_event()))
    path.write_text("x" * 600 + "\n" + good + "\n", encoding="utf-8")
    monkeypatch.setattr(sidecar_module, "REQUEST_CONTEXT_LINE_MAX_CHARS", 500)
    assert list(read_request_context_rows(str(path))) == [request_context_row(_event())]
    monkeypatch.setattr(sidecar_module, "REQUEST_CONTEXTS_MAX_BYTES", 100)
    assert list(read_request_context_rows(str(path))) == []
