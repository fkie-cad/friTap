"""iter_replay_rows: the non-TUI summary -> display-row seam."""

from __future__ import annotations

from types import SimpleNamespace

from friTap.flow import replay_rows
from friTap.flow.models import FlowSummary as RowSummary
from friTap.flow.tap_format import FlowSummary


def _summary(flow_id="f1", transport="tls", **kw):
    base = dict(
        flow_id=flow_id, connection_id="c", src_addr="10.0.0.1", src_port=1,
        dst_addr="10.0.0.2", dst_port=2, ssl_session_id="s", started=1.0,
        ended=2.0, transport=transport, protocol="HTTP/1.1", method="GET",
        url="/x", host="h", status_code=200, status_text="OK", total_size=0,
    )
    base.update(kw)
    return FlowSummary(**base)


class _Ctrl:
    def __init__(self, summaries, full_flow=None):
        self._summaries = summaries
        self._full = full_flow
        self.stored = []

    def get_summaries(self):
        return list(self._summaries)

    def get_flow(self, flow_id):
        return self._full

    def store_reparse(self, flow_id, request, response, clear_trailing=False):
        self.stored.append((flow_id, request, response, clear_trailing))


def test_plain_row():
    ctrl = _Ctrl([_summary("a"), _summary("b")])
    rows = list(replay_rows.iter_replay_rows(ctrl))
    assert [f.flow_id for f, _ in rows] == ["a", "b"]
    flow, row = rows[0]
    assert isinstance(row, RowSummary)
    assert flow.request.method == "GET" and flow.response.status_code == 200
    assert ctrl.stored == []


def test_received_message_row_gets_response_stub():
    s = _summary("r", transport="telegram_e2e", protocol="Telegram-E2E",
                 method="decryptedMessage", status_code=0,
                 has_request=False, has_response=True)
    (flow, _), = replay_rows.iter_replay_rows(_Ctrl([s]))
    assert flow.request is None
    assert flow.response is not None and not flow.response.is_request
    assert flow.flow_method == "decryptedMessage"


def test_total_bytes_set_without_reparse():
    (flow, _), = replay_rows.iter_replay_rows(_Ctrl([_summary(total_size=42)]))
    assert flow._total_bytes == 42


def test_reparse_path_calls_store_reparse(monkeypatch):
    s = _summary("m", transport="mtproto", protocol="unknown", method="",
                 url="", host="", status_code=0, total_size=10,
                 has_request=True)
    from friTap.parsers.base import ParseResult
    new_req = ParseResult(protocol="MTProto", is_request=True)
    new_resp = ParseResult(protocol="MTProto", is_request=False)
    full = SimpleNamespace(request=new_req, response=new_resp, transport="mtproto")
    monkeypatch.setattr("friTap.flow.reparse.reparse_flow", lambda f: True)
    ctrl = _Ctrl([s], full_flow=full)
    (flow, _), = replay_rows.iter_replay_rows(ctrl)
    assert flow.request is new_req and flow.response is new_resp
    assert ctrl.stored == [("m", new_req, new_resp, True)]


def test_no_reparse_when_total_size_zero(monkeypatch):
    s = _summary(protocol="unknown", method="", url="", host="", status_code=0)
    ctrl = _Ctrl([s], full_flow=SimpleNamespace())
    list(replay_rows.iter_replay_rows(ctrl))
    assert ctrl.stored == []


def test_predicates():
    flow = SimpleNamespace
    recv = SimpleNamespace(has_request=False, has_response=True)
    assert replay_rows.is_received_message_summary(flow(transport="mtproto"), recv)
    assert not replay_rows.is_received_message_summary(flow(transport="tls"), recv)
    assert replay_rows.is_tl_pinned_flow(flow(transport="mtproto"))
    assert not replay_rows.needs_tl_reparse(flow(transport="tls"))


def test_module_is_textual_free():
    import subprocess
    import sys
    code = ("import sys, friTap.flow.replay_rows;"
            "assert not [m for m in sys.modules if m=='textual' or m.startswith('friTap.tui')]")
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
