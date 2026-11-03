"""Regression tests for the TapWriter persistence-gap fix.

Flows that complete via ``_attach_response`` (a Content-Length-complete HTTP
response arriving during ``on_data``) must emit EXACTLY ONE ``COMPLETED``
event — at on_data time, not duplicated at flush — so a writer-style
subscriber persists the flow exactly once. Before the fix such flows were
never persisted (zero COMPLETED). Driven through FlowCollector via on_data +
flush. Pure Python — no device/Frida.
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.flow.collector import FlowCollector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(data, direction, function, *, timestamp=1000.0,
           src_addr="10.0.0.2", src_port=51000,
           dst_addr="93.184.216.34", dst_port=443,
           ssl_session_id="sess-1"):
    return SimpleNamespace(
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        data=data,
        direction=direction,
        timestamp=timestamp,
        function=function,
        ssl_session_id=ssl_session_id,
    )


_REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_COMPLETE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
    b"Content-Type: text/plain\r\n\r\nhello"
)


def _drive_request_response(fc, *, t=1000.0):
    fc.on_data(_event(_REQUEST, "write", "SSL_write", timestamp=t))
    fc.on_data(_event(_COMPLETE_RESPONSE, "read", "SSL_read", timestamp=t + 0.1))


# ---------------------------------------------------------------------------
# 1. Exactly one COMPLETED during on_data; none added at flush
# ---------------------------------------------------------------------------

def test_complete_response_emits_one_completed_during_on_data():
    fc = FlowCollector()
    events: list[tuple[str, str]] = []
    fc.subscribe(lambda flow, et: events.append((et.value, flow.flow_id)))

    _drive_request_response(fc)

    completed_before_flush = [e for e in events if e[0] == "completed"]
    assert len(completed_before_flush) == 1

    fc.flush()
    completed_after_flush = [e for e in events if e[0] == "completed"]
    # No double-emit: flush must NOT add a second COMPLETED for this flow.
    assert len(completed_after_flush) == 1


# ---------------------------------------------------------------------------
# 2. Writer-style subscriber persists the flow exactly once
# ---------------------------------------------------------------------------

def test_writer_subscriber_persists_flow_once():
    fc = FlowCollector()
    persisted: list[str] = []

    def writer(flow, et):
        if et.value == "completed":
            persisted.append(flow.flow_id)

    fc.subscribe(writer)

    _drive_request_response(fc)
    fc.flush()

    assert len(persisted) == 1


# ---------------------------------------------------------------------------
# 3. Completed flow carries the layer stack
# ---------------------------------------------------------------------------

def test_completed_flow_has_layer_stack():
    fc = FlowCollector()
    _drive_request_response(fc)
    fc.flush()

    flows = fc.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert [ly.name for ly in flow.layers] == ["tls", "http1"]
    assert flow.layer("http1").parsed is flow.request


# ---------------------------------------------------------------------------
# 4. Request-only flow still completes via flush
# ---------------------------------------------------------------------------

def test_request_only_flow_completes_at_flush():
    fc = FlowCollector()
    events: list[tuple[str, str]] = []
    fc.subscribe(lambda flow, et: events.append((et.value, flow.flow_id)))

    fc.on_data(_event(_REQUEST, "write", "SSL_write"))
    # No completion yet (no complete response).
    assert [e for e in events if e[0] == "completed"] == []

    fc.flush()
    completed = [e for e in events if e[0] == "completed"]
    assert len(completed) == 1


# ---------------------------------------------------------------------------
# 5. Two complete responses on one connection -> two distinct COMPLETED
# ---------------------------------------------------------------------------

def test_two_complete_responses_emit_two_completed():
    fc = FlowCollector()
    events: list[tuple[str, str]] = []
    fc.subscribe(lambda flow, et: events.append((et.value, flow.flow_id)))

    _drive_request_response(fc, t=1000.0)
    _drive_request_response(fc, t=1002.0)
    fc.flush()

    completed = [e for e in events if e[0] == "completed"]
    assert len(completed) == 2
    flow_ids = {fid for _, fid in completed}
    assert len(flow_ids) == 2


# ---------------------------------------------------------------------------
# retain_completed=False (headless --tap): completed flows are released
# ---------------------------------------------------------------------------

def test_release_mode_drops_flow_after_completed_reaches_subscribers():
    fc = FlowCollector(retain_completed=False)
    seen_while_notified: list[bool] = []
    fc.subscribe(lambda flow, et: et.value == "completed"
                 and seen_while_notified.append(fc.get_flow(flow.flow_id) is not None))

    _drive_request_response(fc)

    assert seen_while_notified == [True]  # writer still sees it at COMPLETED
    assert fc.get_flows() == []
    assert fc.memory_stats()["flow_count"] == 0


def test_release_mode_keeps_capturing_on_the_same_connection():
    fc = FlowCollector(retain_completed=False)
    completed: list[str] = []
    fc.subscribe(lambda flow, et: et.value == "completed" and completed.append(flow.flow_id))

    _drive_request_response(fc, t=1000.0)
    _drive_request_response(fc, t=1001.0)
    fc.flush()

    assert len(completed) == 2 and len(set(completed)) == 2
    assert fc.get_flows() == []


def test_default_mode_retains_completed_flows():
    fc = FlowCollector()
    _drive_request_response(fc)
    assert len(fc.get_flows()) == 1
