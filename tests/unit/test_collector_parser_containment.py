"""Unit tests for parser-error containment in FlowCollector."""

import pytest

from friTap.events import (
    DatalogEvent,
    ErrorEvent,
    EventBus,
    ERROR_SEVERITY_WARNING,
)
from friTap.flow.collector import FlowCollector
from friTap.parsers.base import BaseParser, ParseResult, SafeParserAdapter


def _make_event(data: bytes, **kw) -> DatalogEvent:
    defaults = dict(
        function="SSL_read",
        direction="read",
        src_addr="1.1.1.1",
        src_port=1,
        dst_addr="2.2.2.2",
        dst_port=443,
        ssl_session_id="",
        client_random="",
    )
    defaults.update(kw)
    return DatalogEvent(data=data, **defaults)


class _ExplodingParser(BaseParser):
    PROTOCOL = "exploding"

    def __init__(self):
        self.calls = 0
        self.trailing_data = None

    def feed(self, data, direction):
        self.calls += 1
        raise RuntimeError(f"feed-bang #{self.calls}")

    def flush(self):
        return []

    def can_parse(self, data):
        return True


@pytest.fixture
def bus_collector():
    """Bus + collector + ErrorEvent sink. Yields (bus, collector, errors)."""
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    errors: list = []
    bus.subscribe(ErrorEvent, errors.append)
    bus.subscribe(DatalogEvent, collector.on_data)
    return bus, collector, errors


class TestParserFailureEmitsErrorEvent:
    def test_failure_emits_severity_warning_event(self, bus_collector):
        bus, collector, errors = bus_collector
        # Feed enough bytes to commit a parser; then swap the connection's
        # parser to an exploding one so the next feed triggers containment.
        bus.emit(_make_event(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        # After commit, pick the underlying ConnectionState.
        assert len(collector._connections) == 1
        conn = next(iter(collector._connections.values()))
        # Wrap a fresh exploding parser via the same callback path the
        # collector uses, so we exercise _on_parser_failure end-to-end.
        conn.parser = collector._wrap_parser(_ExplodingParser(), conn)
        bus.emit(_make_event(b"more bytes"))
        assert len(errors) >= 1
        last = errors[-1]
        assert last.severity == ERROR_SEVERITY_WARNING
        assert "_ExplodingParser" in last.error
        assert "RuntimeError" in last.description

    def test_failure_does_not_unsubscribe_collector(self, bus_collector):
        bus, collector, errors = bus_collector
        # Trigger many failures on the same connection — adapter
        # short-circuits, EventBus should never auto-unsubscribe on_data.
        bus.emit(_make_event(b"GET / HTTP/1.1\r\n\r\n"))
        conn = next(iter(collector._connections.values()))
        conn.parser = collector._wrap_parser(_ExplodingParser(), conn)
        for _ in range(50):
            bus.emit(_make_event(b"chunk"))
        # Adapter short-circuits; only the FIRST failure ever invoked the
        # exploding feed. So errors length is exactly 1.
        assert len(errors) == 1
        # And the subscriber is still alive.
        bus.emit(_make_event(b"another", direction="write"))
        assert collector.on_data in [
            cb for _p, cb in bus._subscribers.get(DatalogEvent, [])
        ]

    def test_active_flow_protocol_reset_on_failure(self, bus_collector):
        bus, collector, errors = bus_collector
        bus.emit(_make_event(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        conn = next(iter(collector._connections.values()))
        # Pick the active flow and stamp a fake detected_protocol so we
        # can verify reset.
        flow = collector._flows[conn.active_flow_id]
        flow.detected_protocol = "HTTP/1.1"
        conn.parser = collector._wrap_parser(_ExplodingParser(), conn)
        bus.emit(_make_event(b"more"))
        assert flow.detected_protocol == "unknown"


class TestWrapParserIdempotence:
    def test_wrapping_an_adapter_returns_same_instance(self):
        from friTap.parsers.hexdump import HexdumpParser
        bus = EventBus()
        coll = FlowCollector(event_bus=bus)
        adapter = SafeParserAdapter(HexdumpParser())
        result = coll._wrap_parser(adapter)
        assert result is adapter
