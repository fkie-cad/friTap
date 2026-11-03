"""Unit tests for SafeParserAdapter (friTap.parsers.base)."""

import logging
import struct

import pytest

from friTap.parsers.base import (
    MAX_PARSER_RESETS,
    BaseParser,
    ParseResult,
    ParserFailure,
    SafeParserAdapter,
    unwrap_parser,
)


class _GoodParser(BaseParser):
    PROTOCOL = "good"

    def __init__(self):
        self.feeds = 0
        self.flushes = 0
        self.trailing_data = b""

    def feed(self, data, direction):
        self.feeds += 1
        return [ParseResult(protocol=self.PROTOCOL, body=data, body_size=len(data))]

    def flush(self):
        self.flushes += 1
        return []

    def can_parse(self, data):
        return True


class _BrokenParser(BaseParser):
    PROTOCOL = "broken"

    def __init__(self, exc=None):
        self.exc = exc or RuntimeError("boom")

    def feed(self, data, direction):
        raise self.exc

    def flush(self):
        raise self.exc

    def can_parse(self, data):
        return True


class TestSafeParserAdapterHappyPath:
    def test_feed_delegates_to_inner(self):
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        results = adapter.feed(b"hello", "read")
        assert len(results) == 1
        assert results[0].protocol == "good"
        assert inner.feeds == 1
        assert adapter.failed is False

    def test_flush_delegates_to_inner(self):
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        adapter.flush()
        assert inner.flushes == 1

    def test_protocol_is_mirrored(self):
        adapter = SafeParserAdapter(_GoodParser())
        assert adapter.PROTOCOL == "good"

    def test_can_parse_returns_true_for_good(self):
        adapter = SafeParserAdapter(_GoodParser())
        assert adapter.can_parse(b"x") is True


class TestSafeParserAdapterFailure:
    def test_first_failure_invokes_callback_and_marks_failed(self):
        failures = []
        adapter = SafeParserAdapter(_BrokenParser(), on_failure=failures.append)
        results = adapter.feed(b"x", "read")
        assert results == []
        assert adapter.failed is True
        assert len(failures) == 1
        assert isinstance(failures[0], ParserFailure)
        assert failures[0].parser_name == "_BrokenParser"
        assert failures[0].exc_class == "RuntimeError"
        assert failures[0].direction == "read"
        assert "boom" in failures[0].exc_message
        assert "Traceback" in failures[0].traceback_text

    def test_subsequent_feeds_short_circuit_without_extra_callback(self):
        # Bounded recovery: one callback per failure until the reset budget
        # is spent, then the adapter short-circuits with no more callbacks.
        failures = []
        adapter = SafeParserAdapter(_BrokenParser(), on_failure=failures.append)
        for chunk in (b"x", b"y", b"z", b"w", b"v", b"u"):
            adapter.feed(chunk, "read")
        assert len(failures) == 1 + MAX_PARSER_RESETS
        assert adapter.disabled is True

    def test_flush_failure_also_classified(self):
        failures = []
        adapter = SafeParserAdapter(_BrokenParser(), on_failure=failures.append)
        adapter.flush()
        assert adapter.failed is True
        assert failures[0].direction == "flush"

    def test_no_callback_still_safe(self):
        adapter = SafeParserAdapter(_BrokenParser())
        # Must not raise even when on_failure is None.
        assert adapter.feed(b"x", "read") == []
        assert adapter.failed is True

    def test_callback_exception_is_swallowed(self):
        def bad_cb(_failure):
            raise ValueError("callback exploded")
        adapter = SafeParserAdapter(_BrokenParser(), on_failure=bad_cb)
        # Bad callback must NOT propagate out of feed.
        assert adapter.feed(b"x", "read") == []
        assert adapter.failed is True

    def test_failure_logged_with_traceback(self):
        # Attach our own capturing handler directly to the parser logger.
        # caplog cannot reliably observe records from `friTap.parsers.safe`
        # because `friTap` may have ``propagate=False`` set (production
        # behavior, also set by setup_fritap_logging in earlier tests).
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _Capture(level=logging.WARNING)
        log = logging.getLogger("friTap.parsers.safe")
        log.addHandler(handler)
        try:
            adapter = SafeParserAdapter(_BrokenParser())
            adapter.feed(b"x", "read")
        finally:
            log.removeHandler(handler)
        assert any("_BrokenParser" in r.getMessage() for r in records)
        # Traceback was attached so the debug-log file gets the full stack.
        assert any(r.exc_info for r in records)


class _FlakyParser(BaseParser):
    """Raises on chunks starting with b"BAD"; buffers others until flush.

    Class-level logs span every instance, so a test can see which chunks
    reached any (old or fresh) instance.
    """

    PROTOCOL = "flaky"
    instances: list = []
    seen: list = []

    def __init__(self):
        type(self).instances.append(self)
        self.pending = b""

    def feed(self, data, direction):
        type(self).seen.append(data)
        if data.startswith(b"BAD"):
            raise ValueError("malformed chunk")
        self.pending += data
        return [ParseResult(protocol=self.PROTOCOL, body=data, body_size=len(data))]

    def flush(self):
        out = [ParseResult(protocol=self.PROTOCOL, body=self.pending)] if self.pending else []
        self.pending = b""
        return out

    def can_parse(self, data):
        return True


def _fresh_flaky_adapter(**kwargs) -> SafeParserAdapter:
    _FlakyParser.instances = []
    _FlakyParser.seen = []
    return SafeParserAdapter(_FlakyParser(), **kwargs)


class TestSafeParserAdapterBoundedRecovery:
    def test_recovers_after_one_failure(self):
        failures = []
        adapter = _fresh_flaky_adapter(on_failure=failures.append)
        assert adapter.feed(b"BAD-1", "read") == []
        assert adapter.failed is True  # the latest chunk was dropped
        results = adapter.feed(b"good", "read")
        assert [r.body for r in results] == [b"good"]
        assert adapter.failed is False
        assert adapter.disabled is False
        assert adapter.reset_count == 1
        assert len(failures) == 1

    def test_reset_installs_fresh_instance_of_same_class(self):
        adapter = _fresh_flaky_adapter()
        original = adapter.inner
        adapter.feed(b"BAD", "read")
        assert adapter.inner is not original
        assert type(adapter.inner) is _FlakyParser
        assert len(_FlakyParser.instances) == 2
        assert adapter.PROTOCOL == "flaky"

    def test_disabled_after_four_failures(self):
        failures = []
        adapter = _fresh_flaky_adapter(on_failure=failures.append)
        for index in range(MAX_PARSER_RESETS + 1):
            assert adapter.disabled is False
            adapter.feed(b"BAD-%d" % index, "read")
        assert adapter.disabled is True
        assert adapter.failed is True
        assert adapter.reset_count == MAX_PARSER_RESETS
        assert len(failures) == MAX_PARSER_RESETS + 1
        # Disabled: valid data is no longer parsed and nothing reaches inner.
        seen_before = len(_FlakyParser.seen)
        assert adapter.feed(b"good", "read") == []
        assert adapter.flush() == []
        assert len(_FlakyParser.seen) == seen_before
        assert len(failures) == MAX_PARSER_RESETS + 1

    def test_offending_chunk_is_never_refed(self):
        adapter = _fresh_flaky_adapter()
        adapter.feed(b"BAD-chunk", "read")
        adapter.feed(b"next", "write")
        assert _FlakyParser.seen == [b"BAD-chunk", b"next"]
        # The fresh instance only ever saw the chunk after the failure.
        assert adapter.inner.pending == b"next"

    def test_flush_after_reset(self):
        adapter = _fresh_flaky_adapter()
        adapter.feed(b"lost-with-old-parser", "read")
        adapter.feed(b"BAD", "read")
        adapter.feed(b"kept", "read")
        flushed = adapter.flush()
        assert [r.body for r in flushed] == [b"kept"]
        assert adapter.failed is False

    def test_flush_failure_resets_and_keeps_working(self):
        adapter = SafeParserAdapter(_BrokenParser())
        assert adapter.flush() == []
        assert adapter.reset_count == 1
        assert adapter.disabled is False

    def test_custom_parser_factory_is_used(self):
        made = []

        def factory():
            made.append(_GoodParser())
            return made[-1]

        adapter = SafeParserAdapter(_BrokenParser(), parser_factory=factory)
        adapter.feed(b"x", "read")
        assert adapter.inner is made[0]
        assert [r.body for r in adapter.feed(b"y", "read")] == [b"y"]
        assert adapter.PROTOCOL == "good"

    def test_factory_error_disables(self):
        def factory():
            raise TypeError("needs arguments")

        adapter = SafeParserAdapter(_BrokenParser(), parser_factory=factory)
        assert adapter.feed(b"x", "read") == []
        assert adapter.disabled is True
        assert adapter.reset_count == 0

    def test_flow_transport_survives_reset(self):
        adapter = _fresh_flaky_adapter()
        adapter.flow_transport = "quic"
        adapter.feed(b"BAD", "read")
        assert adapter.inner.flow_transport == "quic"
        assert adapter.flow_transport == "quic"


class TestSafeParserAdapterRealParserReset:
    """A fresh real parser must cope with joining a connection mid-stream."""

    def test_http1_resyncs_on_next_message(self):
        from friTap.parsers.http1 import Http1Parser

        class _FailOnce(Http1Parser):
            armed = True

            def feed(self, data, direction, stream_id=None):
                if type(self).armed:
                    type(self).armed = False
                    raise RuntimeError("transient")
                return super().feed(data, direction, stream_id)

        adapter = SafeParserAdapter(_FailOnce())
        adapter.feed(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", "write")
        results = adapter.feed(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n", "write")
        assert adapter.reset_count == 1
        assert any(r.method == "GET" and r.url == "/b" for r in results)

    def test_http2_attaches_mid_connection(self):
        from friTap.parsers.http2 import Http2Parser, _hpack_available
        if not _hpack_available:
            pytest.skip("hpack library not installed")
        from hpack import Encoder

        class _FailOnce(Http2Parser):
            armed = True

            def feed(self, data, direction, stream_id=None):
                if type(self).armed:
                    type(self).armed = False
                    raise RuntimeError("transient")
                return super().feed(data, direction, stream_id)

        block = Encoder().encode([(":method", "GET"), (":path", "/mid"),
                                  (":scheme", "https"), (":authority", "x")])
        headers = (struct.pack("!I", len(block))[1:] + bytes([0x01, 0x05])
                   + struct.pack("!I", 3) + block)
        adapter = SafeParserAdapter(_FailOnce())
        adapter.feed(b"lost chunk", "write")
        results = adapter.feed(headers, "write")  # no preface: mid-connection
        assert adapter.reset_count == 1
        assert adapter.disabled is False
        assert any(r.url == "/mid" for r in results)

    def test_websocket_reset_does_not_raise(self):
        from friTap.parsers.websocket import WebSocketParser

        class _FailOnce(WebSocketParser):
            armed = True

            def feed(self, data, direction, stream_id=None):
                if type(self).armed:
                    type(self).armed = False
                    raise RuntimeError("transient")
                return super().feed(data, direction, stream_id)

        adapter = SafeParserAdapter(_FailOnce())
        adapter.feed(b"\x81\x05hello", "read")
        # Mid-frame garbage after the reset must not raise or disable.
        adapter.feed(b"llo-world-tail", "read")
        results = adapter.feed(b"\x81\x02hi", "read")
        assert adapter.reset_count == 1
        assert adapter.disabled is False
        assert isinstance(results, list)


class TestSafeParserAdapterAttributePassthrough:
    def test_get_unknown_attr_falls_through(self):
        inner = _GoodParser()
        inner.upgrade_protocol = "websocket"
        adapter = SafeParserAdapter(inner)
        assert adapter.upgrade_protocol == "websocket"
        assert getattr(adapter, "trailing_data", None) == b""

    def test_set_unknown_attr_falls_through(self):
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        adapter.trailing_data = b"hello"
        assert inner.trailing_data == b"hello"

    def test_set_failed_does_not_leak_to_inner(self):
        # Triggering a failure must set adapter._failed without touching
        # any same-named attribute on the inner parser.
        broken_inner = _BrokenParser()
        adapter2 = SafeParserAdapter(broken_inner)
        adapter2.feed(b"x", "read")
        assert adapter2.failed is True
        assert not hasattr(broken_inner, "_failed")
        for own in ("_disabled", "_last_call_failed", "_reset_count"):
            assert not hasattr(adapter2.inner, own)


class TestUnwrapParser:
    def test_unwraps_adapter(self):
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        assert unwrap_parser(adapter) is inner

    def test_returns_raw_parser_unchanged(self):
        inner = _GoodParser()
        assert unwrap_parser(inner) is inner
