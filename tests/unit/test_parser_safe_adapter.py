"""Unit tests for SafeParserAdapter (friTap.parsers.base)."""

import logging

import pytest

from friTap.parsers.base import (
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
        failures = []
        adapter = SafeParserAdapter(_BrokenParser(), on_failure=failures.append)
        adapter.feed(b"x", "read")
        adapter.feed(b"y", "read")
        adapter.feed(b"z", "write")
        assert len(failures) == 1, "callback should fire once per adapter"

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
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        # Triggering a failure must set adapter._failed without touching
        # any same-named attribute on the inner parser.
        broken_inner = _BrokenParser()
        adapter2 = SafeParserAdapter(broken_inner)
        adapter2.feed(b"x", "read")
        assert adapter2.failed is True
        assert not hasattr(broken_inner, "_failed")


class TestUnwrapParser:
    def test_unwraps_adapter(self):
        inner = _GoodParser()
        adapter = SafeParserAdapter(inner)
        assert unwrap_parser(adapter) is inner

    def test_returns_raw_parser_unchanged(self):
        inner = _GoodParser()
        assert unwrap_parser(inner) is inner
