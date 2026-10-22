"""Tests for friTap.offline.tls_spans.capture_time_at."""

from __future__ import annotations

from friTap.offline.tls_spans import TlsPlaintextSpan, capture_time_at

_SPANS = [
    TlsPlaintextSpan(1, 100.0, "read", b"abc"),
    TlsPlaintextSpan(2, 200.0, "read", b"de"),
]


def test_time_is_the_span_holding_the_last_byte():
    assert capture_time_at(_SPANS, 3) == 100.0
    assert capture_time_at(_SPANS, 4) == 200.0
    assert capture_time_at(_SPANS, 5) == 200.0


def test_offset_past_the_bytes_clamps_to_the_last_span():
    assert capture_time_at(_SPANS, 99) == 200.0


def test_unknown_offset_or_no_spans_has_no_time():
    assert capture_time_at(_SPANS, -1) == 0.0
    assert capture_time_at(_SPANS, 0) == 0.0
    assert capture_time_at([], 3) == 0.0


def test_span_end_offsets_are_cumulative():
    from friTap.offline.tls_spans import span_end_offsets

    assert span_end_offsets(_SPANS) == [3, 5]
    assert span_end_offsets([]) == []


def test_capture_clock_matches_capture_time_at_including_boundaries():
    from friTap.offline.tls_spans import SpanCaptureClock

    spans = _SPANS + [TlsPlaintextSpan(3, 300.0, "read", b""),
                      TlsPlaintextSpan(4, 400.0, "read", b"f")]
    clock = SpanCaptureClock({"k": {"read": spans}})
    for offset in range(-1, 9):
        assert clock.capture_time_at("k", "read", offset) == capture_time_at(spans, offset)
    assert clock.capture_time_at("k", "write", 3) == 0.0
    assert clock.capture_time_at("missing", "read", 3) == 0.0


def test_capture_clock_sees_spans_appended_after_first_lookup():
    from friTap.offline.tls_spans import SpanCaptureClock

    spans = list(_SPANS)
    clock = SpanCaptureClock({"k": {"read": spans}})
    assert clock.capture_time_at("k", "read", 9) == 200.0
    spans.append(TlsPlaintextSpan(3, 300.0, "read", b"fgh"))
    assert clock.capture_time_at("k", "read", 6) == 300.0
