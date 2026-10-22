"""4-tuple reuse: span capture-time lookups scoped to ONE tshark TLS stream.

Two TCP sessions on the same 4-tuple share one span-store entry, but a per-stream
offset lookup measures ``end_offset`` inside ONE ``follow,tls,raw,<stream>`` buffer
(starting at 0). The lookup must therefore read only that stream's spans.

Signal-E2E message timing that exercises this via ``DecryptedMessage`` lives in the
private ``test_signal_tls_span_timing.py`` so this file stays protocol-agnostic.
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.connection_index import canonical_4tuple
from friTap.offline.tls_spans import SpanCaptureClock, TlsPlaintextSpan, record_tls_span

CLIENT = ("10.0.0.2", 50000)
SERVER = ("1.2.3.4", 443)
KEY = canonical_4tuple(*CLIENT, *SERVER)


def _event(data: bytes, ts: float):
    return SimpleNamespace(data=data, timestamp=ts, direction="read",
                           src_addr=SERVER[0], src_port=SERVER[1],
                           dst_addr=CLIENT[0], dst_port=CLIENT[1])


def _reused_store() -> dict:
    """Session A (tls.stream 0, t=100/110) then session B (tls.stream 1, t=500/510)."""
    store: dict = {}
    for stream, base in ((0, 100.0), (1, 500.0)):
        for i in range(2):
            pkt = {"layers": {"frame_number": [str(int(base) + i)],
                              "tls_stream": [str(stream)]}}
            record_tls_span(store, pkt, _event(b"x" * 10, base + 10 * i))
    return store


def test_record_tls_span_keeps_the_packets_tls_stream():
    spans = _reused_store()[KEY]["read"]
    assert [s.stream for s in spans] == [0, 0, 1, 1]


def test_record_tls_span_without_tls_stream_records_none():
    store: dict = {}
    record_tls_span(store, {"layers": {}}, _event(b"a", 1.0))
    assert store[KEY]["read"][0].stream is None


def test_stream_scoped_lookup_reads_only_that_streams_spans():
    clock = SpanCaptureClock(_reused_store())
    # Offset 15 inside stream 1's own buffer = its 2nd span (t=510), not
    # stream 0's 2nd span (t=110).
    assert clock.capture_time_at(KEY, "read", 15, stream=1) == 510.0
    assert clock.capture_time_at(KEY, "read", 5, stream=1) == 500.0
    assert clock.capture_time_at(KEY, "read", 15, stream=0) == 110.0
    assert clock.capture_time_at(KEY, "read", 5, stream=7) == 0.0


def test_unscoped_lookup_keeps_the_joined_4tuple_view():
    clock = SpanCaptureClock(_reused_store())
    assert clock.capture_time_at(KEY, "read", 15) == 110.0
    assert clock.capture_time_at(KEY, "read", 25) == 500.0


def test_stream_scoped_lookup_falls_back_when_spans_carry_no_stream():
    spans = [TlsPlaintextSpan(1, 100.0, "read", b"abc"),
             TlsPlaintextSpan(2, 200.0, "read", b"de")]
    clock = SpanCaptureClock({"k": {"read": spans}})
    assert clock.capture_time_at("k", "read", 4, stream=3) == 200.0
