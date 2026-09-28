"""Frame/timestamp provenance for offline RC4 messages (TLS single-pass spans).

Covers the TLS span store (:mod:`friTap.offline.tls_spans`), the offset-aware
frame parser, the ``frame_offset``/``frame_header_len`` result keys, building
RC4 streams from spans, and the end-to-end provenance on DecryptedRc4Message.
Pure unit tests; tshark is never executed.
"""

from __future__ import annotations

from types import SimpleNamespace

import friTap.offline.pcap_to_tap as p2t
from friTap.connection_index import canonical_4tuple
from friTap.events import EventBus
from friTap.offline import tshark
from friTap.offline.rc4 import crypto
from friTap.offline.rc4 import decrypt as rc4d
from friTap.offline.rc4.transport import rc4_streams_from_spans
from friTap.offline.tls_spans import TlsPlaintextSpan, record_tls_span, spans_covering

KEY = b"fritap-rc4-demo-key"
CLIENT = ("10.0.0.1", 53646)
SERVER = ("10.0.0.2", 8443)
REQUEST = b"GET /hello rc4 request!!"
RESPONSE = b"HTTP/1.1 200 OK rc4 response body with some printable text...."


def _frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _span(frame_no, ts, direction, data, sender=CLIENT, receiver=SERVER):
    return TlsPlaintextSpan(frame_no, ts, direction, data,
                            sender[0], sender[1], receiver[0], receiver[1])


def _event(direction, data, ts, sender, receiver):
    return SimpleNamespace(direction=direction, data=data, timestamp=ts,
                           src_addr=sender[0], src_port=sender[1],
                           dst_addr=receiver[0], dst_port=receiver[1])


def _demo_store():
    """rc4demo layout: request prefix and ciphertext in separate frames (22, 26),
    the response prefix + ciphertext in one frame (28). Per-frame re-keyed RC4."""
    req_ct, resp_ct = crypto.rc4(KEY, REQUEST), crypto.rc4(KEY, RESPONSE)
    key = canonical_4tuple(*CLIENT, *SERVER)
    return {key: {
        "write": [_span(22, 1.5, "write", len(req_ct).to_bytes(4, "big")),
                  _span(26, 3.5, "write", req_ct)],
        "read": [_span(28, 3.6, "read", _frame(resp_ct), SERVER, CLIENT)],
    }}


# ------------------------------ tshark field -------------------------------- #

def test_tls_command_exports_frame_number():
    cmd = tshark.build_tls_command("x.pcap", "k.log")
    assert "frame.number" in cmd
    assert cmd[cmd.index("frame.number") - 1] == "-e"


# ------------------------------- span store --------------------------------- #

def test_record_tls_span_keys_by_canonical_4tuple_and_direction():
    store: dict = {}
    pkt = {"layers": {"frame_number": ["22"]}}
    record_tls_span(store, pkt, _event("write", b"\x00\x00\x00\x1a", 1.5, CLIENT, SERVER))
    record_tls_span(store, {"layers": {"frame_number": ["28"]}},
                    _event("read", b"xy", 3.6, SERVER, CLIENT))
    key = canonical_4tuple(*CLIENT, *SERVER)
    assert list(store) == [key]
    assert store[key]["write"][0].frame_no == 22
    assert store[key]["write"][0].ts == 1.5
    assert store[key]["read"][0].frame_no == 28


def test_record_tls_span_ignores_empty_data_and_missing_frame_number():
    store: dict = {}
    record_tls_span(store, {"layers": {}}, _event("write", b"", 1.0, CLIENT, SERVER))
    assert store == {}
    record_tls_span(store, {"layers": {}}, _event("write", b"a", 1.0, CLIENT, SERVER))
    assert next(iter(store.values()))["write"][0].frame_no == 0


def test_spans_covering_single_and_split_ranges():
    spans = [_span(1, 1.0, "write", b"aaaa"), _span(2, 2.0, "write", b"bbbbbb"),
             _span(3, 3.0, "write", b"cc")]
    assert [s.frame_no for s in spans_covering(spans, 0, 4)] == [1]
    assert [s.frame_no for s in spans_covering(spans, 5, 8)] == [2]
    # A message split over two spans.
    assert [s.frame_no for s in spans_covering(spans, 2, 6)] == [1, 2]
    assert [s.frame_no for s in spans_covering(spans, 0, 12)] == [1, 2, 3]
    assert spans_covering(spans, 3, 3) == []
    assert spans_covering(spans, 12, 20) == []


# --------------------------- offset-aware framing --------------------------- #

def test_parse_length_prefixed_frame_spans_offsets():
    blob = _frame(b"abc") + _frame(b"defgh")
    spans = rc4d.parse_length_prefixed_frame_spans(blob)
    assert [(s.offset, s.header_len, s.payload) for s in spans] == [
        (0, 4, b"abc"), (7, 4, b"defgh")]
    assert rc4d.parse_length_prefixed_frames(blob) == [b"abc", b"defgh"]


def test_parse_length_prefixed_frame_spans_rejects_unframed():
    assert rc4d.parse_length_prefixed_frame_spans(b"") is None
    assert rc4d.parse_length_prefixed_frame_spans(_frame(b"abc") + b"\x00") is None
    assert rc4d.parse_length_prefixed_frames(b"\x00\x00\x00\x09ab") is None


def test_decrypt_framed_reports_frame_offsets():
    first, second = crypto.rc4(KEY, REQUEST), crypto.rc4(KEY, RESPONSE)
    blob = _frame(first) + _frame(second)
    results = rc4d.decrypt_framed(blob, [("k", KEY)])
    assert [(r["frame_offset"], r["frame_header_len"]) for r in results] == [
        (0, 4), (4 + len(first), 4)]


def test_decrypt_framed_known_plaintext_reports_frame_offsets():
    first, second = crypto.rc4(KEY, REQUEST), crypto.rc4(KEY, RESPONSE)
    blob = _frame(first) + _frame(second)
    results = rc4d.decrypt_framed(blob, [("k", KEY)], known_plaintext=b"HTTP/1.1")
    assert [(r["frame_offset"], r["frame_header_len"]) for r in results] == [
        (0, 4), (4 + len(first), 4)]


# ------------------------------ span streams -------------------------------- #

def test_rc4_streams_from_spans_joins_directions_and_addressing():
    streams = list(rc4_streams_from_spans(_demo_store()))
    assert len(streams) == 1
    stream = streams[0]
    assert stream.client_addr == CLIENT and stream.server_addr == SERVER
    assert stream.ss_family == "AF_INET"
    assert stream.directions["write"] == _frame(crypto.rc4(KEY, REQUEST))
    assert [s.frame_no for s in stream.spans["write"]] == [22, 26]


def test_rc4_streams_from_spans_read_only_connection():
    store = {"k": {"read": [_span(5, 1.0, "read", b"zz", SERVER, CLIENT)]}}
    stream = next(rc4_streams_from_spans(store))
    assert stream.client_addr == CLIENT and stream.server_addr == SERVER
    assert list(stream.directions) == ["read"]


# ---------------------------- end-to-end provenance ------------------------- #

def _messages(store):
    cands = rc4d.materialize_candidates([("keylog", KEY)])
    msgs = rc4d.iter_decrypted_messages(
        "unused.pcap", cands, streams=rc4_streams_from_spans(store))
    return {m.direction: m for m in msgs}


def test_iter_decrypted_messages_fills_provenance_from_spans():
    msgs = _messages(_demo_store())
    req, resp = msgs["write"], msgs["read"]
    assert req.message == REQUEST and resp.message == RESPONSE
    assert req.nested is True
    assert req.tls_frames == (22, 26) and req.timestamp == 3.5
    assert (req.cipher_offset, req.cipher_len, req.frame_header_len) == (
        4, len(REQUEST), 4)
    assert resp.tls_frames == (28,) and resp.timestamp == 3.6
    assert (resp.cipher_offset, resp.cipher_len) == (4, len(RESPONSE))


def test_continuous_stream_provenance_covers_whole_direction():
    ct = crypto.rc4(KEY, REQUEST + RESPONSE)  # one keystream, no length prefix
    cut = len(REQUEST)
    store = {"k": {"write": [_span(7, 1.0, "write", ct[:cut]),
                             _span(9, 2.0, "write", ct[cut:])]}}
    msg = _messages(store)["write"]
    assert msg.tls_frames == (7, 9) and msg.timestamp == 2.0
    assert (msg.cipher_offset, msg.cipher_len, msg.frame_header_len) == (
        0, len(ct), 0)


def test_streams_without_spans_keep_provenance_defaults():
    from friTap.offline.rc4.transport import Rc4Stream

    stream = Rc4Stream(CLIENT, SERVER, "AF_INET",
                       directions={"write": crypto.rc4(KEY, REQUEST)})
    cands = rc4d.materialize_candidates([("keylog", KEY)])
    msg = next(rc4d.iter_decrypted_messages("unused.pcap", cands, streams=[stream]))
    assert (msg.timestamp, msg.tls_frames, msg.cipher_len) == (0.0, (), 0)


# ------------------------ single-pass span recording ------------------------ #

class _NullWriter:
    def open(self, *a, **k):
        pass

    def write_keylog(self, line):
        pass

    def update_capture_start(self, ts):
        pass


def test_tls_singlepass_records_spans(monkeypatch):
    def pkt(frame, ts, sender, receiver, hexdata):
        return {"layers": {
            "frame_number": [str(frame)], "frame_time_epoch": [str(ts)],
            "ip_src": [sender[0]], "ip_dst": [receiver[0]], "tcp_stream": ["0"],
            "tcp_srcport": [str(sender[1])], "tcp_dstport": [str(receiver[1])],
            "data_data": [hexdata]}}

    packets = [pkt(22, 1.5, CLIENT, SERVER, "0000001a"),
               pkt(28, 3.6, SERVER, CLIENT, "00000001ff")]
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(packets))
    state = p2t._WriterState(_NullWriter(), "unused.tap", "t", None)
    p2t._emit_tls_streams_singlepass(
        "tshark", "x.pcap", None, tls_ports=(8443,), extra_decode_as=(),
        heuristic=False, bus=EventBus(), state=state,
        result=p2t.ConvertResult(tap_path="unused.tap"),
        tracker=p2t._StreamDirectionTracker(server_ports=(8443,)))
    conn = state.tls_spans[canonical_4tuple(*CLIENT, *SERVER)]
    assert [(s.frame_no, s.ts, s.data) for s in conn["write"]] == [
        (22, 1.5, b"\x00\x00\x00\x1a")]
    assert [s.frame_no for s in conn["read"]] == [28]
    assert state.rc4_provenance == {}
