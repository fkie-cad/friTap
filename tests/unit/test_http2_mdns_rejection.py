"""Http2Parser.can_parse must not claim plaintext mDNS/DNS-over-UDP packets.

A DNS/mDNS message begins with a 2-byte transaction id (often 0) followed by
flags; a response's `00 00 84 00 ...` decodes, under HTTP/2 framing, as a
zero-length DATA frame (type 0x0) on stream 0. DATA on stream 0 is a protocol
error (RFC 7540 Sec 6.1), so it is never valid HTTP/2 and must be rejected —
otherwise mDNS on UDP is mislabelled HTTP/2 in the offline/TUI view.
"""
from friTap.parsers.http2 import Http2Parser


def _mk(prefix: bytes) -> bytes:
    # Pad to at least a full 9-byte frame header so can_parse inspects it.
    return prefix + b"\x00" * (16 - len(prefix))


def test_can_parse_rejects_mdns_response():
    parser = Http2Parser()
    # mDNS response: id=0x0000, flags=0x8400 (QR=1, AA=1) → DATA(0) frame, stream 0.
    assert parser.can_parse(_mk(b"\x00\x00\x84\x00\x00\x00\x00\x00")) is False


def test_can_parse_rejects_mdns_query():
    parser = Http2Parser()
    # mDNS query: id=0x0000, flags=0x0000 → DATA(0) frame.
    assert parser.can_parse(_mk(b"\x00\x00\x00\x00\x00\x00\x00\x00")) is False


def test_can_parse_accepts_real_http2_settings_frame():
    parser = Http2Parser()
    # A preface-less HTTP/2 connection frame: empty SETTINGS (type 0x04) on
    # stream 0 — length 0, type 0x04, flags 0, stream id 0.
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    assert parser.can_parse(settings) is True


def test_can_parse_accepts_http2_with_preface():
    parser = Http2Parser()
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    assert parser.can_parse(preface + settings) is True
