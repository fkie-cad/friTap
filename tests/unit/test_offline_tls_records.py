"""Unit tests for the ServerHello / handshake helpers in offline.tls.records."""
from __future__ import annotations

from friTap.offline.tls import records as rec


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _server_hello_body(random: bytes, suite: int, *, legacy=0x0303,
                       selected_version=None) -> bytes:
    exts = b""
    if selected_version is not None:
        ext_body = selected_version.to_bytes(2, "big")
        exts = (rec.EXT_SUPPORTED_VERSIONS.to_bytes(2, "big")
                + len(ext_body).to_bytes(2, "big") + ext_body)
    return (legacy.to_bytes(2, "big") + random + b"\x00"       # empty session id
            + suite.to_bytes(2, "big") + b"\x00"               # compression
            + len(exts).to_bytes(2, "big") + exts)


def test_iter_handshake_messages_splits_and_stops_on_overrun():
    msgs = _handshake(8, b"ab") + _handshake(20, b"cdef")
    assert rec.iter_handshake_messages(msgs) == [(8, b"ab"), (20, b"cdef")]
    # A declared length past the end is dropped, not raised.
    truncated = _handshake(2, b"xyz")[:-1]
    assert rec.iter_handshake_messages(truncated) == []


def test_server_hello_tls13_selected_version():
    rnd = bytes(range(32))
    frag = _handshake(2, _server_hello_body(rnd, 0x1301, selected_version=0x0304))
    info = rec.server_hello_info(frag)
    assert info is not None
    assert info.random == rnd
    assert info.cipher_suite == 0x1301
    assert info.legacy_version == 0x0303
    assert info.selected_version == 0x0304
    assert info.version == 0x0304        # selected wins over legacy
    assert not info.is_hrr


def test_server_hello_tls12_no_supported_versions():
    frag = _handshake(2, _server_hello_body(bytes(32), 0xC02F))
    info = rec.server_hello_info(frag)
    assert info.selected_version is None
    assert info.version == 0x0303        # falls back to legacy_version


def test_server_hello_coalesced_with_certificate():
    # TLS 1.2 coalesces ServerHello + Certificate in one record; the length field
    # must bound the parse so the trailing message does not corrupt it.
    sh = _handshake(2, _server_hello_body(bytes(32), 0xC030))
    cert = _handshake(11, b"\x00" * 20)
    info = rec.server_hello_info(sh + cert)
    assert info is not None
    assert info.cipher_suite == 0xC030


def test_hello_retry_request_flagged():
    frag = _handshake(2, _server_hello_body(rec.HRR_RANDOM, 0x1301,
                                            selected_version=0x0304))
    info = rec.server_hello_info(frag)
    assert info.is_hrr


def test_server_hello_info_rejects_non_serverhello():
    assert rec.server_hello_info(_handshake(1, bytes(40))) is None
    assert rec.server_hello_info(b"") is None


def test_record_content_type_constants():
    from friTap.offline.tls import records as rec
    from friTap.offline.tls import tls12
    assert (rec.CT_CHANGE_CIPHER_SPEC, rec.CT_ALERT, rec.CT_HANDSHAKE,
            rec.CT_APPLICATION_DATA) == (0x14, 0x15, 0x16, 0x17)
    assert (tls12.CHANGE_CIPHER_SPEC, tls12.HANDSHAKE) == (0x14, 0x16)
