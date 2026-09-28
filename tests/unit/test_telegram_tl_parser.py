"""Transport-pinned Telegram TL parsers (Secret Chat + cloud MTProto).

A decrypted ``decryptedMessageLayer`` starts ``89 17`` which blind byte
sniffing reads as a WebSocket FIN|PING frame. These tests pin the fix: the
``telegram_e2e`` / ``mtproto`` transports select a dedicated TL parser, the
reparse path re-labels old mis-parsed flows and drops their bogus trailing
segments, and the replay controller keeps that across cache eviction.
"""

from __future__ import annotations

import struct

import pytest

from friTap.flow.models import Flow, FlowChunk
from friTap.flow.reparse import detect_protocol_from_bytes, reparse_flow
from friTap.flow.replay import ReplayController
from friTap.offline.mtproto.content import (
    SecretChatFields,
    decode_secret_chat_fields,
    parse_secret_chat_message,
)
from friTap.parsers.base import ParseResult
from friTap.parsers.registry import ParserRegistry, get_default_registry
from friTap.parsers.telegram_tl import MtprotoParser, TelegramE2EParser
from friTap.parsers.websocket import WebSocketParser
from tests.unit._tl_helpers import tl_str, u32

# decryptedMessageLayer{random_bytes(15), layer=151, in_seq_no=20, out_seq_no=57,
#   decryptedMessage#91cc4674{flags=0, random_id, ttl=0, message="Hi infected"}}
_BLOB = bytes.fromhex(
    "89 17 e3 1b 0f c1 a2 e4 f9 1e 39 17 8d 09 05 d8"
    "cb 63 91 22 97 00 00 00 14 00 00 00 39 00 00 00"
    "74 46 cc 91 00 00 00 00 36 f2 16 00 8c 20 5e fc"
    "00 00 00 00 0b 48 69 20 69 6e 66 65 63 74 65 64"
)
_BLOB_RANDOM_ID = struct.unpack("<q", bytes.fromhex("36f216008c205efc"))[0]


def _layer(inner: bytes, layer: int = 151, in_seq: int = 1, out_seq: int = 2) -> bytes:
    return (u32(0x1BE31789) + tl_str("r" * 15)
            + struct.pack("<iii", layer, in_seq, out_seq) + inner)


def _text_message(text: str, random_id: int = 42) -> bytes:
    return (u32(0x91CC4674) + u32(0) + struct.pack("<q", random_id)
            + struct.pack("<i", 0) + tl_str(text))


def _service_message(action_ctor: int, random_id: int = 7) -> bytes:
    return u32(0x73164160) + struct.pack("<q", random_id) + u32(action_ctor)


# --------------------------------------------------------------------------- #
# decode_secret_chat_fields
# --------------------------------------------------------------------------- #

def test_blob_fixture_is_the_documented_64_bytes():
    assert len(_BLOB) == 64
    assert _BLOB[:4] == bytes.fromhex("8917e31b")


def test_decode_fields_of_real_blob():
    fields = decode_secret_chat_fields(_BLOB)
    assert isinstance(fields, SecretChatFields)
    assert fields.ctor_name == "decryptedMessage"
    assert fields.ctor == 0x91CC4674
    assert (fields.layer, fields.in_seq_no, fields.out_seq_no) == (151, 20, 57)
    assert fields.random_bytes_len == 15
    assert fields.flags == 0
    assert fields.random_id == _BLOB_RANDOM_ID
    assert fields.ttl == 0
    assert fields.message == "Hi infected"
    assert fields.has_media is False
    assert fields.has_layer_envelope is True


def test_decode_fields_of_bare_decrypted_message():
    fields = decode_secret_chat_fields(_text_message("bare", random_id=-5))
    assert fields.message == "bare"
    assert fields.random_id == -5
    assert fields.has_layer_envelope is False
    assert fields.layer == 0


def test_decode_fields_of_service_message():
    fields = decode_secret_chat_fields(_layer(_service_message(0xCCB27641, 99)))
    assert fields.ctor_name == "decryptedMessageService"
    assert fields.action == "decryptedMessageActionTyping"
    assert fields.random_id == 99


def test_decode_fields_of_layer8_service_message():
    blob = (u32(0xAA48327D) + struct.pack("<q", 3) + tl_str("rb")
            + u32(0x6719E45C))
    fields = decode_secret_chat_fields(blob)
    assert fields.ctor_name == "decryptedMessageService"
    assert fields.action == "decryptedMessageActionFlushHistory"


def test_decode_fields_of_unknown_action_falls_back_to_hex():
    fields = decode_secret_chat_fields(_service_message(0x12345678))
    assert fields.action == "0x12345678"


def test_decode_fields_of_flagged_media():
    inner = (u32(0x91CC4674) + u32(1 << 9) + struct.pack("<q", 1)
             + struct.pack("<i", 0) + tl_str("pic") + u32(0xDEADBEEF))
    fields = decode_secret_chat_fields(_layer(inner))
    assert fields.has_media is True
    assert fields.media_ctor == "0xdeadbeef"


@pytest.mark.parametrize("blob", [
    b"", b"\x89", _BLOB[:30], b"\x00" * 64, u32(0x1BE31789) + b"\xff" * 3,
    _layer(u32(0x11111111)),
])
def test_decode_fields_never_raises(blob):
    assert decode_secret_chat_fields(blob) is None


def test_parse_secret_chat_message_emits_service_item():
    [msg] = parse_secret_chat_message(_layer(_service_message(0xA1733AEC, 11)))
    assert msg.kind == "service"
    assert msg.method == "decryptedMessageService"
    assert msg.body == "decryptedMessageActionSetMessageTTL"
    assert msg.random_id == 11


def test_parse_secret_chat_message_real_blob_unchanged():
    [msg] = parse_secret_chat_message(_BLOB)
    assert (msg.kind, msg.body, msg.method) == ("text", "Hi infected", "decryptedMessage")
    assert msg.random_id == _BLOB_RANDOM_ID


# --------------------------------------------------------------------------- #
# TelegramE2EParser
# --------------------------------------------------------------------------- #

def test_e2e_parser_decodes_real_blob():
    [result] = TelegramE2EParser().feed(_BLOB, "write")
    assert result.protocol == "Telegram-E2E"
    assert result.method == "decryptedMessage"
    assert result.body == b"Hi infected"
    assert result.body_size == len(b"Hi infected")
    assert result.content_type == "text/plain; charset=utf-8"
    assert result.raw == _BLOB
    assert result.is_request is True
    assert result.is_complete is True
    assert result.error == ""
    headers = result.headers
    assert headers["layer"] == "151"
    assert headers["in_seq_no"] == "20"
    assert headers["out_seq_no"] == "57"
    assert headers["random_id"] == str(_BLOB_RANDOM_ID)
    assert headers["ttl"] == "0"
    assert headers["random_bytes_len"] == "15"
    assert headers["constructor"].startswith("decryptedMessage")
    assert all(isinstance(v, str) for v in headers.values())


def test_e2e_parser_read_direction_is_response():
    [result] = TelegramE2EParser().feed(_BLOB, "read")
    assert result.is_request is False


def test_e2e_parser_service_message():
    [result] = TelegramE2EParser().feed(_layer(_service_message(0xC4F40BE)), "read")
    assert result.method == "decryptedMessageService"
    assert result.headers["action"] == "decryptedMessageActionReadMessages"
    assert result.body == b"decryptedMessageActionReadMessages"


@pytest.mark.parametrize("garbage, method", [
    (b"\xde\xad\xbe\xef" + b"\x00" * 8, "0xefbeadde"),
    (b"\x01\x02", "unknown"),
    (b"", "unknown"),
])
def test_e2e_parser_garbage_yields_error_result(garbage, method):
    [result] = TelegramE2EParser().feed(garbage, "write")
    assert result.protocol == "Telegram-E2E"
    assert result.method == method
    assert result.body == garbage
    assert result.error


def test_e2e_parser_never_blind_detects_and_does_not_buffer():
    parser = TelegramE2EParser()
    assert parser.can_parse(_BLOB) is False
    parser.feed(_BLOB[:10], "write")
    [result] = parser.feed(_BLOB, "write")
    assert result.body == b"Hi infected"
    assert parser.flush() == []
    assert not hasattr(parser, "trailing_data")


# --------------------------------------------------------------------------- #
# MtprotoParser
# --------------------------------------------------------------------------- #

def test_mtproto_parser_names_ctor_and_counts_messages():
    pong = u32(0x347773C5) + struct.pack("<qq", 1, 2)
    [result] = MtprotoParser().feed(pong, "read")
    assert result.protocol == "MTProto"
    assert result.method == "pong"
    assert result.headers == {"constructor": "pong#347773c5", "messages": "1"}
    assert result.body == pong and result.raw == pong
    assert result.is_request is False


def test_mtproto_parser_unknown_payload_uses_hex_ctor():
    [result] = MtprotoParser().feed(b"\x78\x56\x34\x12rest", "write")
    assert result.method == "0x12345678"
    assert result.headers["messages"] == "0"
    assert MtprotoParser().can_parse(b"\x78\x56\x34\x12") is False
    assert MtprotoParser().flush() == []


def test_mtproto_parser_labels_constructor_from_schema():
    data = u32(0xF3427B8C) + struct.pack("<qi", 7, 75)
    [result] = MtprotoParser().feed(data, "write")
    assert result.headers["constructor"] == "ping_delay_disconnect#f3427b8c"
    assert result.method == "ping_delay_disconnect"
    assert result.headers["messages"] == "0"


def test_mtproto_parser_schema_names_rpc_function_call():
    # account.getPrivacy#dadbc950 key:InputPrivacyKey (inputPrivacyKeyStatusTimestamp#4f96cb18)
    data = u32(0xDADBC950) + u32(0x4F96CB18)
    [result] = MtprotoParser().feed(data, "write")
    assert result.method == "account.getPrivacy"
    assert result.headers["constructor"] == "account.getPrivacy#dadbc950"


def test_mtproto_parser_names_generic_rpc_result_by_its_result():
    # rpc_result wrapping updates.differenceEmpty#5d75a138 date:int seq:int
    data = u32(0xF35C6D01) + struct.pack("<q", 9) + u32(0x5D75A138) + struct.pack("<ii", 1, 2)
    [result] = MtprotoParser().feed(data, "read")
    assert result.headers["constructor"] == "rpc_result#f35c6d01"
    assert result.method == "updates.differenceEmpty"


def test_mtproto_parser_short_payload():
    [result] = MtprotoParser().feed(b"\x01", "write")
    assert result.method == "unknown"


# --------------------------------------------------------------------------- #
# Registry pinning
# --------------------------------------------------------------------------- #

def test_blind_detect_on_blob_is_no_longer_websocket():
    """The original mislabel (``89 17`` read as a WS PING) is fixed at detection.

    Phase 7c: a leading control frame must span the buffer or be followed by a
    valid non-CONTINUATION frame; the blob's PING is followed by ``00 00``.
    Transport pinning still wins regardless (next test).
    """
    assert not isinstance(get_default_registry().detect(_BLOB), WebSocketParser)


def test_pinned_transport_wins_over_blind_detect():
    registry = get_default_registry()
    assert isinstance(registry.detect(_BLOB, transport="telegram_e2e"), TelegramE2EParser)
    assert isinstance(registry.detect(_BLOB, transport="mtproto"), MtprotoParser)
    assert not isinstance(registry.detect(_BLOB, transport="tls"), WebSocketParser)


def test_pin_transport_on_fresh_registry():
    registry = ParserRegistry()
    assert registry.pinned_parser_for("telegram_e2e") is None
    registry.pin_transport("telegram_e2e", TelegramE2EParser)
    assert registry.pinned_parser_for("telegram_e2e") is TelegramE2EParser
    assert registry.pinned_parser_for(None) is None
    parser = registry.detect(b"", transport="telegram_e2e")
    assert isinstance(parser, TelegramE2EParser)


def test_detect_protocol_from_bytes_uses_transport():
    assert detect_protocol_from_bytes(_BLOB) != "WebSocket"  # Phase 7c detection fix
    assert detect_protocol_from_bytes(_BLOB, transport="telegram_e2e") == "Telegram-E2E"


# --------------------------------------------------------------------------- #
# reparse_flow on an old, mis-parsed flow
# --------------------------------------------------------------------------- #

def _old_style_flow() -> Flow:
    flow = Flow(flow_id="f1", transport="telegram_e2e")
    flow.chunks.append(FlowChunk(data=_BLOB, direction="write", timestamp=1.0))
    flow.chunks.append(FlowChunk(
        data=_layer(_text_message("hello folks")), direction="read", timestamp=2.0))
    flow.request = ParseResult(protocol="WebSocket", method="PING", is_request=True)
    flow.trailing_bytes = b"\x01\x02\x03"
    flow.trailing_protocol = "unknown"
    flow.trailing_parse = ParseResult(protocol="unknown")
    return flow


def test_reparse_flow_fixes_old_websocket_labelled_flow():
    flow = _old_style_flow()
    assert reparse_flow(flow) is True
    assert flow.request.protocol == "Telegram-E2E"
    assert flow.request.body == b"Hi infected"
    assert flow.request.is_request is True
    assert flow.response.protocol == "Telegram-E2E"
    assert flow.response.body == b"hello folks"
    assert flow.response.is_request is False
    assert flow.trailing_bytes is None
    assert flow.trailing_protocol == ""
    assert flow.trailing_parse is None
    assert [s["source"] for s in flow.segments] == ["primary"]


def test_reparse_flow_pinned_single_direction():
    flow = Flow(flow_id="f2", transport="telegram_e2e")
    flow.chunks.append(FlowChunk(data=_BLOB, direction="read", timestamp=1.0))
    assert reparse_flow(flow) is True
    assert flow.request is None
    assert flow.response.body == b"Hi infected"


# --------------------------------------------------------------------------- #
# ReplayController.store_reparse(clear_trailing=...)
# --------------------------------------------------------------------------- #

class _FakeReader:
    """Re-reads a fresh (stale, trailing-bearing) flow from 'disk' every time."""

    def read_flow(self, flow_id):
        return _old_style_flow()

    def close(self):
        pass


def _controller() -> ReplayController:
    ctrl = ReplayController("unused.tap")
    ctrl._reader = _FakeReader()
    return ctrl


def test_store_reparse_clear_trailing_survives_cache_eviction():
    ctrl = _controller()
    fixed = _old_style_flow()
    reparse_flow(fixed)
    ctrl.store_reparse("f1", fixed.request, fixed.response, clear_trailing=True)
    ctrl._flow_cache.clear()  # simulate LRU eviction -> re-read from disk
    flow = ctrl.get_flow("f1")
    assert flow.request.body == b"Hi infected"
    assert flow.trailing_bytes is None
    assert flow.trailing_parse is None


def test_store_reparse_default_keeps_trailing():
    ctrl = _controller()
    ctrl.store_reparse("f1", ParseResult(protocol="X"), None)
    flow = ctrl.get_flow("f1")
    assert flow.request.protocol == "X"
    assert flow.trailing_bytes == b"\x01\x02\x03"


# --------------------------------------------------------------------------- #
# MainScreen._needs_reparse
# --------------------------------------------------------------------------- #

class _Summary:
    method = ""


def _needs_reparse():
    pytest.importorskip("textual")
    from friTap.tui.screens import main_screen
    return main_screen._needs_reparse


@pytest.mark.parametrize("transport, req_proto, resp_proto, expected", [
    ("telegram_e2e", "WebSocket", None, True),
    ("telegram_e2e", None, None, True),
    ("telegram_e2e", "Telegram-E2E", "Telegram-E2E", False),
    ("telegram_e2e", "Telegram-E2E", "unknown", True),
    ("mtproto", "HTTP/3", None, True),
    ("mtproto", "MTProto", None, False),
    ("tls", "HTTP/1.x", None, False),
])
def test_needs_reparse_truth_table(transport, req_proto, resp_proto, expected):
    needs_reparse = _needs_reparse()
    flow = Flow(flow_id="x", transport=transport)
    if req_proto is not None:
        flow.request = ParseResult(protocol=req_proto, method="GET", is_request=True)
    if resp_proto is not None:
        flow.response = ParseResult(protocol=resp_proto, is_request=False)
    assert needs_reparse(flow, _Summary()) is expected


# --------------------------------------------------------------------------- #
# Name-only rpc_result lookup == the full-decode answer it replaced
# --------------------------------------------------------------------------- #

def _reference_rpc_result_name(data: bytes):
    """The original implementation: full decode, read the result node's name."""
    from friTap.offline.mtproto.tl import TlNode, decode_tl

    result = decode_tl(bytes(data)).value("result")
    if isinstance(result, TlNode) and result.kind == "gzip":
        result = result.value("packed_data")
    if isinstance(result, TlNode) and result.kind in ("constructor", "function"):
        return result.name
    return None


def _tl_bytes(raw: bytes) -> bytes:
    head = bytes([len(raw)]) if len(raw) < 254 else b"\xfe" + len(raw).to_bytes(3, "little")
    body = head + raw
    return body + b"\x00" * (-len(body) % 4)


def _gzip_packed(inner: bytes) -> bytes:
    import gzip

    return u32(0x3072CFA1) + _tl_bytes(gzip.compress(inner))


def _rpc(result: bytes) -> bytes:
    return u32(0xF35C6D01) + struct.pack("<q", 0x5F0000000000001C) + result


_PONG = u32(0x347773C5) + struct.pack("<qq", 1, 2)
_RPC_NAME_CASES = [
    _rpc(u32(0x997275B5)),                                   # boolTrue
    _rpc(_PONG),                                              # pong
    _rpc(_PONG[:8]),                                          # truncated body -> still named
    _rpc(_gzip_packed(_PONG)),                                # gzip -> pong
    _rpc(_gzip_packed(_gzip_packed(_PONG))),                  # nested gzip -> unnamed
    _rpc(_gzip_packed(b"\x01\x02")),                          # inflated too short
    _rpc(u32(0x3072CFA1) + _tl_bytes(b"not gzip at all")),   # corrupt gzip
    _rpc(u32(0x3072CFA1) + b"\x10abc"),                      # truncated packed bytes
    _rpc(u32(0x1CB5C415) + u32(0)),                         # vector -> unnamed
    _rpc(u32(0x73F1F8DC) + u32(0)),                         # msg_container
    _rpc(_rpc(_PONG)),                                        # nested rpc_result
    _rpc(u32(0x12345678)),                                   # unknown ctor
    _rpc(b"\x01"),                                            # truncated ctor
    u32(0xF35C6D01) + b"\x00" * 4,                           # truncated req_msg_id
    _PONG,                                                    # not an rpc_result
    b"",
]


@pytest.mark.parametrize("data", _RPC_NAME_CASES)
def test_rpc_result_name_matches_full_decode(data):
    from friTap.parsers.telegram_tl import _rpc_result_name

    assert _rpc_result_name(data) == _reference_rpc_result_name(data)
    assert _rpc_result_name(bytearray(data)) == _reference_rpc_result_name(data)
