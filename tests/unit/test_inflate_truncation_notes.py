"""A truncated gzip/zlib stream keeps its partial output AND says so.

``inflate_bounded`` used to return the partial output of a truncated stream
with no signal. :func:`inflate_bounded_checked` reports ``(data, complete)``
and its callers (MTProto ``gzip_packed`` in the hand parser and the schema
decoder, compressed gRPC messages) attach a note when ``complete`` is False.
Complete streams must produce exactly the output they always did.
"""

from __future__ import annotations

import gzip
import zlib

import pytest

from friTap.offline.mtproto.content import ParsedMtprotoMessage, parse_mtproto_message
from friTap.offline.mtproto.offline_decryptor import _parsed_mtproto_to_dicts
from friTap.offline.mtproto.tl.decoder import GZIP_TRUNCATED_NOTE, decode_tl
from friTap.offline.mtproto.tl.nodes import iter_nodes
from friTap.parsers.decompress import (
    InflateLimitError,
    inflate_bounded,
    inflate_bounded_checked,
)
from friTap.parsers.protobuf.grpc import (
    GRPC_INFLATE_TRUNCATED_NOTE_FMT,
    InflateBudget,
    decompress_grpc_payload,
)
from friTap.parsers.protobuf.view import decode_protobuf_view
from tests.unit._tl_helpers import (
    GZIP_PACKED,
    VECTOR,
    gzip_packed,
    i32,
    i64,
    rpc_result,
    synthetic_user,
    tl_bytes,
    tl_str,
    u32,
)
from tests.unit.test_tl_users import contact_user

_GZIP_TRAILER = 8  # CRC32 + ISIZE: cutting it leaves the deflate data whole
_UPDATE_SHORT_MESSAGE = 0x313BC7F8
_USERS = u32(VECTOR) + i32(2) + synthetic_user() + contact_user()


def _truncated_gzip_packed(inner: bytes, cut: int = _GZIP_TRAILER) -> bytes:
    """A ``gzip_packed`` whose gzip member lost its last *cut* bytes."""
    return u32(GZIP_PACKED) + tl_bytes(gzip.compress(inner)[:-cut])


def _short_message(text: str) -> bytes:
    return (u32(_UPDATE_SHORT_MESSAGE) + u32(0) + i32(7) + i64(4242)
            + tl_str(text) + i32(1) + i32(1) + i32(1700000000))


def _fields(messages):
    """Comparable view of parsed messages (every dataclass field)."""
    return [vars(m) for m in messages]


# --------------------------------------------------------------------------- #
# decompress.inflate_bounded_checked
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress])
def test_checked_complete_stream_is_complete(compress):
    data = b"payload " * 64
    assert inflate_bounded_checked(compress(data)) == (data, True)


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress])
def test_checked_truncated_stream_keeps_partial_output(compress):
    data = bytes(range(256)) * 64
    packed = compress(data)
    partial, complete = inflate_bounded_checked(packed[: len(packed) // 2])
    assert complete is False
    assert partial and data.startswith(partial)
    # Same bytes the legacy (silent) default returns.
    assert partial == inflate_bounded(packed[: len(packed) // 2])


def test_checked_raises_like_inflate_bounded():
    with pytest.raises(zlib.error):
        inflate_bounded_checked(b"\x1f\x8b\x08garbage")
    with pytest.raises(InflateLimitError):
        inflate_bounded_checked(gzip.compress(b"A" * 1000), 999)


def test_inflate_bounded_require_eof_still_raises_on_truncation():
    packed = gzip.compress(b"data" * 50)
    with pytest.raises(zlib.error):
        inflate_bounded(packed[:-_GZIP_TRAILER], require_eof=True)


# --------------------------------------------------------------------------- #
# MTProto hand parser (content.py)
# --------------------------------------------------------------------------- #

def test_content_truncated_gzip_packed_keeps_users_with_a_note():
    msgs = parse_mtproto_message(rpc_result(100, _truncated_gzip_packed(_USERS)))
    users = [m for m in msgs if m.kind == "user"]
    assert len(users) == 2
    assert all(m.note == GZIP_TRUNCATED_NOTE for m in users)


def test_content_complete_gzip_packed_is_unchanged():
    complete = parse_mtproto_message(rpc_result(100, gzip_packed(_USERS)))
    assert complete and all(m.note == "" for m in complete)
    # Byte-identical to the uncompressed result (gzip is transparent).
    assert _fields(complete) == _fields(parse_mtproto_message(rpc_result(100, _USERS)))


def test_content_truncated_result_with_nothing_decoded_marks_the_rpc_marker():
    # Cut so deep that the inflated prefix holds no decodable object.
    payload = rpc_result(100, _truncated_gzip_packed(b"\x00" * 64 + _USERS, cut=60))
    msgs = parse_mtproto_message(payload)
    markers = [m for m in msgs if m.kind == "rpc"]
    assert markers and markers[0].note == GZIP_TRUNCATED_NOTE


def test_content_schema_text_from_truncated_gzip_carries_the_note():
    msgs = parse_mtproto_message(_truncated_gzip_packed(_short_message("partial hi")))
    texts = [m for m in msgs if m.kind == "text"]
    assert [m.body for m in texts] == ["partial hi"]
    assert texts[0].note == GZIP_TRUNCATED_NOTE


def test_content_schema_text_from_complete_gzip_has_no_note():
    msgs = parse_mtproto_message(gzip_packed(_short_message("full hi")))
    assert [m.note for m in msgs if m.kind == "text"] == [""]


def test_offline_dicts_carry_note_only_when_set():
    plain, noted = _parsed_mtproto_to_dicts(
        [ParsedMtprotoMessage(kind="text", body="a"),
         ParsedMtprotoMessage(kind="text", body="b", note=GZIP_TRUNCATED_NOTE)],
        "read",
    )
    assert "note" not in plain
    assert noted["note"] == GZIP_TRUNCATED_NOTE


# --------------------------------------------------------------------------- #
# MTProto schema decoder (tl/decoder.py)
# --------------------------------------------------------------------------- #

def _gzip_node(root):
    return next(n for n in iter_nodes(root) if n.kind == "gzip")


def test_decoder_truncated_gzip_note_keeps_inflated_prefix():
    packed = gzip.compress(_USERS)[:-_GZIP_TRAILER]
    node = _gzip_node(decode_tl(rpc_result(100, _truncated_gzip_packed(_USERS))))
    assert node.note.startswith(f"inflated {len(packed)} B → {len(_USERS)} B")
    assert GZIP_TRUNCATED_NOTE in node.note
    assert any(n.name == "user" for n in iter_nodes(node))


def test_decoder_complete_gzip_note_is_unchanged():
    packed = gzip.compress(_USERS)
    node = _gzip_node(decode_tl(rpc_result(100, gzip_packed(_USERS))))
    assert node.note == f"inflated {len(packed)} B → {len(_USERS)} B"


# --------------------------------------------------------------------------- #
# gRPC (grpc.py + the protobuf view that renders its notes)
# --------------------------------------------------------------------------- #

_MSG = b"\x0a\x05hello\x10\x2a" * 8


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_grpc_truncated_message_keeps_partial_data_with_note(encoding):
    packed = gzip.compress(_MSG) if encoding == "gzip" else zlib.compress(_MSG)
    cut = _GZIP_TRAILER if encoding == "gzip" else 4  # zlib trailer: Adler-32
    data, note = decompress_grpc_payload(packed[:-cut], encoding)
    assert data == _MSG
    assert note == GRPC_INFLATE_TRUNCATED_NOTE_FMT.format(label=encoding)


def test_grpc_truncated_guessed_encoding_joins_both_notes():
    data, note = decompress_grpc_payload(gzip.compress(_MSG)[:-_GZIP_TRAILER], "")
    assert data == _MSG
    assert note == (
        "compressed gRPC message without grpc-encoding; inflated as gzip/zlib; "
        + GRPC_INFLATE_TRUNCATED_NOTE_FMT.format(label="gzip/zlib")
    )


def test_grpc_complete_messages_are_unchanged():
    assert decompress_grpc_payload(gzip.compress(_MSG), "gzip") == (_MSG, "")
    assert decompress_grpc_payload(gzip.compress(_MSG), "gzip", InflateBudget()) == (_MSG, "")
    assert decompress_grpc_payload(gzip.compress(_MSG), "identity") == (
        _MSG, "compressed gRPC message without grpc-encoding; inflated as gzip/zlib")


def test_grpc_truncated_budget_charges_partial_output():
    budget = InflateBudget(limit=10_000)
    data, _note = decompress_grpc_payload(gzip.compress(_MSG)[:-_GZIP_TRAILER], "gzip", budget)
    assert budget.remaining == 10_000 - len(data)


def test_protobuf_view_shows_the_truncation_note():
    payload = gzip.compress(_MSG)[:-_GZIP_TRAILER]
    body = b"\x01" + len(payload).to_bytes(4, "big") + payload
    view = decode_protobuf_view(body, content_type="application/grpc",
                                grpc_encoding="gzip")
    message = view.messages[0]
    assert message.ok and not message.error
    assert GRPC_INFLATE_TRUNCATED_NOTE_FMT.format(label="gzip") in message.notes
