"""Unit tests for the TL tree / envelope / cross-reference renderer (synthetic bytes)."""

from __future__ import annotations

import gzip
from datetime import datetime

from rich.text import Text

from friTap.offline.mtproto.tl import TlField, TlNode, TlRaw, TlVector, decode_tl
from friTap.tui.widgets.tl_tree_render import (
    TRUNCATED_LINE,
    format_msg_id,
    format_tl_bytes,
    format_tl_string,
    render_envelope,
    render_refs,
    render_tl_tree,
)
from tests.unit._tl_helpers import (
    GZIP_PACKED,
    USER,
    USER_STATUS_ONLINE,
    container,
    gzip_packed,
    i32,
    i64,
    msgs_ack,
    pong,
    rpc_result,
    synthetic_user,
    tl_bytes,
    tl_str,
    u32,
)

UPLOAD_FILE = 0x096A18D5
STORAGE_FILE_UNKNOWN = 0xAA963B05
RES_PQ = 0x05162463
VECTOR = 0x1CB5C415
#: A plausible client msg_id: 2026-09-25 (high 32 bits = Unix seconds).
MSG_ID = (1790358548 << 32) | 0x80000000


def _color(role: str) -> str:
    return {"warning": "yellow", "primary": "blue", "accent": "cyan"}.get(role, "white")


def render(data: bytes, **kwargs) -> list[str]:
    return render_tl_tree(decode_tl(data), color=_color, **kwargs)


def plain(lines: list[str]) -> list[str]:
    """Render markup to plain text (fails loudly on broken markup)."""
    return [Text.from_markup(line).plain for line in lines]


def joined(lines: list[str]) -> str:
    return "\n".join(plain(lines))


def user_with_names(first: str, last: str = "X") -> bytes:
    flags = (1 << 1) | (1 << 2) | (1 << 6) | (1 << 10) | (1 << 11)
    return (
        u32(USER) + u32(flags) + u32(0) + i64(7)
        + tl_str(first) + tl_str(last)
        + u32(USER_STATUS_ONLINE) + i32(1700000000)
    )


# --------------------------------------------------------------------------- #
# Scalars
# --------------------------------------------------------------------------- #

def test_markup_inside_strings_is_escaped():
    lines = render(user_with_names("[bold]Mallory[/bold]", "[red]x"))
    text = joined(lines)
    assert '"[bold]Mallory[/bold]"' in text
    assert '"[red]x"' in text


def test_control_chars_are_escaped():
    text = joined(render(user_with_names("a\nb\tc\x01d\"e\\")))
    assert '"a\\nb\\tc\\x01d\\"e\\\\"' in text


def test_long_string_is_truncated_with_length():
    text = joined(render(user_with_names("A" * 600)))
    assert '"' + "A" * 512 + '"… (600 chars)' in text
    assert "A" * 513 not in text


def test_format_tl_string_short_is_plain_quoted():
    assert format_tl_string("hi") == '"hi"'


def test_bytes_field_shows_length_and_hex_preview():
    payload = bytes(range(40))
    data = u32(UPLOAD_FILE) + u32(STORAGE_FILE_UNKNOWN) + i32(5) + tl_bytes(payload)
    text = joined(render(data))
    assert f"bytes: bytes[40] {payload[:32].hex()}…  bytes" in text
    assert "mtime: 5  int" in text
    assert "type: storage.fileUnknown#aa963b05" in text


def test_format_tl_bytes_short_and_empty():
    assert format_tl_bytes(b"\x01\x02") == "bytes[2] 0102"
    assert format_tl_bytes(b"") == "bytes[0]"


def test_int128_rendered_as_hex_and_invalid_utf8_string_as_bytes():
    nonce, server_nonce = bytes(range(16)), bytes(range(16, 32))
    data = (u32(RES_PQ) + nonce + server_nonce + tl_bytes(b"\xff\xfe\x00")
            + u32(VECTOR) + i32(1) + i64(99))
    text = joined(render(data))
    assert f"nonce: 0x{nonce.hex()}  int128" in text
    assert "pq: bytes[3] fffe00 (invalid UTF-8)  string" in text


# --------------------------------------------------------------------------- #
# Flags, dates, msg_ids
# --------------------------------------------------------------------------- #

def test_flags_list_set_bit_names_and_omit_absent_optionals():
    text = joined(render(synthetic_user()))
    assert "flags: 0x00000457 (self, access_hash, first_name, last_name, phone, status)  #" in text
    assert "flags2: 0x00000010 (stories_unavailable)  #" in text
    assert "self: true  flags.10?true" in text
    assert "first_name: \"Alice\"  flags.1?string" in text
    assert "username" not in text
    assert "contact:" not in text


def test_date_like_field_gets_local_time():
    text = joined(render(synthetic_user()))
    when = datetime.fromtimestamp(1700000000).strftime("%Y-%m-%d %H:%M:%S")
    assert f"expires: 1700000000 ({when})  int" in text


def test_msg_id_hex_time_and_ref_label():
    labels = {MSG_ID: "→ #12 messages.getDialogs"}
    text = joined(render(rpc_result(MSG_ID, pong(msg_id=MSG_ID)), ref_label=labels.get))
    stamp = datetime.fromtimestamp(1790358548.5).strftime("%Y-%m-%d %H:%M:%S.500")
    assert f"req_msg_id: 0x{MSG_ID:016x} ({stamp}) → #12 messages.getDialogs  long" in text


def test_msg_ids_vector_items_are_msg_ids():
    labels = {MSG_ID: "→ #3 ping"}
    text = joined(render(msgs_ack(MSG_ID, 5), ref_label=labels.get))
    assert f"[0] 0x{MSG_ID:016x} (" in text and "→ #3 ping" in text
    assert "[1] 0x0000000000000005" in text


def test_format_msg_id_without_plausible_time_or_label():
    assert format_msg_id(4) == "0x0000000000000004"
    assert format_msg_id(-1) == "0xffffffffffffffff"


def test_ref_label_is_escaped():
    text = joined(render(msgs_ack(MSG_ID), ref_label=lambda _m: "→ [bold]x"))
    assert "→ [bold]x" in text


# --------------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------------- #

def test_tree_glyphs_and_node_header():
    lines = plain(render(container(pong(), msgs_ack(1))))
    assert lines[0] == "  msg_container#73f1f8dc"
    assert lines[1].startswith("  └─ messages: Vector<%Message> [2]")
    assert any(line.lstrip().startswith("├─ [0] message") for line in lines)
    assert any("│" in line for line in lines)


def test_vector_summary_shows_first_items_and_more():
    text = joined(render(msgs_ack(*range(25))))
    assert "msg_ids: Vector<long> [25]" in text
    assert "[19] 0x0000000000000013" in text
    assert "[20]" not in text
    assert "… 5 more" in text


def test_undecoded_remainder_warning_and_hex_preview():
    lines = render(pong() + b"\xaa" * 80)
    text = joined(lines)
    assert "undecoded remainder (80 bytes) at +0x14" in text
    assert ("aa " * 16).strip() in text
    assert text.count("aa aa") > 0 and "…" in text
    assert any("yellow" in line and "undecoded remainder" in line for line in lines)


def test_unknown_constructor_uses_warning_and_keeps_remainder():
    lines = render(u32(0xDEADBEEF) + b"abcdefgh")
    text = joined(lines)
    assert plain(lines)[0].strip() == "unknown constructor 0xdeadbeef"
    assert "yellow" in lines[0]
    assert "undecoded remainder (8 bytes) at +0x4" in text
    assert "61 62 63 64 65 66 67 68" in text


def test_gzip_note_and_inflated_child():
    inner = pong(msg_id=1, ping_id=2)
    data = rpc_result(MSG_ID, gzip_packed(inner))
    packed = len(gzip.compress(inner))
    text = joined(render(data))
    assert "result: gzip_packed (inflated " in text
    assert f"→ {len(inner)} B)" in text
    assert "packed_data: pong#347773c5" in text
    assert packed > 0


def test_gzip_failure_is_a_warning_with_remainder():
    data = u32(GZIP_PACKED) + tl_bytes(b"not gzip at all!")
    text = joined(render(data))
    assert "gzip_packed (inflate failed" in text
    assert "undecoded remainder (16 bytes) at +0x5" in text


def test_line_cap_appends_hint():
    lines = render(msgs_ack(*range(50)), max_lines=5)
    assert len(lines) == 6
    assert plain(lines)[-1].strip() == TRUNCATED_LINE


def test_indent_prefixes_every_line():
    assert all(line.startswith(">>") for line in plain(render(pong(), indent=">>")))


def test_hand_built_tree_with_none_and_raw_vector_items():
    vector = TlVector("?", (TlRaw(b"\x01\x02", "vector of unknown element type"),), 3, 8)
    node = TlNode("thing", 0x11223344, "constructor",
                  (TlField("v", "Vector<?>", vector), TlField("gone", "int", None)), 0, 20)
    text = joined(render_tl_tree(node, color=_color))
    assert "thing#11223344" in text
    assert "undecoded remainder (2 bytes) at +0xc" in text
    assert "gone: (omitted)" in text


def test_default_color_function_works_without_theme():
    assert render_tl_tree(decode_tl(pong()))[0]


# --------------------------------------------------------------------------- #
# Envelope / refs
# --------------------------------------------------------------------------- #

def test_render_envelope_full_cloud():
    envelope = {
        "auth_key_id": "0123456789abcdef", "salt": "aa" * 8, "session_id": "bb" * 8,
        "msg_id": f"0x{MSG_ID:016x}", "msg_time": 1790358548.5, "msg_id_kind": "server_response",
        "seq_no": 7, "content_related": True, "msg_len": 40, "padding_len": 12,
        "frame_len": 92, "transport": "intermediate", "obfuscated": True, "dc_id": 2,
        "dc_addr": "149.154.167.41:443",
    }
    text = joined(render_envelope(envelope))
    stamp = datetime.fromtimestamp(1790358548.5).strftime("%Y-%m-%d %H:%M:%S.500")
    assert stamp in text
    assert "seq_no               7 (content-related)" in text
    assert "server response" in text
    assert "padding              12 B" in text
    assert "obfuscated           yes" in text
    assert "149.154.167.41:443" in text
    assert "content_related" not in text


def test_render_envelope_tolerates_missing_and_extra_keys():
    assert render_envelope({}) == []
    assert render_envelope(None) == []
    text = joined(render_envelope({"seq_no": 4, "key_fingerprint": "[bold]ff", "odd": 1}))
    assert "4 (service)" in text
    assert "key fingerprint      [bold]ff" in text
    assert "odd" in text


def test_render_refs_with_row_resolver():
    refs = {
        "answers": {"msg_id": MSG_ID, "record_seq": 3, "flow_id": "f3", "method": "messages.getDialogs"},
        "acks": [{"msg_id": 5, "flow_id": "f1"}, {"msg_id": 9, "flow_id": "missing"}],
        "acks_total": 70,
        "request_method": "messages.getDialogs",
        "carries": [{"msg_id": "0x01", "flow_id": "f9", "method": "decryptedMessage"}],
    }
    rows = {"f3": 12, "f1": 4, "f9": 20}
    text = joined(render_refs(refs, rows.get))
    assert f"answers              msg 0x{MSG_ID:016x} → #12 messages.getDialogs" in text
    assert "acks (2 of 70):" in text
    assert "msg 0x0000000000000005 → #4" in text
    assert "msg 0x0000000000000009" in text
    assert "request method       messages.getDialogs" in text
    assert "carries              msg 0x01 → #20 decryptedMessage" in text


def test_render_refs_tolerates_missing_keys_and_no_resolver():
    assert render_refs({}) == []
    assert render_refs(None) == []
    text = joined(render_refs({"answered_by": [{"flow_id": 3, "method": "rpc_result"}], "acked_by": []}))
    assert "answered by          → rpc_result" in text
    assert "acked by" not in text
