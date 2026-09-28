"""Unit tests for the generic schema-driven TL decoder (synthetic bytes only)."""

from __future__ import annotations

import gzip
import json
import os
import time
import zlib

import pytest

from friTap.offline.mtproto.tl import (
    TlLimits,
    TlNode,
    TlRaw,
    TlVector,
    decode_tl,
    decode_tl_cached,
    iter_nodes,
    stopped_early,
)
from tests.unit._tl_helpers import (  # noqa: F401 - re-exported for sibling tests
    BOOL_TRUE,
    GET_DIALOGS,
    GZIP_PACKED,
    HELP_GET_CONFIG,
    INIT_CONNECTION,
    INPUT_PEER_EMPTY,
    INVOKE_AFTER_MSG,
    INVOKE_WITH_LAYER,
    MSG_CONTAINER,
    MSGS_ACK,
    PONG,
    RPC_RESULT,
    USER,
    USER_STATUS_ONLINE,
    VECTOR,
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

# --------------------------------------------------------------------------- #
# Service messages
# --------------------------------------------------------------------------- #

def test_msgs_ack():
    node = decode_tl(msgs_ack(11, 22))
    assert (node.name, node.kind, node.ctor_id) == ("msgs_ack", "constructor", MSGS_ACK)
    ids = node.value("msg_ids")
    assert isinstance(ids, TlVector)
    assert (ids.items, ids.total, ids.elem_type) == ((11, 22), 2, "long")
    assert node.length == len(msgs_ack(11, 22))
    assert not stopped_early(node)


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress], ids=["gzip", "zlib"])
def test_rpc_result_gzip_packed_is_inflated(compress):
    inner = pong(7, 8)
    data = rpc_result(0x1234, gzip_packed(inner, compress))
    node = decode_tl(data)
    assert node.name == "rpc_result"
    assert node.value("req_msg_id") == 0x1234
    wrapper = node.value("result")
    assert wrapper.kind == "gzip" and wrapper.name == "gzip_packed"
    assert wrapper.note.startswith("inflated ") and f"→ {len(inner)} B" in wrapper.note
    inner_node = wrapper.value("packed_data")
    assert (inner_node.name, inner_node.value("msg_id"), inner_node.value("ping_id")) == ("pong", 7, 8)
    assert not stopped_early(node)


def test_gzip_inflate_is_bounded():
    data = gzip_packed(pong() * 50)
    node = decode_tl(data, limits=TlLimits(max_inflate=64))
    assert node.kind == "gzip"
    raw = node.value("packed_data")
    assert isinstance(raw, TlRaw) and "exceeds 64 B" in raw.reason


def test_gzip_corrupt_payload_is_raw_not_exception():
    node = decode_tl(u32(GZIP_PACKED) + tl_bytes(b"\x1f\x8b\x08not really gzip"))
    assert isinstance(node.value("packed_data"), TlRaw)
    assert "inflate failed" in node.note


def test_msg_container_children_are_bare_messages():
    node = decode_tl(container(msgs_ack(5), pong(3, 4)))
    assert node.name == "msg_container"
    messages = node.value("messages")
    assert messages.total == 2
    first, second = messages.items
    assert (first.name, first.ctor_id) == ("message", None)
    assert first.value("seqno") == 1 and first.value("bytes") == len(msgs_ack(5))
    assert first.value("body").name == "msgs_ack"
    assert second.value("body").name == "pong"
    assert node.length == len(container(msgs_ack(5), pong(3, 4)))


def test_unknown_child_in_container_keeps_siblings():
    unknown = u32(0xDEADBEEF) + b"\x01\x02\x03\x04"
    node = decode_tl(container(pong(), unknown, msgs_ack(9)))
    bodies = [m.value("body") for m in node.value("messages").items]
    assert [b.name for b in bodies] == ["pong", "unknown", "msgs_ack"]
    assert bodies[1].kind == "unknown" and bodies[1].ctor_id == 0xDEADBEEF
    assert bodies[1].value("remainder").data == b"\x01\x02\x03\x04"
    assert stopped_early(node)


def test_unknown_constructor_stops_and_keeps_earlier_fields():
    node = decode_tl(rpc_result(42, u32(0xCAFEBABE) + b"\xaa" * 8))
    assert node.name == "rpc_result"
    assert node.value("req_msg_id") == 42
    unknown = node.value("result")
    assert unknown.kind == "unknown"
    assert unknown.value("remainder") == TlRaw(b"\xaa" * 8, "unknown constructor 0xcafebabe")
    assert "stopped" in node.note


def test_unknown_top_level():
    node = decode_tl(u32(0x11111111) + b"rest")
    assert node.kind == "unknown" and node.ctor_id == 0x11111111


@pytest.mark.parametrize("data", [b"", b"\x01", b"\xff" * 3, os.urandom(64), u32(MSGS_ACK) + u32(VECTOR) + i32(99)])
def test_never_raises(data):
    node = decode_tl(data)
    assert isinstance(node, TlNode)


def test_truncated_field_reports_raw():
    data = pong()[:-3]
    node = decode_tl(data)
    assert node.name == "pong"
    assert stopped_early(node)
    assert node.value("msg_id") == 1


def test_trailing_bytes_are_reported():
    node = decode_tl(pong() + b"\x00" * 4)
    trailing = node.value("<trailing>")
    assert isinstance(trailing, TlRaw) and trailing.data == b"\x00" * 4


# --------------------------------------------------------------------------- #
# Limits
# --------------------------------------------------------------------------- #

def test_depth_limit_stops_cleanly():
    data = pong()
    for index in range(40):
        data = u32(INVOKE_AFTER_MSG) + i64(index) + data
    node = decode_tl(data, limits=TlLimits(max_depth=10))
    assert node.name == "invokeAfterMsg"
    assert any("max depth 10" in r.reason for r in _raws(node))
    unlimited = decode_tl(data, limits=TlLimits(max_depth=64))
    assert not stopped_early(unlimited)


def test_node_budget_switches_to_advance_only():
    data = container(*[pong(i, i) for i in range(10)])
    node = decode_tl(data, limits=TlLimits(max_nodes=4))
    assert "advance-only" in node.note
    assert node.length == len(data)
    assert not stopped_early(node)  # bytes were walked, just not materialised
    assert sum(1 for _ in iter_nodes(node)) <= 4


def test_vector_keeps_first_items_with_summary():
    node = decode_tl(msgs_ack(*range(50)))
    ids = node.value("msg_ids")
    assert ids.total == 50
    assert ids.items == tuple(range(20))
    assert ids.note == "… 30 more"


def test_object_vector_summary_still_walks_all_items():
    vector = u32(VECTOR) + i32(30) + b"".join(pong(i, i) for i in range(30))
    node = decode_tl(rpc_result(1, vector) + b"", limits=TlLimits(keep_vector_items=5))
    result = node.value("result")
    assert result.total == 30 and len(result.items) == 5
    assert [p.value("msg_id") for p in result.items] == [0, 1, 2, 3, 4]
    assert node.length == len(rpc_result(1, vector))
    assert not stopped_early(node)


# --------------------------------------------------------------------------- #
# Vector element-type heuristic (untyped rpc_result)
# --------------------------------------------------------------------------- #

def test_vector_heuristic_boxed_objects():
    node = decode_tl(rpc_result(1, u32(VECTOR) + i32(2) + pong() + pong()))
    assert node.value("result").elem_type == "Object"
    assert [p.name for p in node.value("result").items] == ["pong", "pong"]


def test_vector_heuristic_longs():
    node = decode_tl(rpc_result(1, u32(VECTOR) + i32(2) + i64(-5) + i64(6)))
    assert (node.value("result").elem_type, node.value("result").items) == ("long", (-5, 6))


def test_vector_heuristic_ints():
    node = decode_tl(rpc_result(1, u32(VECTOR) + i32(3) + i32(1) + i32(2) + i32(3)))
    assert (node.value("result").elem_type, node.value("result").items) == ("int", (1, 2, 3))


def test_vector_heuristic_unknown_is_raw():
    node = decode_tl(rpc_result(1, u32(VECTOR) + i32(2) + b"\x07" * 5))
    result = node.value("result")
    assert result.elem_type == "?" and isinstance(result.items[0], TlRaw)
    assert stopped_early(node)


def test_expect_types_the_rpc_result():
    node = decode_tl(rpc_result(1, u32(VECTOR) + i32(2) + i32(4) + i32(5) + i32(6) + i32(7)),
                     expect="Vector<long>")
    result = node.value("result")
    assert result.elem_type == "long" and result.total == 2
    assert not stopped_early(node)


def test_expect_types_a_plain_payload():
    node = decode_tl(u32(VECTOR) + i32(1) + i64(99), expect="Vector<long>")
    assert node.name == "vector"
    assert node.value("items").items == (99,)


# --------------------------------------------------------------------------- #
# Functions (client writes)
# --------------------------------------------------------------------------- #

def test_invoke_with_layer_init_connection():
    init = (
        u32(INIT_CONNECTION) + u32(0) + i32(4)
        + tl_str("Pixel") + tl_str("SDK 36") + tl_str("12.0") + tl_str("en")
        + tl_str("android") + tl_str("en")
        + u32(HELP_GET_CONFIG)
    )
    node = decode_tl(u32(INVOKE_WITH_LAYER) + i32(214) + init)
    assert (node.name, node.kind, node.value("layer")) == ("invokeWithLayer", "function", 214)
    query = node.value("query")
    assert (query.name, query.kind) == ("initConnection", "function")
    assert query.value("device_model") == "Pixel"
    assert query.value("lang_pack") == "android"
    assert query.field("proxy") is None  # flags.0 unset -> field omitted
    assert query.value("query").name == "help.getConfig"
    assert not stopped_early(node)


def test_messages_get_dialogs_function():
    data = (
        u32(GET_DIALOGS) + u32(0b11) + i32(1)  # exclude_pinned (flags.0) + folder_id (flags.1)
        + i32(0) + i32(0) + u32(INPUT_PEER_EMPTY) + i32(100) + i64(0)
    )
    node = decode_tl(data)
    assert (node.name, node.kind) == ("messages.getDialogs", "function")
    exclude = node.field("exclude_pinned")
    assert (exclude.value, exclude.flag_bit) == (True, "flags.0")
    assert node.value("folder_id") == 1
    assert node.value("offset_peer").name == "inputPeerEmpty"
    assert node.value("limit") == 100
    assert node.length == len(data)


# --------------------------------------------------------------------------- #
# user#b1b8cc83 (current schema; verified against a real capture)
# --------------------------------------------------------------------------- #



def test_synthetic_user_b1b8cc83():
    data = synthetic_user()
    node = decode_tl(data)
    assert (node.name, node.ctor_id) == ("user", USER)
    assert node.value("self") is True
    assert node.value("stories_unavailable") is True
    assert node.value("id") == 123456789
    assert node.value("access_hash") == -42
    assert (node.value("first_name"), node.value("last_name")) == ("Alice", "Example")
    assert node.value("phone") == "15550000000"
    assert node.value("status").value("expires") == 1700000000
    assert node.field("username") is None
    assert node.length == len(data)
    assert not stopped_early(node)


def test_user_inside_gzip_rpc_result_vector():
    vector = u32(VECTOR) + i32(1) + synthetic_user()
    node = decode_tl(rpc_result(9, gzip_packed(vector)))
    users = node.value("result").value("packed_data")
    assert users.items[0].value("first_name") == "Alice"


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #

def test_bool_result_decodes_as_constructor_when_untyped():
    node = decode_tl(rpc_result(1, u32(BOOL_TRUE)))
    assert node.value("result").name == "boolTrue"


def test_secret_domain():
    node = decode_tl(u32(0x6719E45C), domain="secret")
    assert node.name == "decryptedMessageActionFlushHistory"


def test_unknown_domain_never_raises():
    node = decode_tl(pong(), domain="nope")
    assert node.kind == "unknown" and "decoder error" in node.note


def test_to_jsonable_round_trips_through_json():
    node = decode_tl(rpc_result(1, gzip_packed(synthetic_user())))
    text = json.dumps(node.to_jsonable())
    assert '"first_name"' in text and '"0xb1b8cc83"' in text


def test_decode_tl_cached_memoises():
    data = msgs_ack(1, 2, 3)
    assert decode_tl_cached(data) is decode_tl_cached(data)


def test_large_gzip_payload_decodes_fast():
    vector = u32(VECTOR) + i32(3000) + synthetic_user() * 3000
    data = rpc_result(1, gzip_packed(vector))
    start = time.perf_counter()
    node = decode_tl(data)
    elapsed = time.perf_counter() - start
    assert node.value("result").value("packed_data").total == 3000
    assert not stopped_early(node)
    assert elapsed < 1.0


def _raws(node):
    from friTap.offline.mtproto.tl import iter_raws
    return list(iter_raws(node))


# --------------------------------------------------------------------------- #
# Real sample (gitignored; skipped when absent)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(
    not os.path.exists("e2e.pcapng") or not os.path.exists("tg.keys.log"),
    reason="e2e.pcapng / tg.keys.log sample not present",
)
def test_sample_capture_decodes_every_record():
    from friTap.offline.mtproto.decrypt import iter_decrypted_messages
    from friTap.offline.pcap_to_tap import _load_telegram_keys

    auth_keymap, obf_keys, _secret = _load_telegram_keys(["tg.keys.log"])
    records = list(iter_decrypted_messages("e2e.pcapng", auth_keymap, obf_keys=obf_keys))
    assert records
    stopped = 0
    gzip_nodes = []
    for record in records:
        node = decode_tl(record.message)
        assert isinstance(node, TlNode)
        stopped += stopped_early(node)
        gzip_nodes += [n for n in iter_nodes(node) if n.kind == "gzip"]
    print(f"\n{len(records)} records, {stopped} stopped early, {len(gzip_nodes)} gzip_packed")
    assert gzip_nodes
    assert all(n.note.startswith("inflated ") for n in gzip_nodes)
