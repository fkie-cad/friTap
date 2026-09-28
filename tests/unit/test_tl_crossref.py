"""Cross-references between decrypted Telegram records (synthetic bytes only)."""

from __future__ import annotations

import os

import pytest

from friTap.offline.mtproto.crossref import (
    MAX_ACKS,
    CrossRefIndex,
    extract_record_refs,
    method_name,
    msg_id_hex,
)
from friTap.offline.mtproto.tl import decode_tl
from tests.unit._tl_helpers import (
    HELP_GET_CONFIG,
    INIT_CONNECTION,
    INVOKE_WITH_LAYER,
    MSG_CONTAINER,
    gzip_packed,
    i32,
    i64,
    msgs_ack,
    pong,
    rpc_result,
    tl_str,
    u32,
)

AKID = "1122334455667788"
BOOL_TRUE = 0x997275B5
REQ_ID = 0x6000_0000_0000_0004          # client msg_id (0 mod 4)
RSP_ID = 0x6000_0000_0000_0101          # server response (1 mod 4)


def container_with_ids(*children) -> bytes:
    """``msg_container`` of ``(msg_id, seqno, body)`` children."""
    out = u32(MSG_CONTAINER) + i32(len(children))
    for msg_id, seqno, body in children:
        out += i64(msg_id) + i32(seqno) + i32(len(body)) + body
    return out


def ref(seq, data, msg_id, direction="read", akid=AKID):
    return extract_record_refs(data, record_seq=seq, auth_key_id=akid,
                               direction=direction, msg_id=msg_id)


def index_of(*refs) -> CrossRefIndex:
    index = CrossRefIndex()
    for item in refs:
        index.add(item)
    return index


# --------------------------------------------------------------------------- #
# extraction
# --------------------------------------------------------------------------- #

def test_extract_rpc_result_request_id_and_method():
    item = ref(2, rpc_result(REQ_ID, u32(BOOL_TRUE)), RSP_ID)
    assert item.answers_req_ids == (REQ_ID,)
    assert item.method == "rpc_result"
    assert item.child_msg_ids == () and item.acked_ids == ()


def test_extract_all_ack_ids_beyond_the_display_vector_limit():
    ids = [RSP_ID + 4 * i for i in range(50)]
    item = ref(1, msgs_ack(*ids), REQ_ID, direction="write")
    assert item.acked_ids == tuple(ids)


def test_extract_container_children_and_label():
    data = container_with_ids((RSP_ID, 1, pong()), (RSP_ID + 4, 3, rpc_result(REQ_ID, u32(BOOL_TRUE))))
    item = ref(3, data, RSP_ID + 8)
    assert [(c.msg_id, c.seqno, c.method) for c in item.child_msg_ids] == [
        (RSP_ID, 1, "pong"), (RSP_ID + 4, 3, "rpc_result")]
    assert item.method == "msg_container[pong, rpc_result]"
    assert item.answers_req_ids == (REQ_ID,)


def test_method_name_unwraps_invoke_wrappers_and_gzip():
    init = (u32(INIT_CONNECTION) + u32(0) + i32(6) + tl_str("dev") + tl_str("os")
            + tl_str("1.0") + tl_str("en") + tl_str("") + tl_str("en") + u32(HELP_GET_CONFIG))
    wrapped = u32(INVOKE_WITH_LAYER) + i32(200) + init
    assert method_name(decode_tl(wrapped)) == "help.getConfig"
    assert method_name(decode_tl(gzip_packed(pong()))) == "pong"


def test_extract_never_raises_on_garbage():
    item = ref(9, b"\x01\x02\x03", 0)
    assert item.record_seq == 9 and item.answers_req_ids == ()


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #

def test_rpc_result_resolves_to_its_request_and_back():
    index = index_of(ref(1, u32(HELP_GET_CONFIG), REQ_ID, direction="write"),
                     ref(2, rpc_result(REQ_ID, u32(BOOL_TRUE)), RSP_ID))
    response = index.resolve(2)
    assert response["answers"] == [
        {"msg_id": msg_id_hex(REQ_ID), "record_seq": 1, "method": "help.getConfig"}]
    assert response["request_method"] == "help.getConfig"
    assert index.resolve(1)["answered_by"] == [
        {"msg_id": msg_id_hex(RSP_ID), "record_seq": 2, "method": "boolTrue"}]


def test_unresolved_request_keeps_msg_id_without_record():
    index = index_of(ref(2, rpc_result(REQ_ID, u32(BOOL_TRUE)), RSP_ID))
    assert index.resolve(2)["answers"] == [{"msg_id": msg_id_hex(REQ_ID)}]
    assert "request_method" not in index.resolve(2)


def test_ack_mapping_both_directions_including_container_children():
    server = ref(1, pong(), RSP_ID)
    bundle = ref(2, container_with_ids((RSP_ID + 4, 1, pong()), (RSP_ID + 8, 3, pong())),
                 RSP_ID + 12)
    ack = ref(3, msgs_ack(RSP_ID, RSP_ID + 8, 0x7777), REQ_ID, direction="write")
    index = index_of(server, bundle, ack)
    refs = index.resolve(3)
    assert refs["acks_total"] == 3
    assert [a.get("record_seq") for a in refs["acks"]] == [1, 2, None]
    assert refs["acks"][1]["method"] == "pong"
    assert index.resolve(1)["acked_by"] == [
        {"msg_id": msg_id_hex(REQ_ID), "record_seq": 3, "method": "msgs_ack"}]
    assert index.resolve(2)["acked_by"][0]["record_seq"] == 3


def test_acks_are_capped_but_counted():
    ids = [RSP_ID + 4 * i for i in range(100)]
    refs = index_of(ref(1, msgs_ack(*ids), REQ_ID, direction="write")).resolve(1)
    assert len(refs["acks"]) == MAX_ACKS and refs["acks_total"] == 100


def test_container_refs_list_children_and_rpc_inside_container_resolves():
    request = ref(1, u32(HELP_GET_CONFIG), REQ_ID, direction="write")
    bundle = ref(2, container_with_ids((RSP_ID, 1, pong()),
                                       (RSP_ID + 4, 3, rpc_result(REQ_ID, u32(BOOL_TRUE)))),
                 RSP_ID + 8)
    index = index_of(request, bundle)
    refs = index.resolve(2)
    assert refs["container"] == [
        {"msg_id": msg_id_hex(RSP_ID), "seqno": 1, "method": "pong"},
        {"msg_id": msg_id_hex(RSP_ID + 4), "seqno": 3, "method": "rpc_result"}]
    assert refs["request_method"] == "help.getConfig"
    assert index.resolve(1)["answered_by"] == [
        {"msg_id": msg_id_hex(RSP_ID + 8), "record_seq": 2, "method": "boolTrue"}]


def test_other_auth_key_does_not_resolve():
    index = index_of(ref(1, u32(HELP_GET_CONFIG), REQ_ID, direction="write", akid="ffff"),
                     ref(2, rpc_result(REQ_ID, u32(BOOL_TRUE)), RSP_ID))
    assert "record_seq" not in index.resolve(2)["answers"][0]


def test_late_add_rebuilds_reverse_maps():
    index = index_of(ref(1, u32(HELP_GET_CONFIG), REQ_ID, direction="write"))
    assert index.resolve(1) == {}
    index.add(ref(2, rpc_result(REQ_ID, u32(BOOL_TRUE)), RSP_ID))
    assert index.resolve(1)["answered_by"][0]["record_seq"] == 2


def test_e2e_carrier_links_both_ways():
    index = index_of(ref(1, pong(), RSP_ID))
    index.add_e2e(2, AKID, RSP_ID)
    assert index.resolve(2) == {"carried_in": {"msg_id": msg_id_hex(RSP_ID), "record_seq": 1}}
    assert index.resolve(1)["carries"] == [{"record_seq": 2}]


def test_late_add_e2e_is_reflected_in_carries():
    index = index_of(ref(1, pong(), RSP_ID))
    assert "carries" not in index.resolve(1)
    index.add_e2e(3, AKID, RSP_ID)
    index.add_e2e(2, AKID, RSP_ID)
    index.add_e2e(4, "other-akid", RSP_ID)  # same msg_id under another key: not ours
    assert index.resolve(1)["carries"] == [{"record_seq": 2}, {"record_seq": 3}]


def test_e2e_without_decrypted_carrier_keeps_msg_id_only():
    index = CrossRefIndex()
    index.add_e2e(5, AKID, RSP_ID)
    assert index.resolve(5) == {"carried_in": {"msg_id": msg_id_hex(RSP_ID)}}
    assert index.resolve(99) == {}


# --------------------------------------------------------------------------- #
# Real sample (gitignored; skipped when absent)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(
    not os.path.exists("e2e.pcapng") or not os.path.exists("tg.keys.log"),
    reason="e2e.pcapng / tg.keys.log sample not present",
)
def test_sample_every_rpc_result_resolves_to_a_record():
    from friTap.offline.mtproto.decrypt import iter_decrypted_messages
    from friTap.offline.pcap_to_tap import _load_telegram_keys

    auth_keymap, obf_keys, _secret = _load_telegram_keys(["tg.keys.log"])
    records = list(iter_decrypted_messages("e2e.pcapng", auth_keymap, obf_keys=obf_keys))
    index = CrossRefIndex()
    for seq, record in enumerate(records, start=1):
        index.add(extract_record_refs(record.message, record_seq=seq,
                                      auth_key_id=record.auth_key_id_hex,
                                      direction=record.direction, msg_id=record.msg_id))
    answers = [a for seq in range(1, len(records) + 1)
               for a in index.resolve(seq).get("answers", [])]
    assert len(answers) >= 54
    assert all("record_seq" in a for a in answers)
