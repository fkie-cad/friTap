#!/usr/bin/env python3

"""Locks for the offline write-once / dedupe cleanups.

* TapWriter ``defer_flow``: deferred flows are not persisted on "completed";
  the caller writes them exactly once later.
* TapWriter index: keyed by flow_id, first-write order, last record wins,
  ``forget_flow`` drops the entry.
* encode_flow: identical blobs within one flow are stored once.
* pcap_to_tap ``_state_attr`` / ``_already_emitted`` / ``_mark_seen``.
* keylog path identity (``friTap.offline.keylog_paths``).
"""

from __future__ import annotations

import os

from friTap.flow.models import Flow, FlowChunk
from friTap.parsers.base import ParseResult
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from friTap.offline import pcap_to_tap as p2t
from friTap.offline.keylog_paths import canonical_keylog_path, same_keylog_path


def _flow(flow_id: str, transport: str = "tls") -> Flow:
    flow = Flow(flow_id=flow_id, connection_id="c", src_addr="1.1.1.1", src_port=1,
                dst_addr="2.2.2.2", dst_port=443)
    flow.transport = transport
    return flow


def _read_ids(path: str) -> list[str]:
    reader = TapReader(path)
    reader.open()
    ids = [f.flow_id for f in reader.read_all_flows()]
    reader.close()
    return ids


# --- TapWriter ---------------------------------------------------------------

def test_defer_flow_skips_completed_write(tmp_path):
    path = str(tmp_path / "d.tap")
    writer = TapWriter(defer_flow=lambda f: f.transport == "mtproto")
    writer.open(path)
    deferred, normal = _flow("a", "mtproto"), _flow("b")
    writer.on_flow_event(deferred, "completed")
    writer.on_flow_event(normal, "completed")
    assert not writer.has_written("a")
    assert writer.has_written("b")
    writer.write_flow(deferred)  # the caller's single post-attach write
    writer.close()
    assert sorted(_read_ids(path)) == ["a", "b"]
    assert writer.flow_count == 2  # one FLOW record each, no duplicate


def test_index_keeps_first_write_order_and_last_record(tmp_path):
    path = str(tmp_path / "o.tap")
    writer = TapWriter()
    writer.open(path)
    first, second = _flow("x"), _flow("y")
    writer.write_flow(first)
    writer.write_flow(second)
    writer.write_flow(first)  # rewrite keeps x's position
    assert writer.written_flow_ids == {"x", "y"}
    writer.close()
    assert _read_ids(path) == ["x", "y"]


def test_forget_flow_drops_index_entry(tmp_path):
    path = str(tmp_path / "f.tap")
    writer = TapWriter()
    writer.open(path)
    writer.write_flow(_flow("x"))
    writer.write_flow(_flow("y"))
    writer.forget_flow("x")
    writer.forget_flow("missing")  # no-op
    assert not writer.has_written("x")
    writer.close()
    assert _read_ids(path) == ["y"]


# --- encode_flow blob dedupe -------------------------------------------------

def test_identical_blobs_are_stored_once_and_round_trip():
    body = b"B" * 4096
    flow = _flow("z")
    flow.chunks.append(FlowChunk(direction="write", data=body, timestamp=1.0))
    flow.request = ParseResult(protocol="mtproto", is_request=True, body=body)
    payload = encode_flow(flow)
    assert len(payload) < 2 * len(body)  # the body shares the chunk's blob
    decoded = decode_flow(payload)
    assert decoded.chunks[0].data == body
    assert decoded.request.body == body


# --- pcap_to_tap state helpers ----------------------------------------------

class _Bare:
    pass


class _Frozen:
    __slots__ = ()


def test_state_attr_creates_attaches_and_reuses():
    state = _Bare()
    value = p2t._state_attr(state, "thing", list)
    assert state.thing is value
    assert p2t._state_attr(state, "thing", list) is value


def test_state_attr_call_local_when_state_refuses_attributes():
    assert p2t._state_attr(_Frozen(), "thing", set) == set()


def test_writer_state_declares_telegram_fields():
    state = p2t._WriterState(TapWriter(), "x.tap", "t", None)
    assert state.telegram_ledger is None and state.telegram_refs is None
    assert p2t._next_record_seq(state) == 1
    assert p2t._next_record_seq(state) == 2


def test_already_emitted_and_mark_seen_share_semantics():
    seen: set = set()
    assert p2t._already_emitted(seen, "k") is False
    assert p2t._already_emitted(seen, "k") is True
    assert p2t._already_emitted(seen, None) is False  # unknown never dedupes
    entry: dict = {}
    assert p2t._mark_seen(entry, ("msg", 1)) is False
    assert p2t._mark_seen(entry, ("msg", 1)) is True
    assert entry["_seen"] == {("msg", 1)}


# --- keylog path identity ----------------------------------------------------

def test_canonical_keylog_path_resolves_relative_and_symlink(tmp_path, monkeypatch):
    target = tmp_path / "k.log"
    target.write_text("x\n")
    link = tmp_path / "l.log"
    os.symlink(target, link)
    monkeypatch.chdir(tmp_path)
    assert canonical_keylog_path("k.log") == canonical_keylog_path(str(link))
    assert same_keylog_path("k.log", str(link))
    assert not same_keylog_path(str(target), str(tmp_path / "other.log"))


def test_unique_keylog_paths_dedupes_by_canonical_path(tmp_path, monkeypatch):
    target = tmp_path / "k.log"
    target.write_text("x\n")
    monkeypatch.chdir(tmp_path)
    assert p2t._unique_keylog_paths("k.log", [str(target), "", "k.log"]) == ["k.log"]
