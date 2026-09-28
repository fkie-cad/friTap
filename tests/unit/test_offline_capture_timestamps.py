#!/usr/bin/env python3

"""Offline Telegram conversion stamps flows with pcap capture time, not wall time.

Covers the emitter helpers (``_time_ordered``, ``_event_ts_kwargs``,
``_open_at_capture_time``), the parsed-message timestamp fallback, and an
end-to-end drive of the Telegram emitter with hermetic fakes.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from friTap.events import DatalogEvent, EventBus
from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.e2e.records import SecretChatMessage
from friTap.offline.mtproto.records import DecryptedMessage
from tests.unit._offline_helpers import patch_keylog_loaders


def _cloud(ts: float, body: bytes = b"\x00" * 16, msg_id: int = 0) -> DecryptedMessage:
    return DecryptedMessage(
        src_addr="10.0.0.1", src_port=12345,
        dst_addr="149.154.167.51", dst_port=443,
        ss_family="AF_INET", direction="write",
        message=body, dc_id=2, transport="abridged",
        obfuscated=True, auth_key_id_hex="1122334455667788",
        msg_id=msg_id, timestamp=ts,
    )


# ------------------------------------------------------------------ helpers


def test_time_ordered_sorts_by_timestamp():
    msgs = [SimpleNamespace(timestamp=t, n=i) for i, t in enumerate((3.0, 1.0, 2.0))]
    assert [m.n for m in p2t._time_ordered(msgs)] == [1, 2, 0]


def test_time_ordered_is_stable_for_ties_and_unknowns():
    msgs = [SimpleNamespace(timestamp=t, n=i) for i, t in enumerate((5.0, 0.0, 5.0, 0.0))]
    assert [m.n for m in p2t._time_ordered(msgs)] == [1, 3, 0, 2]


def test_time_ordered_tolerates_missing_attribute():
    msgs = [SimpleNamespace(n=0), SimpleNamespace(n=1, timestamp=None)]
    assert [m.n for m in p2t._time_ordered(msgs)] == [0, 1]


def test_event_ts_kwargs_only_for_real_times():
    assert p2t._event_ts_kwargs(12.5) == {"timestamp": 12.5}
    assert p2t._event_ts_kwargs(0.0) == {}
    assert p2t._event_ts_kwargs(-1.0) == {}


def test_open_at_capture_time_uses_note_capture_time_when_available():
    calls = []
    state = SimpleNamespace(note_capture_time=calls.append)
    p2t._open_at_capture_time(state, 7.0)
    assert calls == [7.0]


def test_open_at_capture_time_falls_back_to_ensure_open():
    calls = []
    state = SimpleNamespace(ensure_open=calls.append)
    p2t._open_at_capture_time(state, 7.0)
    p2t._open_at_capture_time(state, 0.0)
    assert calls == [7.0, 0.0]


def test_parsed_dicts_fall_back_to_capture_ts_when_tl_date_missing():
    parsed = [
        SimpleNamespace(sender_id=0, timestamp=0, kind="text", body="a",
                        has_media=False, peer_id=0),
        SimpleNamespace(sender_id=0, timestamp=111, kind="text", body="b",
                        has_media=False, peer_id=0),
    ]
    dicts = p2t._parsed_mtproto_to_dicts(parsed, "write", fallback_ts=99.5)
    assert [d["timestamp"] for d in dicts] == [99.5, 111]
    assert [d["timestamp"] for d in p2t._parsed_mtproto_to_dicts(parsed, "write")] == [0, 111]


# ------------------------------------------------------------------ emitter


class _TimedState:
    def __init__(self) -> None:
        self.mtproto_meta: dict = {}
        self.telegram_e2e_meta: dict = {}
        self.capture_times: list = []

    def note_capture_time(self, ts: float) -> None:
        self.capture_times.append(ts)


def _patch_backend(monkeypatch, cloud_msgs, e2e_ts: float = 0.0):
    patch_keylog_loaders(monkeypatch)

    def _fake_cloud(pcap_path, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        yield from cloud_msgs

    def _fake_e2e(transport_messages, keymap, stats=None):
        for m in transport_messages:
            if m.message == b"carrier":
                yield SecretChatMessage(
                    src_addr=m.src_addr, src_port=m.src_port,
                    dst_addr=m.dst_addr, dst_port=m.dst_port,
                    ss_family="AF_INET", direction=m.direction,
                    message=b"\x01" * 16, chat_id=1,
                    key_fingerprint_hex="aabbccddeeff0011", timestamp=e2e_ts,
                )

    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages", _fake_cloud)
    monkeypatch.setattr("friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages", _fake_e2e)


def _drive(state):
    bus = EventBus()
    events: list = []
    bus.subscribe(DatalogEvent, events.append)
    result = p2t.ConvertResult(tap_path="out.tap")
    p2t._emit_telegram_streams("cap.pcap", "k.log", bus=bus, state=state, result=result)
    return events


def test_emitter_orders_and_stamps_events_by_capture_time(monkeypatch):
    late = _cloud(200.0, b"late", msg_id=2)
    early = _cloud(100.0, b"carrier", msg_id=1)
    _patch_backend(monkeypatch, [late, early])  # yielded out of time order
    state = _TimedState()
    events = _drive(state)
    assert [(e.protocol, e.timestamp) for e in events] == [
        ("mtproto", 100.0), ("telegram_e2e", 100.0), ("mtproto", 200.0),
    ]
    assert state.capture_times == [100.0, 100.0, 200.0]


def test_emitter_e2e_prefers_its_own_timestamp(monkeypatch):
    _patch_backend(monkeypatch, [_cloud(100.0, b"carrier", msg_id=1)], e2e_ts=150.0)
    events = _drive(_TimedState())
    assert [e.timestamp for e in events if e.protocol == "telegram_e2e"] == [150.0]


def test_emitter_without_capture_time_keeps_default_timestamp(monkeypatch):
    _patch_backend(monkeypatch, [_cloud(0.0, b"x", msg_id=1)])
    state = _TimedState()
    events = _drive(state)
    assert events[0].timestamp > 1e9  # DatalogEvent default: wall clock
    assert state.capture_times == [0.0]


def test_real_writer_state_lowers_header_start(tmp_path):
    from friTap.flow.tap_reader import TapReader
    from friTap.flow.tap_writer import TapWriter

    writer = TapWriter()
    state = p2t._WriterState(writer, str(tmp_path / "o.tap"), "t", None)
    state.note_capture_time(500.0)
    state.note_capture_time(400.0)
    state.note_capture_time(0.0)
    writer.close()
    with TapReader(str(tmp_path / "o.tap")) as rd:
        rd.open()
        assert rd.header.capture_start == 400.0


def test_cloud_msg_replace_keeps_timestamp():
    # Guard: DecryptedMessage is a dataclass whose timestamp survives replace().
    assert replace(_cloud(5.0), dst_port=1).timestamp == 5.0
