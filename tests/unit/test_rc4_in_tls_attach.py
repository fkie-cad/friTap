"""Nested RC4-in-TLS: event timestamps/session ids, provenance, attach and absorption.

Pure unit tests over hand-built flows/spans; tshark is never executed. The demo
layout mirrors rc4demo_neu4.pcap: the request's 4-byte length prefix (frame 22)
and its 26-byte ciphertext (frame 26) ride separate TLS frames, the 64-byte
response rides one frame (28) together with its prefix.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import friTap.offline.pcap_to_tap as p2t
from friTap.connection_index import canonical_4tuple, resolve_connection_key
from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.offline.rc4 import decrypt as rc4d
from friTap.offline.rc4 import offline_decryptor as od
from friTap.offline.rc4 import tls_attach as ta
from friTap.offline.registry import get_offline_decryptor_registry
from friTap.offline.tls_spans import TlsPlaintextSpan

CLIENT = ("127.0.0.1", 53646)
SERVER = ("127.0.0.1", 8443)
KEY = canonical_4tuple(*CLIENT, *SERVER)
REQUEST = b"R" * 26
RESPONSE = b"S" * 64


def _span(frame_no, ts, direction, data):
    sender, receiver = (CLIENT, SERVER) if direction == "write" else (SERVER, CLIENT)
    return TlsPlaintextSpan(frame_no, ts, direction, data, *sender, *receiver)


def _demo_spans() -> dict:
    return {
        "write": [_span(22, 1.5, "write", b"\x00\x00\x00\x1a"),
                  _span(26, 3.5, "write", b"c" * 26)],
        "read": [_span(28, 3.6, "read", b"\x00\x00\x00\x40" + b"d" * 64)],
    }


def _msg(direction, message, *, ts=0.0, frames=(), offset=0, header=0):
    sender, receiver = (CLIENT, SERVER) if direction == "write" else (SERVER, CLIENT)
    return rc4d.DecryptedRc4Message(
        src_addr=sender[0], src_port=sender[1],
        dst_addr=receiver[0], dst_port=receiver[1],
        ss_family="AF_INET", direction=direction, message=message,
        key=b"k" * 19, source="rc4-keylog", nested=True,
        timestamp=ts, tls_frames=tuple(frames), cipher_offset=offset,
        cipher_len=len(message), frame_header_len=header,
    )


def _demo_msgs():
    return [_msg("write", REQUEST, ts=3.5, frames=(22, 26), offset=4, header=4),
            _msg("read", RESPONSE, ts=3.6, frames=(28,), offset=4, header=4)]


def _record(direction, length, offset=4, header=4):
    return {"direction": direction, "length": length,
            "cipher_offset": offset, "frame_header_len": header}


# ------------------------------ step 3: events ------------------------------ #

def test_rc4_event_carries_pcap_timestamp_and_session_id():
    ev = od._rc4_datalog_event(_msg("write", REQUEST, ts=1790603138.5))
    assert ev.timestamp == 1790603138.5
    assert ev.ssl_session_id == f"rc4:{KEY}"
    assert ev.protocol == "rc4"


def test_rc4_event_without_timestamp_keeps_default_clock():
    ev = od._rc4_datalog_event(_msg("write", REQUEST))
    assert ev.timestamp > 0  # DatalogEvent's own default, as before


def test_rc4_session_id_separates_rc4_from_tls_connection_key():
    ev = od._rc4_datalog_event(_msg("write", REQUEST))
    rc4_key = resolve_connection_key(*CLIENT, *SERVER,
                                     session_token=ev.ssl_session_id, protocol="rc4")
    tls_key = resolve_connection_key(*CLIENT, *SERVER, protocol="tls")
    assert rc4_key.startswith("sid:rc4:") and tls_key.startswith("net:")
    assert rc4_key != tls_key


def test_record_rc4_provenance_tags_records():
    state = SimpleNamespace(rc4_provenance={})
    msg = _demo_msgs()[0]
    od._record_rc4_provenance(state, KEY, msg, msg.message)
    (rec,) = state.rc4_provenance[KEY]
    assert rec["tls_frames"] == [22, 26] and rec["length"] == 26
    assert rec["framing"] == "u32be-length" and rec["key_len"] == 19
    assert rec["_chunk_key"] == p2t._chunk_key("write", REQUEST)


def test_record_rc4_provenance_tolerates_minimal_state():
    od._record_rc4_provenance(object(), KEY, _demo_msgs()[0], REQUEST)  # no raise


def test_span_streams_only_when_nested_with_spans():
    state = SimpleNamespace(tls_spans={KEY: _demo_spans()})
    assert "streams" in od._span_streams_kwargs(state, True)
    assert od._span_streams_kwargs(state, False) == {}
    assert od._span_streams_kwargs(SimpleNamespace(tls_spans={}), True) == {}


def test_emitter_passes_timestamps_and_records_provenance(monkeypatch, tmp_path):
    msgs = _demo_msgs()
    seen_kwargs = {}

    def fake_iter(*_a, stats=None, **kw):
        seen_kwargs.update(kw)
        return iter(msgs)

    monkeypatch.setattr(rc4d, "iter_decrypted_messages", fake_iter)
    keylog = tmp_path / "rc4.keylog"
    keylog.write_text("")
    tls_keylog = tmp_path / "tls.keylog"
    tls_keylog.write_text("")
    bus, seen = EventBus(), []
    bus.subscribe(DatalogEvent, seen.append)
    state = SimpleNamespace(tls_spans={KEY: _demo_spans()}, rc4_provenance={},
                            ensure_open=lambda *_a: None,
                            note_capture_time=lambda *_a: None)
    od._emit_rc4_streams("x.pcap", str(keylog), str(tls_keylog), tshark_bin="t",
                         tls_ports=(), bus=bus, state=state,
                         result=p2t.ConvertResult(tap_path="x"))
    assert "streams" in seen_kwargs
    assert [ev.timestamp for ev in seen] == [3.5, 3.6]
    assert len(state.rc4_provenance[KEY]) == 2


# ------------------------------ step 4: registry ---------------------------- #

def test_rc4_entry_nests_in_tls_and_is_post_attached():
    assert get_offline_decryptor_registry().get("rc4").nests_in_tls is True
    assert "rc4" in p2t._tls_nested_protocol_names()
    assert "rc4" in p2t._post_attach_transports()


def test_tls_holdback_only_with_a_nesting_entry():
    rc4 = get_offline_decryptor_registry().get("rc4")
    assert p2t._tls_holdback_transports([rc4]) == frozenset({"tls"})
    assert p2t._tls_holdback_transports([]) == frozenset()
    assert "tls" not in p2t._post_attach_transports()


# --------------------------- step 4: consumption ---------------------------- #

def test_tls_fully_consumed_when_records_cover_both_directions():
    records = [_record("write", 26), _record("read", 64)]
    assert ta._tls_fully_consumed(_demo_spans(), records) is True


def test_tls_not_consumed_when_bytes_are_left_over():
    assert ta._tls_fully_consumed(_demo_spans(), [_record("write", 26)]) is False
    assert ta._tls_fully_consumed(_demo_spans(),
                                  [_record("write", 20), _record("read", 64)]) is False


def test_tls_not_consumed_without_spans():
    assert ta._tls_fully_consumed({}, [_record("write", 26)]) is False


def test_tls_owned_for_dedupes_frames_in_order():
    owned = ta._tls_owned_for([_record("write", 26), _record("read", 64)],
                              _demo_spans())
    assert owned["write"] == b"\x00\x00\x00\x1a" + b"c" * 26
    assert len(owned["read"]) == 68


# ----------------------------- step 4: attach ------------------------------- #

def _collect(events):
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    collector.use_event_clock(True)
    bus.subscribe(DatalogEvent, collector.on_data)
    for ev in events:
        bus.emit(ev)
    return collector.live_flows()


def _tls_event(span):
    return DatalogEvent(data=span.data, direction=span.direction,
                        src_addr=span.src_addr, src_port=span.src_port,
                        dst_addr=span.dst_addr, dst_port=span.dst_port,
                        transport="tcp", timestamp=span.ts)


def _demo_state_and_flows():
    spans = _demo_spans()
    state = SimpleNamespace(tls_spans={KEY: spans}, rc4_provenance={})
    events = [_tls_event(s) for d in ("write", "read") for s in spans[d]]
    for msg in _demo_msgs():
        ev = od._rc4_datalog_event(msg)
        od._record_rc4_provenance(state, KEY, msg, ev.data)
        events.append(ev)
    flows = _collect(events)
    flows_by_transport = {f.transport: f for f in flows}
    flows_by_transport["tls"].tls.version = "TLS 1.3"
    flows_by_transport["tls"].tls.cipher = "TLS_AES_256_GCM_SHA384"
    return state, flows, flows_by_transport


def test_attach_builds_tls_owned_then_rc4_chunks_stack():
    state, flows, by_transport = _demo_state_and_flows()
    absorbed = p2t._attach_rc4_in_tls_layers(flows, state)
    rc4_flow = by_transport["rc4"]
    tls_layer, rc4_layer = rc4_flow.layers
    assert (tls_layer.name, tls_layer.depth, tls_layer.data.data_source) == ("tls", 0, "owned")
    assert (rc4_layer.name, rc4_layer.depth, rc4_layer.data.data_source) == ("rc4", 1, "chunks")
    assert rc4_layer.parent is tls_layer and tls_layer.child is rc4_layer
    assert len(tls_layer.data.write) == 30 and len(tls_layer.data.read) == 68
    assert tls_layer.version == "TLS 1.3"
    assert rc4_layer.data.write == REQUEST and rc4_layer.data.read == RESPONSE
    assert absorbed == {by_transport["tls"].flow_id}


def test_attach_fills_rc4_metadata():
    state, flows, by_transport = _demo_state_and_flows()
    p2t._attach_rc4_in_tls_layers(flows, state)
    layer = by_transport["rc4"].layer("rc4")
    assert (layer.source, layer.key_len, layer.direction) == ("rc4-keylog", 19, "both")
    assert layer.message_count == 2 and layer.framing == "u32be-length"
    assert [r["tls_frames"] for r in layer.records] == [[22, 26], [28]]
    assert all("_chunk_key" not in r and "source" not in r for r in layer.records)


def test_partially_consumed_tls_flow_is_kept():
    state, flows, _ = _demo_state_and_flows()
    state.rc4_provenance[KEY] = state.rc4_provenance[KEY][:1]  # response undecrypted
    assert p2t._attach_rc4_in_tls_layers(flows, state) == set()


def test_attach_is_noop_without_rc4_provenance():
    flows = [SimpleNamespace(transport="tls", layers=[])]
    assert p2t._attach_rc4_in_tls_layers(flows, SimpleNamespace(rc4_provenance={})) == set()
    assert p2t._attach_rc4_in_tls_layers(flows, object()) == set()


# ------------------------- TLS metadata stream key -------------------------- #

@pytest.mark.parametrize("layers, expected", [
    ({"tls_stream": ["0"], "tcp_stream": ["2"]}, "by-tls"),
    ({"tcp_stream": ["2"]}, "by-tcp"),
])
def test_tls_meta_for_packet_prefers_tls_stream(layers, expected):
    meta = {0: "by-tls", 2: "by-tcp"}
    assert p2t._tls_meta_for_packet(meta, {"layers": layers}, 2) == expected


def test_single_pass_exports_tls_stream():
    from friTap.offline import tshark
    cmd = tshark.build_tls_command("x.pcap", "k.log")
    assert cmd[cmd.index("tls.stream") - 1] == "-e"


# --------------------------- real capture (tshark) -------------------------- #

_REPO = __import__("pathlib").Path(__file__).resolve().parents[2]
_PCAP = _REPO / "rc4demo_neu4.pcap"


def _convert_demo(tmp_path, with_rc4: bool):
    import shutil
    from friTap.flow.tap_reader import TapReader
    from friTap.offline.tshark import find_tshark

    try:
        find_tshark(None)
    except Exception:  # noqa: BLE001 - no tshark on this machine
        pytest.skip("tshark not installed")
    if not _PCAP.is_file():
        pytest.skip("rc4demo_neu4.pcap not present")
    keylogs = {"rc4": str(_REPO / "rc4demo_neu4.rc4.keylog")} if with_rc4 else {}
    pcap = tmp_path / "demo.pcap"  # no manifest next to it
    shutil.copy(_PCAP, pcap)
    tap = tmp_path / "out.tap"
    result = p2t.convert_pcap_to_tap(str(pcap), str(_REPO / "rc4demo_neu4.keylog"),
                                     str(tap), protocol_keylogs=keylogs)
    reader = TapReader(str(tap))
    reader.open()
    return result, reader.read_all_flows()


def test_real_capture_one_rc4_flow_absorbs_tls(tmp_path):
    result, flows = _convert_demo(tmp_path, with_rc4=True)
    assert result.flow_count == 1 and [f.transport for f in flows] == ["rc4"]
    tls_layer, rc4_layer = flows[0].layers
    assert (tls_layer.name, tls_layer.data.data_source) == ("tls", "owned")
    assert (len(tls_layer.data.write), len(tls_layer.data.read)) == (30, 68)
    assert (len(rc4_layer.data.write), len(rc4_layer.data.read)) == (26, 64)


def test_real_capture_without_rc4_keeps_single_tls_flow(tmp_path):
    result, flows = _convert_demo(tmp_path, with_rc4=False)
    assert result.flow_count == 1 and [f.transport for f in flows] == ["tls"]
    assert flows[0].layer("rc4") is None
