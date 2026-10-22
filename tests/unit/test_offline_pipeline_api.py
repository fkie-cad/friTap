"""Tests for friTap.offline.pipeline_api (the public offline-decryptor plugin API)."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from friTap.events import EventBus
from friTap.offline import pcap_to_tap, pipeline_api

PUBLIC_NAMES = (
    "ConvertResult", "WriterState", "StreamDirectionTracker",
    "chunk_key", "event_ts_kwargs", "open_at_capture_time", "scope_messages_to_flow",
    "ek_field", "ek_as_list", "ek_first", "coerce_int", "coerce_float", "extract_addrs",
    "tls_packet_to_events", "emit_tls_session_event",
    "TlsSinglePass", "run_tls_combined_pass",
)

# pcap_to_tap's historical private name -> the pipeline_api object it must alias.
LEGACY_ALIASES = {
    "ConvertResult": "ConvertResult",
    "_WriterState": "WriterState",
    "_StreamDirectionTracker": "StreamDirectionTracker",
    "_field": "ek_field",
    "_as_list": "ek_as_list",
    "_first": "ek_first",
    "_coerce_int": "coerce_int",
    "_coerce_float": "coerce_float",
    "_extract_addrs": "extract_addrs",
    "_tls_packet_to_events": "tls_packet_to_events",
}

# Removed pcap_to_tap aliases/re-exports: import these from their real modules
# (friTap.offline.pipeline_api, keylog_paths, tls_spans) instead.
REMOVED_PCAP_TO_TAP_NAMES = (
    "_chunk_key", "_event_ts_kwargs", "_open_at_capture_time", "_scope_messages_to_flow",
    "_unique_keylog_paths", "_emit_tls_session_event", "_tls_meta_for_packet",
    "_strip_private_keys", "_flow_chunk_keys", "_copy_keylog_into_tap",
    "canonical_keylog_path", "record_tls_span",
    "_emit_tls_streams", "_emit_tls_streams_singlepass", "_tls_segments_to_events",
    "_extract_tls_metadata_safe", "_extract_quic_metadata_safe", "_emit_quic_streams",
)


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_public_name_is_importable(name):
    assert callable(getattr(pipeline_api, name))


@pytest.mark.parametrize("legacy, public", sorted(LEGACY_ALIASES.items()))
def test_pcap_to_tap_keeps_legacy_alias(legacy, public):
    assert getattr(pcap_to_tap, legacy) is getattr(pipeline_api, public)


@pytest.mark.parametrize("name", REMOVED_PCAP_TO_TAP_NAMES)
def test_pcap_to_tap_no_longer_carries_removed_name(name):
    assert not hasattr(pcap_to_tap, name)


@pytest.mark.parametrize("name", ("emit_tls_streams_singlepass",
                                  "extract_tls_metadata_safe", "_tls_meta_for_packet"))
def test_removed_legacy_pass_helpers_are_gone(name):
    assert not hasattr(pipeline_api, name)


def test_chunk_key_is_direction_plus_short_sha1():
    digest = hashlib.sha1(b"abc").hexdigest()[:16]
    assert pipeline_api.chunk_key("write", b"abc") == f"write:{digest}"
    assert pipeline_api.chunk_key("read", None) == (
        f"read:{hashlib.sha1(b'').hexdigest()[:16]}")


@pytest.mark.parametrize("ts, expected", [
    (12.5, {"timestamp": 12.5}), (0.0, {}), (-1.0, {}), (None, {}),
])
def test_event_ts_kwargs_only_carries_real_capture_times(ts, expected):
    assert pipeline_api.event_ts_kwargs(ts) == expected


def test_tracker_prefers_server_port_over_first_packet():
    tracker = pipeline_api.StreamDirectionTracker(server_ports=(8443,))
    # Server-originated first packet: the destination is the client.
    assert tracker.direction_for("s", "10.0.0.2", 8443, "10.0.0.1", 50000) == "read"
    assert tracker.direction_for("s", "10.0.0.1", 50000, "10.0.0.2", 8443) == "write"
    assert tracker.stream_count == 1


def test_tracker_falls_back_to_first_packet_is_client():
    tracker = pipeline_api.StreamDirectionTracker()
    assert tracker.direction_for("s", "a", 1000, "b", 2000) == "write"
    assert tracker.direction_for("s", "b", 2000, "a", 1000) == "read"


def test_ek_helpers_accept_both_spellings_and_lists():
    layers = {"tcp_stream": ["7"], "ip.src": "1.2.3.4"}
    assert pipeline_api.coerce_int(pipeline_api.ek_first(
        pipeline_api.ek_field(layers, "tcp.stream"))) == 7
    assert pipeline_api.ek_first(pipeline_api.ek_field(layers, "ip.src")) == "1.2.3.4"
    assert pipeline_api.coerce_int("x", default=None) is None


def test_scope_messages_to_flow_keeps_only_matching_chunks():
    key = pipeline_api.chunk_key("write", b"hi")
    flow = SimpleNamespace(chunks=[SimpleNamespace(direction="write", data=b"hi")])
    messages = [{"_chunk_key": key, "body": "kept"}, {"_chunk_key": "other", "body": "x"}]
    assert pipeline_api.scope_messages_to_flow(flow, messages) == [{"body": "kept"}]


def test_singlepass_honours_injected_packet_source():
    class _Writer:
        def open(self, *a, **k):
            pass

        def update_capture_start(self, ts):
            pass

    pkt = {"layers": {"frame_number": ["1"], "ip_src": ["10.0.0.1"], "ip_dst": ["10.0.0.2"],
                      "tcp_stream": ["0"], "tcp_srcport": ["50000"], "tcp_dstport": ["443"],
                      "tls_app_data": ["17"], "data_data": ["6869"]}}
    result = pipeline_api.ConvertResult(tap_path="unused.tap")
    pipeline_api.run_tls_combined_pass(
        "tshark", "x.pcap", None, tls_ports=(), extra_decode_as=(), heuristic=False,
        bus=EventBus(), state=pipeline_api.WriterState(_Writer(), "unused.tap", "t", None),
        result=result, tracker=pipeline_api.StreamDirectionTracker(),
        packet_source=lambda cmd: iter([pkt]), app_data_marker="tls.app_data")
    assert (result.decrypted_packet_count, result.stream_count) == (1, 1)


def test_protocol_session_id_is_perspective_independent():
    from friTap.connection_index import canonical_4tuple

    fwd = pipeline_api.protocol_session_id("rc4", "10.0.0.1", 5000, "1.2.3.4", 443)
    rev = pipeline_api.protocol_session_id("rc4", "1.2.3.4", 443, "10.0.0.1", 5000)
    assert fwd == rev == "rc4:" + canonical_4tuple("10.0.0.1", 5000, "1.2.3.4", 443)
