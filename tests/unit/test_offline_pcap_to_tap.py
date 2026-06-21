#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the offline pcap-to-tap pipeline.

The pure tests need no tshark binary: command building is pure, follow-output
parsing and QUIC packet translation are fed hand-built strings/dicts, and the
end-to-end path monkeypatches ``list_tls_streams`` / ``follow_tls_stream`` /
``stream_packets`` / ``find_tshark``.

A single integration test (``test_real_tshark_*``) runs the real tshark binary
against the hermetic premaster fixture (explicit keylog); it is skipped when
tshark or the fixture is unavailable.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import struct

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

from friTap.offline import tshark as tshark_mod
from friTap.offline import pcap_to_tap as p2t
from friTap.offline import cli as offline_cli
from friTap.flow.tap_reader import TapReader


# ---------------------------------------------------------------------------
# build_quic_command + Decode-As
# ---------------------------------------------------------------------------

def test_build_quic_command_default_quic_port():
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log")
    assert "udp.port==443,quic" in cmd


def test_build_quic_command_custom_quic_port():
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log", quic_ports=[8443])
    assert "udp.port==8443,quic" in cmd


def test_build_quic_command_keylog_only_when_provided():
    with_key = tshark_mod.build_quic_command("cap.pcapng", "keys.log")
    assert "tls.keylog_file:keys.log" in with_key

    without_key = tshark_mod.build_quic_command("cap.pcapng", None)
    assert not any("tls.keylog_file" in tok for tok in without_key)


def test_build_quic_command_extra_decode_as_passthrough():
    cmd = tshark_mod.build_quic_command(
        "cap.pcapng", "keys.log", extra_decode_as=["udp.port==9000,quic"]
    )
    assert "udp.port==9000,quic" in cmd


def test_build_quic_command_core_flags_and_filter():
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log")
    assert cmd[:5] == ["tshark", "-r", "cap.pcapng", "-2", "-T"]
    assert "ek" in cmd
    assert "quic.stream_data" in cmd
    # The useless encrypted tls.app_data field must NOT be requested.
    assert "tls.app_data" not in cmd


def test_quic_command_does_not_extract_tls_app_data():
    """tls.app_data is the ENCRYPTED field; it must never be exported."""
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log")
    assert all("tls.app_data" not in tok for tok in cmd)


# ---------------------------------------------------------------------------
# --tls-heuristic threading (BUG #2: flag used to be dead)
# ---------------------------------------------------------------------------

def _consecutive(cmd, *pair) -> bool:
    """True when *pair* appears as adjacent elements in *cmd* (e.g. -o VALUE)."""
    for i in range(len(cmd) - len(pair) + 1):
        if list(cmd[i:i + len(pair)]) == list(pair):
            return True
    return False


def test_heuristic_off_by_default_quic_command():
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log")
    assert "tcp.try_heuristic_first:TRUE" not in cmd


def test_heuristic_emits_tcp_try_heuristic_first_in_quic_command():
    cmd = tshark_mod.build_quic_command("cap.pcapng", "keys.log", heuristic=True)
    assert _consecutive(cmd, "-o", "tcp.try_heuristic_first:TRUE")


def _capture_run_capture(monkeypatch, captured: dict):
    """Stub tshark_mod._run_capture to record the argv and return empty stdout."""
    def _fake(cmd):
        captured["cmd"] = list(cmd)
        return ""
    monkeypatch.setattr(tshark_mod, "_run_capture", _fake)


def test_heuristic_emits_option_in_list_tls_streams_command(monkeypatch):
    captured: dict = {}
    _capture_run_capture(monkeypatch, captured)
    tshark_mod.list_tls_streams("/usr/bin/tshark", "cap.pcapng", "keys.log",
                                heuristic=True)
    assert _consecutive(captured["cmd"], "-o", "tcp.try_heuristic_first:TRUE")


def test_heuristic_emits_option_in_follow_tls_stream_command(monkeypatch):
    captured: dict = {}
    _capture_run_capture(monkeypatch, captured)
    tshark_mod.follow_tls_stream("/usr/bin/tshark", "cap.pcapng", 7, "keys.log",
                                 heuristic=True)
    assert _consecutive(captured["cmd"], "-o", "tcp.try_heuristic_first:TRUE")


def test_heuristic_absent_when_disabled_in_tls_commands(monkeypatch):
    captured: dict = {}
    _capture_run_capture(monkeypatch, captured)
    tshark_mod.list_tls_streams("/usr/bin/tshark", "cap.pcapng", "keys.log")
    assert "tcp.try_heuristic_first:TRUE" not in captured["cmd"]


def test_tls_decode_as_flags_for_custom_ports():
    flags = tshark_mod._decode_as_flags(
        "tcp.port", "tls", [8443], ["tcp.port==9000,http"])
    assert "tcp.port==8443,tls" in flags
    assert "tcp.port==9000,http" in flags


def test_quic_decode_as_flags_default_port():
    """QUIC defaults to port 443 when no explicit ports are given."""
    flags = tshark_mod._decode_as_flags(
        "udp.port", "quic", [], [], default_port=tshark_mod.DEFAULT_QUIC_PORT)
    assert "udp.port==443,quic" in flags


# ---------------------------------------------------------------------------
# follow_tls_stream output parsing (canned text)
# ---------------------------------------------------------------------------

# Server on 443 is Node 0; client is Node 1. Two client segments
# (tab-indented) and one server segment (non-indented).
_FOLLOW_SAMPLE = (
    "\n"
    "===================================================================\n"
    "Follow: tls,raw\n"
    "Filter: tls.stream eq 37\n"
    "Node 0: 157.240.27.35:443\n"
    "Node 1: 192.168.0.122:49283\n"
    "\t48656c6c6f\n"          # client -> server  "Hello"  (write)
    "576f726c64\n"           # server -> client  "World"  (read)
    "\t21\n"                 # client -> server  "!"      (write)
    "===================================================================\n"
)


def test_parse_follow_output_endpoints_and_segments():
    endpoints, segments = tshark_mod._parse_follow_output(_FOLLOW_SAMPLE)

    client_addr, client_port, server_addr, server_port = endpoints
    assert (client_addr, client_port) == ("192.168.0.122", 49283)
    assert (server_addr, server_port) == ("157.240.27.35", 443)

    assert segments == [
        ("write", b"Hello"),
        ("read", b"World"),
        ("write", b"!"),
    ]


def test_parse_follow_output_preserves_capture_order():
    _, segments = tshark_mod._parse_follow_output(_FOLLOW_SAMPLE)
    # Capture order: client, server, client — order must be preserved so the
    # parsers see bytes in the right sequence per direction.
    assert [d for d, _ in segments] == ["write", "read", "write"]


def test_parse_follow_output_empty_stream_no_endpoints():
    text = (
        "\n===================================================================\n"
        "Follow: tls,raw\n"
        "Filter: tls.stream eq 0\n"
        "Node 0: :0\n"
        "Node 1: :0\n"
        "===================================================================\n"
    )
    endpoints, segments = tshark_mod._parse_follow_output(text)
    assert segments == []


def test_parse_follow_output_server_chosen_by_smaller_port_when_no_443():
    text = (
        "Node 0: 10.0.0.5:8443\n"
        "Node 1: 10.0.0.9:51000\n"
        "\t41\n"   # Node 1 (client, higher port) -> write
        "42\n"     # Node 0 (server, lower port)  -> read
    )
    endpoints, segments = tshark_mod._parse_follow_output(text)
    client_addr, client_port, server_addr, server_port = endpoints
    assert (server_addr, server_port) == ("10.0.0.5", 8443)
    assert (client_addr, client_port) == ("10.0.0.9", 51000)
    assert segments == [("write", b"A"), ("read", b"B")]


def test_parse_follow_output_custom_tls_port_marks_server():
    text = (
        "Node 0: 10.0.0.9:51000\n"   # client
        "Node 1: 10.0.0.5:8443\n"    # server (custom tls port)
        "41\n"     # Node 0 (client) -> write
        "\t42\n"   # Node 1 (server) -> read
    )
    _, segments = tshark_mod._parse_follow_output(text, tls_ports=[8443])
    assert segments == [("write", b"A"), ("read", b"B")]


def test_parse_node_endpoint_ipv6_splits_on_last_colon():
    addr, port = tshark_mod._parse_node_endpoint("2606:2800:220::1:443")
    assert addr == "2606:2800:220::1"
    assert port == 443


def test_parse_node_endpoint_strips_ipv6_brackets():
    # tshark brackets IPv6 endpoints in follow output; the address must come back
    # unbracketed so its 4-tuple key matches the (unbracketed) ipv6.src field path.
    addr, port = tshark_mod._parse_node_endpoint(
        "[2600:9000:a507:ab6d:575d:9d9f:64af:7a5a]:443"
    )
    assert addr == "2600:9000:a507:ab6d:575d:9d9f:64af:7a5a"
    assert port == 443


def test_parse_node_endpoint_ipv4_unchanged():
    addr, port = tshark_mod._parse_node_endpoint("10.0.0.5:8443")
    assert addr == "10.0.0.5"
    assert port == 8443


def test_parse_follow_output_bracketed_ipv6_endpoints_unbracketed():
    text = (
        "Node 0: [2600:9000:a507:ab6d:575d:9d9f:64af:7a5a]:443\n"
        "Node 1: [2a01:599:327:4bae:55d4:8c51:f36c:ab6d]:60306\n"
        "\t0011\n"   # Node 1 (client) writes first -> client identified
        "2233\n"     # Node 0 (server) responds
    )
    endpoints, _ = tshark_mod._parse_follow_output(text, tls_ports=[443])
    client_addr, client_port, server_addr, server_port = endpoints
    assert client_addr == "2a01:599:327:4bae:55d4:8c51:f36c:ab6d"
    assert server_addr == "2600:9000:a507:ab6d:575d:9d9f:64af:7a5a"
    assert (client_port, server_port) == (60306, 443)


# ---------------------------------------------------------------------------
# _tls_segments_to_events
# ---------------------------------------------------------------------------

def test_tls_segments_to_events_directions_and_endpoints():
    endpoints = ("192.168.0.122", 49283, "157.240.27.35", 443)
    segments = [("write", b"req"), ("read", b"resp")]
    events = p2t._tls_segments_to_events(endpoints, segments)

    assert len(events) == 2
    write_ev, read_ev = events
    assert write_ev.direction == "write"
    assert write_ev.transport == "tcp"
    assert write_ev.ss_family == "AF_INET"
    assert (write_ev.src_addr, write_ev.src_port) == ("192.168.0.122", 49283)
    assert (write_ev.dst_addr, write_ev.dst_port) == ("157.240.27.35", 443)

    assert read_ev.direction == "read"
    assert (read_ev.src_addr, read_ev.src_port) == ("157.240.27.35", 443)
    assert (read_ev.dst_addr, read_ev.dst_port) == ("192.168.0.122", 49283)


def test_tls_segments_to_events_ipv6_family():
    endpoints = ("2001:db8::1", 49283, "2606:2800:220::1", 443)
    events = p2t._tls_segments_to_events(endpoints, [("write", b"x")])
    assert events[0].ss_family == "AF_INET6"


def test_tls_segments_to_events_skips_empty():
    endpoints = ("10.0.0.1", 1, "10.0.0.2", 443)
    events = p2t._tls_segments_to_events(endpoints, [("write", b"")])
    assert events == []


# ---------------------------------------------------------------------------
# _StreamDirectionTracker (still used for QUIC)
# ---------------------------------------------------------------------------

def test_direction_tracker_first_packet_is_write():
    tracker = p2t._StreamDirectionTracker()
    assert tracker.direction_for("udp:0", "10.0.0.1", 50000) == "write"


def test_direction_tracker_reverse_is_read():
    tracker = p2t._StreamDirectionTracker()
    tracker.direction_for("udp:0", "10.0.0.1", 50000)  # fix client
    assert tracker.direction_for("udp:0", "93.184.216.34", 443) == "read"
    assert tracker.direction_for("udp:0", "10.0.0.1", 50000) == "write"
    assert tracker.stream_count == 1


def test_direction_tracker_server_first_packet_labels_read(monkeypatch):
    """BUG #12: when the FIRST packet on a stream is server-originated (e.g. the
    capture starts mid-flow), direction must still be anchored to the server
    port, not to first-packet order."""
    tracker = p2t._StreamDirectionTracker()
    # First packet is FROM the server (src port 443) TO the client -> "read".
    assert tracker.direction_for(
        "udp:0", "93.184.216.34", 443, "10.0.0.1", 50000) == "read"
    # A subsequent client packet is then correctly "write".
    assert tracker.direction_for(
        "udp:0", "10.0.0.1", 50000, "93.184.216.34", 443) == "write"


def test_direction_tracker_custom_server_port_anchors_direction():
    """A configured --quic-port (non-443) anchors direction the same way."""
    tracker = p2t._StreamDirectionTracker(server_ports=(8443,))
    # Server-originated first packet on the custom port -> "read".
    assert tracker.direction_for(
        "udp:1", "203.0.113.5", 8443, "10.0.0.1", 50000) == "read"
    assert tracker.direction_for(
        "udp:1", "10.0.0.1", 50000, "203.0.113.5", 8443) == "write"


def test_quic_packet_server_first_packet_labels_read():
    """End-to-end through _quic_packet_to_events: a server-originated first
    packet (src port 443) is labelled "read", not "write"."""
    tracker = p2t._StreamDirectionTracker()
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ip_src": ["93.184.216.34"], "ip_dst": ["10.0.0.1"],
            "udp_stream": ["0"],
            "udp_srcport": ["443"], "udp_dstport": ["50000"],
            "quic_stream_stream_id": ["0"],
            "quic_stream_data": ["41"],
        }
    }
    events = p2t._quic_packet_to_events(pkt, tracker)
    assert len(events) == 1
    assert events[0].direction == "read"


# ---------------------------------------------------------------------------
# _quic_packet_to_events (canned -T ek dict; parallel stream lists)
# ---------------------------------------------------------------------------

def test_quic_packet_zips_parallel_stream_lists():
    tracker = p2t._StreamDirectionTracker()
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
            "udp_stream": ["2"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            # Two stream frames in one packet -> parallel lists.
            "quic_stream_stream_id": ["0", "4"],
            "quic_stream_data": ["41", "42"],  # "A", "B"
        }
    }
    events = p2t._quic_packet_to_events(pkt, tracker)
    assert len(events) == 2
    assert [(e.stream_id, e.data) for e in events] == [(0, b"A"), (4, b"B")]
    assert all(e.transport == "udp" for e in events)
    assert all(e.direction == "write" for e in events)  # first packet => client


def test_quic_packet_single_frame():
    tracker = p2t._StreamDirectionTracker()
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
            "udp_stream": ["2"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            "quic_stream_stream_id": ["4"],
            "quic_stream_data": ["41"],
        }
    }
    events = p2t._quic_packet_to_events(pkt, tracker)
    assert len(events) == 1
    assert events[0].stream_id == 4
    assert events[0].data == b"A"


def test_quic_packet_ipv6():
    tracker = p2t._StreamDirectionTracker()
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ipv6_src": ["2001:db8::1"], "ipv6_dst": ["2606:2800:220::1"],
            "udp_stream": ["0"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            "quic_stream_stream_id": ["0"],
            "quic_stream_data": ["41"],
        }
    }
    events = p2t._quic_packet_to_events(pkt, tracker)
    assert events[0].ss_family == "AF_INET6"
    assert events[0].data == b"A"


# ---------------------------------------------------------------------------
# _quic_packet_to_events misalignment guard (BUG #3: zip() truncation)
# ---------------------------------------------------------------------------

def test_quic_packet_mismatched_lengths_skips_and_counts(caplog):
    """A FIN-only STREAM frame can give more ids than payloads. zip() would
    silently truncate and mis-attribute; instead we skip + drop-count + warn."""
    tracker = p2t._StreamDirectionTracker()
    result = p2t.ConvertResult(tap_path="x.tap")
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
            "udp_stream": ["2"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            # Two stream ids but only one payload (e.g. one frame is FIN-only).
            "quic_stream_stream_id": ["0", "4"],
            "quic_stream_data": ["41"],  # only "A"
        }
    }
    # friTap's logger sets propagate=False once logging is configured, so
    # caplog's root handler never sees the record. Attach caplog's handler to
    # the module logger directly so the assertion is robust to suite ordering.
    module_logger = logging.getLogger(p2t.__name__)
    module_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level("WARNING", logger=p2t.__name__):
            events = p2t._quic_packet_to_events(pkt, tracker, result)
    finally:
        module_logger.removeHandler(caplog.handler)

    # No events emitted (would otherwise wrongly map payload "A" to stream 0).
    assert events == []
    assert result.dropped_packet_count == 1
    assert any("mismatch" in rec.message.lower() for rec in caplog.records)


def test_quic_packet_mismatched_lengths_skips_without_result():
    """The drop counter is optional; a missing result must not crash the skip."""
    tracker = p2t._StreamDirectionTracker()
    pkt = {
        "layers": {
            "udp_stream": ["2"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
            "quic_stream_stream_id": ["0", "4", "8"],
            "quic_stream_data": ["41"],
        }
    }
    assert p2t._quic_packet_to_events(pkt, tracker) == []


def test_quic_packet_matched_lengths_unchanged():
    """Behavior when lengths match must be identical to before the guard."""
    tracker = p2t._StreamDirectionTracker()
    result = p2t.ConvertResult(tap_path="x.tap")
    pkt = {
        "layers": {
            "frame_time_epoch": ["1700000000.0"],
            "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
            "udp_stream": ["2"],
            "udp_srcport": ["50000"], "udp_dstport": ["443"],
            "quic_stream_stream_id": ["0", "4"],
            "quic_stream_data": ["41", "42"],
        }
    }
    events = p2t._quic_packet_to_events(pkt, tracker, result)
    assert [(e.stream_id, e.data) for e in events] == [(0, b"A"), (4, b"B")]
    assert result.dropped_packet_count == 0


# ---------------------------------------------------------------------------
# End-to-end with mocked tshark boundary
# ---------------------------------------------------------------------------

def _hex(b: bytes) -> str:
    return b.hex()


def _tls_ek_packets(endpoints, segments, *, stream=0, t0=1700000000.0):
    """Build TLS single-pass ``-T ek`` packet dicts from follow-style segments.

    Mirrors what ``build_tls_command``'s export yields: one ``data.data`` frame
    per direction-tagged segment, addresses oriented by direction (write =
    client->server). Lets the old ``(endpoints, segments)`` fixtures drive the
    new single-pass path with no change to the test's data."""
    c_addr, c_port, s_addr, s_port = endpoints
    packets = []
    for i, (direction, data) in enumerate(segments):
        if direction == "write":
            src_a, src_p, dst_a, dst_p = c_addr, c_port, s_addr, s_port
        else:
            src_a, src_p, dst_a, dst_p = s_addr, s_port, c_addr, c_port
        packets.append({"layers": {
            "frame_time_epoch": [f"{t0 + i}"],
            "ip_src": [src_a], "ip_dst": [dst_a],
            "tcp_stream": [str(stream)],
            "tcp_srcport": [str(src_p)], "tcp_dstport": [str(dst_p)],
            "data_data": [data.hex()],
        }})
    return packets


def _tls_stream_dispatch(packets):
    """A ``stream_packets`` fake that returns *packets* for the TLS export
    command (identified by the ``data.data`` field) and nothing for the QUIC
    command — both transports now share the single-pass ``stream_packets``."""
    def fake(cmd):
        return iter(packets) if "data.data" in cmd else iter(())
    return fake


def test_convert_pcap_to_tap_end_to_end(tmp_path, monkeypatch):
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        b"Content-Type: text/plain\r\n\r\nhello"
    )

    endpoints = ("10.0.0.1", 50000, "93.184.216.34", 443)
    segments = [("write", request), ("read", response)]

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    # Single-pass TLS export: two data.data frames (request then response) on
    # tcp.stream 0; the QUIC command gets nothing.
    monkeypatch.setattr(p2t, "stream_packets",
                        _tls_stream_dispatch(_tls_ek_packets(endpoints, segments)))

    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"\x00")  # existence only; tshark is mocked
    keylog = tmp_path / "keys.log"
    keylog.write_text("")  # existence only; tshark is mocked
    tap = tmp_path / "capture.tap"

    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tap)
    )

    assert result.decrypted_packet_count == 2
    assert result.flow_count >= 1
    assert result.stream_count == 1
    assert tap.exists()

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()
    assert len(flows) >= 1
    flow = flows[0]
    assert flow.request is not None
    assert flow.request.method == "GET"
    assert flow.response is not None
    assert flow.response.status_code == 200


def test_tls_packet_to_events_concatenates_multi_record_frame():
    """#7: a single frame carrying several TLS records exposes data.data as a
    parallel list; the single-pass translator must concatenate them in order
    into ONE event so per-direction byte order is preserved for the parsers."""
    tracker = p2t._StreamDirectionTracker(server_ports=())
    pkt = {"layers": {
        "frame_time_epoch": ["1700000000.5"],
        "ip_src": ["10.0.0.1"], "ip_dst": ["93.184.216.34"],
        "tcp_stream": ["0"], "tcp_srcport": ["50000"], "tcp_dstport": ["443"],
        "data_data": [b"AB".hex(), b"CD".hex()],  # two records in one frame
    }}
    events = p2t._tls_packet_to_events(pkt, tracker)
    assert len(events) == 1
    ev = events[0]
    assert ev.data == b"ABCD"          # records joined in capture order
    assert ev.direction == "write"     # dst port 443 -> source is the client
    assert ev.transport == "tcp"
    assert ev.stream_id is None
    assert ev.timestamp == 1700000000.5


def test_tls_packet_to_events_direction_from_tracker():
    """#7: direction comes from the tracker (seeded with the server ports), so a
    server-originated frame (src port 443) is labelled "read"."""
    tracker = p2t._StreamDirectionTracker(server_ports=())
    pkt = {"layers": {
        "ip_src": ["93.184.216.34"], "ip_dst": ["10.0.0.1"],
        "tcp_stream": ["0"], "tcp_srcport": ["443"], "tcp_dstport": ["50000"],
        "data_data": [b"hi".hex()],
    }}
    ev = p2t._tls_packet_to_events(pkt, tracker)[0]
    assert ev.direction == "read"      # src port 443 -> server -> read


def test_convert_pcap_to_tap_quic_path(tmp_path, monkeypatch):
    """The QUIC -T ek pass alone should still produce events/flows."""
    h3_get = b"GET / HTTP/3\r\n"  # opaque to the test; just needs to be data

    def fake_stream(cmd):
        yield {
            "layers": {
                "frame_time_epoch": ["1700000000.0"],
                "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
                "udp_stream": ["0"],
                "udp_srcport": ["50000"], "udp_dstport": ["443"],
                "quic_stream_stream_id": ["0"],
                "quic_stream_data": [_hex(h3_get)],
            }
        }

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", fake_stream)

    pcap = tmp_path / "q.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")  # existence only; tshark is mocked
    tap = tmp_path / "q.tap"

    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tap)
    )
    assert result.decrypted_packet_count == 1
    assert result.stream_count == 1
    assert tap.exists()


def test_malformed_tls_packet_increments_dropped_packet_count(tmp_path, monkeypatch):
    """The single-pass TLS export drops per-PACKET, like QUIC: a packet that
    fails to translate increments dropped_packet_count and the conversion still
    completes. (The old per-stream follow model's dropped_stream_count no longer
    applies — there is no per-stream pass to fail; undecryptable streams simply
    never surface a data.data frame.)"""
    def boom(*a, **k):
        raise RuntimeError("boom: cannot translate this TLS packet")

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "_tls_packet_to_events", boom)
    # One TLS frame (triggers boom in the per-packet translator), no QUIC.
    one_tls = [{"layers": {
        "tcp_stream": ["0"], "data_data": ["41"],
        "ip_src": ["10.0.0.1"], "ip_dst": ["93.184.216.34"],
        "tcp_srcport": ["50000"], "tcp_dstport": ["443"],
    }}]
    monkeypatch.setattr(p2t, "stream_packets", _tls_stream_dispatch(one_tls))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tmp_path / "out.tap"))

    assert result.dropped_packet_count == 1  # the malformed TLS frame was dropped
    assert result.dropped_stream_count == 0  # no per-stream pass in single-pass mode


def test_quic_zip_mismatch_still_counts_as_dropped_packet(tmp_path, monkeypatch):
    """BUG #10 guard: the QUIC per-packet drop path keeps using
    dropped_packet_count (must not regress to dropped_stream_count)."""
    def fake_stream(cmd):
        yield {
            "layers": {
                "frame_time_epoch": ["1700000000.0"],
                "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
                "udp_stream": ["0"],
                "udp_srcport": ["50000"], "udp_dstport": ["443"],
                "quic_stream_stream_id": ["0", "4"],  # 2 ids
                "quic_stream_data": ["41"],            # 1 payload -> mismatch
            }
        }

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", fake_stream)

    pcap = tmp_path / "q.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tmp_path / "q.tap"))

    assert result.dropped_packet_count == 1
    assert result.dropped_stream_count == 0


def test_quic_stream_count_counts_distinct_streams_not_udp_conns(tmp_path, monkeypatch):
    """BUG #11: stream_count for QUIC must count distinct
    (udp.stream, quic stream_id) identities, not UDP 4-tuples. One UDP
    connection multiplexing three QUIC streams must report stream_count == 3."""
    def fake_stream(cmd):
        # All three frames ride the SAME udp.stream (==0) but distinct QUIC ids.
        yield {
            "layers": {
                "frame_time_epoch": ["1700000000.0"],
                "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
                "udp_stream": ["0"],
                "udp_srcport": ["50000"], "udp_dstport": ["443"],
                "quic_stream_stream_id": ["0", "4", "8"],
                "quic_stream_data": [_hex(b"a"), _hex(b"b"), _hex(b"c")],
            }
        }
        # A repeat of stream id 0 on the same connection must NOT be recounted.
        yield {
            "layers": {
                "frame_time_epoch": ["1700000001.0"],
                "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
                "udp_stream": ["0"],
                "udp_srcport": ["50000"], "udp_dstport": ["443"],
                "quic_stream_stream_id": ["0"],
                "quic_stream_data": [_hex(b"d")],
            }
        }

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", fake_stream)

    pcap = tmp_path / "q.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tmp_path / "q.tap"))

    # 3 distinct QUIC streams on a SINGLE UDP connection -> stream_count == 3.
    assert result.stream_count == 3


def test_convert_pcap_to_tap_no_data_still_writes_tap(tmp_path, monkeypatch):
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))

    pcap = tmp_path / "empty.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")  # decryptable precondition satisfied; just no traffic
    result = p2t.convert_pcap_to_tap(str(pcap), keylog_path=str(keylog))

    assert result.decrypted_packet_count == 0
    assert result.flow_count == 0
    assert (tmp_path / "empty.tap").exists()


# ---------------------------------------------------------------------------
# Manifest merge (cli)
# ---------------------------------------------------------------------------

def _ns(**kw) -> argparse.Namespace:
    base = dict(
        keylog=None, tls_ports=[], quic_ports=[], decode_as=[], tls_heuristic=False,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def test_manifest_load_and_merge_supplies_values(tmp_path):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    manifest = tmp_path / "cap.pcapng.fritap.json"
    manifest.write_text(json.dumps({
        "tls_ports": [8443], "quic_ports": [8443], "keylog": "/tmp/keys.log",
    }))

    loaded = offline_cli.load_manifest(str(pcap))
    merged = offline_cli.merge_manifest(_ns(), loaded)

    assert merged["tls_ports"] == (8443,)
    assert merged["quic_ports"] == (8443,)
    assert merged["keylog_path"] == "/tmp/keys.log"


def test_manifest_cli_flags_take_precedence(tmp_path):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    manifest = tmp_path / "cap.pcapng.fritap.json"
    manifest.write_text(json.dumps({
        "tls_ports": [8443], "keylog": "/tmp/manifest_keys.log",
    }))

    loaded = offline_cli.load_manifest(str(pcap))
    merged = offline_cli.merge_manifest(
        _ns(tls_ports=[9999], keylog="/tmp/cli_keys.log"), loaded
    )

    assert merged["tls_ports"] == (9999,)
    assert merged["keylog_path"] == "/tmp/cli_keys.log"


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_manifest_keylogs_map_wins_over_wrong_toplevel(tmp_path):
    """Regression: a multi-protocol (signal) capture splits the -k keylog, but the
    manifest's top-level ``signal_keylog`` historically held the BASE/TLS path.
    The authoritative ``keylogs`` map must win so Signal decrypt gets its own keys
    (the bug: signal_keylog pointed at the TLS log -> 0 Signal messages)."""
    pcap = tmp_path / "s.pcap"
    pcap.write_bytes(b"\x00")
    manifest = tmp_path / "s.pcap.fritap.json"
    manifest.write_text(json.dumps({
        "keylog": "skeys.tls.log",
        "signal_keylog": "skeys.tls.log",          # WRONG top-level (base/TLS path)
        "keylogs": {"signal": "skeys.signal.log", "tls": "skeys.tls.log"},
    }))

    loaded = offline_cli.load_manifest(str(pcap))
    merged = offline_cli.merge_manifest(_ns(), loaded)

    assert merged["signal_keylog"] == "skeys.signal.log"
    assert merged["protocol_keylogs"]["signal"] == "skeys.signal.log"


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_manifest_explicit_signal_keylog_beats_keylogs_map(tmp_path):
    """Explicit --signal-keylog still wins over the manifest keylogs map."""
    pcap = tmp_path / "s.pcap"
    pcap.write_bytes(b"\x00")
    manifest = tmp_path / "s.pcap.fritap.json"
    manifest.write_text(json.dumps({
        "keylogs": {"signal": "skeys.signal.log"},
    }))

    loaded = offline_cli.load_manifest(str(pcap))
    merged = offline_cli.merge_manifest(_ns(signal_keylog="/cli/explicit.log"), loaded)

    assert merged["signal_keylog"] == "/cli/explicit.log"


def test_manifest_missing_returns_empty(tmp_path):
    pcap = tmp_path / "nomanifest.pcapng"
    pcap.write_bytes(b"\x00")
    assert offline_cli.load_manifest(str(pcap)) == {}


# ---------------------------------------------------------------------------
# DSB detection (capture_has_dsb)
# ---------------------------------------------------------------------------

def _classic_pcap_header() -> bytes:
    """Minimal classic .pcap file header (us-resolution, little-endian).

    Classic pcap cannot embed TLS secrets, so capture_has_dsb must return False.
    """
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcapng_block(type_id: int, body: bytes) -> bytes:
    """Wrap *body* in a pcapng block: type, total length, body, total length."""
    total = 8 + len(body) + 4
    return struct.pack("<II", type_id, total) + body + struct.pack("<I", total)


def _pcapng_with_dsb() -> bytes:
    """Minimal pcapng: a Section Header Block followed by a (empty) DSB.

    Lets capture_has_dsb be tested without shipping a binary fixture.
    """
    shb_body = struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    dsb_body = struct.pack("<I", 0x544C534B) + struct.pack("<I", 0)  # TLSK, len 0
    return _pcapng_block(0x0A0D0D0A, shb_body) + _pcapng_block(0x0000000A, dsb_body)


def test_capture_has_dsb_false_for_classic_pcap(tmp_path):
    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    assert tshark_mod.capture_has_dsb(str(pcap)) is False


def test_capture_has_dsb_true_for_pcapng_with_dsb(tmp_path):
    pcap = tmp_path / "dsb.pcapng"
    pcap.write_bytes(_pcapng_with_dsb())
    assert tshark_mod.capture_has_dsb(str(pcap)) is True


def test_capture_has_dsb_false_for_pcapng_without_dsb(tmp_path):
    # SHB only, no DSB block — self-decryption not possible.
    pcap = tmp_path / "nodsb.pcapng"
    full = _pcapng_with_dsb()
    shb_total = struct.unpack_from("<I", full, 4)[0]
    pcap.write_bytes(full[:shb_total])  # keep only the SHB
    assert tshark_mod.capture_has_dsb(str(pcap)) is False


# ---------------------------------------------------------------------------
# Keyless behavior: no --keylog at all => ingest as plaintext; an explicitly
# given but missing keylog still fails loud (don't mask a typo'd path).
# ---------------------------------------------------------------------------

def test_classic_pcap_without_keys_ingests_as_plaintext(tmp_path, monkeypatch):
    """A capture with NO --keylog and no DSB is no longer an error: it is treated
    as already-plaintext and the raw transport payload is ingested. With no
    packets the conversion simply yields an empty .tap (no raise)."""
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))

    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    result = p2t.convert_pcap_to_tap(str(pcap), tap_path=str(tmp_path / "out.tap"))
    assert result.flow_count == 0
    assert result.decrypted_packet_count == 0


def test_missing_keylog_file_fails_loud(tmp_path):
    """An EXPLICIT --keylog whose file does not exist (and no DSB) still errors,
    so a typo'd keylog path is not silently masked as a plaintext capture."""
    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    with pytest.raises(p2t.NoDecryptionKeysError):
        p2t.convert_pcap_to_tap(str(pcap), keylog_path=str(tmp_path / "nope.log"))


def test_pcapng_with_dsb_needs_no_keylog(tmp_path, monkeypatch):
    """A DSB-embedded pcapng satisfies the precondition without a keylog."""
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))

    pcap = tmp_path / "dsb.pcapng"
    pcap.write_bytes(_pcapng_with_dsb())
    result = p2t.convert_pcap_to_tap(str(pcap), tap_path=str(tmp_path / "out.tap"))
    assert result.flow_count == 0  # no traffic, but the guard let it proceed


def test_cli_no_keys_no_dsb_ingests_plaintext_empty(tmp_path, monkeypatch, capsys):
    """No --keylog and no DSB now ingests as plaintext. An empty capture yields no
    plaintext data, so the CLI returns exit 4 with the generic no-data warning."""
    monkeypatch.setattr(offline_cli, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))
    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    rc = offline_cli.run_offline_pcap_to_tap(["--from-pcap", str(pcap)])
    assert rc == 4
    assert "no application data" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Plaintext (keyless) ingestion of an already-cleartext capture
# ---------------------------------------------------------------------------

def _plaintext_ek_packets(endpoints, segments, *, stream=0, transport="tcp",
                          protocols="eth:ethertype:ip:tcp", t0=1700000000.0,
                          tls_content_type=None, quic_header_form=None):
    """Build raw-payload ``-T ek`` packet dicts mirroring build_plaintext_command.

    One ``<transport>.payload`` frame per direction-tagged segment; *protocols*
    is the frame.protocols stack. Marking a stream as *genuinely* encrypted now
    requires BOTH a "tls"/"quic" entry in *protocols* AND a corroborating record
    marker: pass *tls_content_type* (e.g. "23") or *quic_header_form* (e.g. "1")
    to populate ``tls.record.content_type`` / ``quic.header_form`` so the
    translator skips the stream. A "tls"/"quic" stack with no marker mimics
    tshark heuristically mislabeling decrypted plaintext and is ingested."""
    c_addr, c_port, s_addr, s_port = endpoints
    packets = []
    for i, (direction, data) in enumerate(segments):
        if direction == "write":
            src_a, src_p, dst_a, dst_p = c_addr, c_port, s_addr, s_port
        else:
            src_a, src_p, dst_a, dst_p = s_addr, s_port, c_addr, c_port
        layers = {
            "frame_time_epoch": [f"{t0 + i}"],
            "frame_protocols": [protocols],
            "ip_src": [src_a], "ip_dst": [dst_a],
            f"{transport}_stream": [str(stream)],
            f"{transport}_srcport": [str(src_p)], f"{transport}_dstport": [str(dst_p)],
            f"{transport}_payload": [data.hex()],
        }
        if tls_content_type is not None:
            layers["tls_record_content_type"] = [str(tls_content_type)]
        if quic_header_form is not None:
            layers["quic_header_form"] = [str(quic_header_form)]
        packets.append({"layers": layers})
    return packets


def _plaintext_stream_dispatch(packets):
    """A ``stream_packets`` fake returning *packets* for the plaintext export
    command (identified by the ``tcp.payload`` field) and nothing otherwise."""
    def fake(cmd):
        return iter(packets) if "tcp.payload" in cmd else iter(())
    return fake


def test_plaintext_packet_to_events_parses_cleartext_tcp():
    """A cleartext TCP frame (no tls/quic in frame.protocols) yields one event
    carrying the raw payload, direction anchored on the server port."""
    tracker = p2t._StreamDirectionTracker(server_ports=(80,))
    skipped: set[str] = set()
    pkt = _plaintext_ek_packets(
        ("10.0.0.1", 50000, "93.184.216.34", 80),
        [("write", b"GET / HTTP/1.1\r\n")],
    )[0]
    events = p2t._plaintext_packet_to_events(pkt, tracker, skipped)
    assert len(events) == 1
    ev = events[0]
    assert ev.data == b"GET / HTTP/1.1\r\n"
    assert ev.transport == "tcp"
    assert ev.direction == "write"   # dst port 80 -> source is the client
    assert not skipped


def test_plaintext_packet_to_events_skips_encrypted_stream():
    """A 'tls' frame that ALSO carries a parsed record (tls.record.content_type)
    is genuinely encrypted: it produces no event and the stream is recorded for
    the 'needs keys' hint."""
    tracker = p2t._StreamDirectionTracker(server_ports=(443,))
    skipped: set[str] = set()
    pkt = _plaintext_ek_packets(
        ("10.0.0.1", 50000, "93.184.216.34", 443),
        [("write", b"\x16\x03\x01encryptedrecord")],
        protocols="eth:ethertype:ip:tcp:tls",
        tls_content_type="23",  # application_data: a real TLS record was parsed
    )[0]
    assert p2t._plaintext_packet_to_events(pkt, tracker, skipped) == []
    assert skipped == {"tcp:0"}


def test_plaintext_packet_to_events_ingests_mislabeled_tls_plaintext():
    """A 'tls'-tagged frame with NO parsed TLS record is decrypted plaintext that
    tshark's heuristic dissector mislabeled (e.g. an HTTP/2 frame on port 443). It
    must be ingested, not skipped, so real data is not dropped."""
    tracker = p2t._StreamDirectionTracker(server_ports=(443,))
    skipped: set[str] = set()
    # HTTP/2 SETTINGS frame: len=6, type=0x04, on stream 0 — no TLS record header.
    h2_settings = bytes.fromhex("000006040000000000000401000000")
    pkt = _plaintext_ek_packets(
        ("10.0.0.1", 50000, "93.184.216.34", 443),
        [("write", h2_settings)],
        protocols="eth:ethertype:ip:tcp:tls",  # heuristic mislabel, no content_type
    )[0]
    events = p2t._plaintext_packet_to_events(pkt, tracker, skipped)
    assert len(events) == 1
    assert events[0].data == h2_settings
    assert not skipped


def test_convert_pcap_plaintext_end_to_end(tmp_path, monkeypatch):
    """Keyless conversion of an already-cleartext HTTP capture reconstructs the
    request/response into a flow and writes a readable .tap."""
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        b"Content-Type: text/plain\r\n\r\nhello"
    )
    endpoints = ("10.0.0.1", 50000, "93.184.216.34", 80)
    segments = [("write", request), ("read", response)]

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(
        p2t, "stream_packets",
        _plaintext_stream_dispatch(_plaintext_ek_packets(endpoints, segments)))

    pcap = tmp_path / "cleartext.pcap"
    pcap.write_bytes(_classic_pcap_header())  # classic pcap: no DSB
    tap = tmp_path / "cleartext.tap"

    result = p2t.convert_pcap_to_tap(str(pcap), tap_path=str(tap))

    assert result.decrypted_packet_count == 2
    assert result.flow_count >= 1
    assert result.stream_count == 1
    assert result.encrypted_streams_skipped == 0
    assert tap.exists()

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()
    assert len(flows) >= 1
    flow = flows[0]
    assert flow.request is not None
    assert flow.request.method == "GET"
    assert flow.response is not None
    assert flow.response.status_code == 200


def test_convert_pcap_plaintext_skips_encrypted_and_reports(tmp_path, monkeypatch):
    """A keyless capture made only of TLS streams produces no plaintext and
    reports the skipped encrypted streams so the CLI can hint for --keylog."""
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    packets = _plaintext_ek_packets(
        ("10.0.0.1", 50000, "93.184.216.34", 443),
        [("write", b"\x16\x03\x01abc"), ("read", b"\x16\x03\x03def")],
        protocols="eth:ethertype:ip:tcp:tls",
        tls_content_type="22",  # handshake: genuine TLS records were parsed
    )
    monkeypatch.setattr(p2t, "stream_packets", _plaintext_stream_dispatch(packets))

    pcap = tmp_path / "enc.pcap"
    pcap.write_bytes(_classic_pcap_header())
    result = p2t.convert_pcap_to_tap(str(pcap), tap_path=str(tmp_path / "enc.tap"))

    assert result.decrypted_packet_count == 0
    assert result.encrypted_streams_skipped == 1


# ---------------------------------------------------------------------------
# Hermetic tshark invocation (isolated WIRESHARK_CONFIG_DIR)
# ---------------------------------------------------------------------------

def _assert_isolated_config(env: dict) -> None:
    assert env is not None, "tshark must be spawned with an explicit env"
    cfg = env.get("WIRESHARK_CONFIG_DIR")
    assert cfg, "WIRESHARK_CONFIG_DIR must be set to isolate the profile"
    assert os.path.isdir(cfg) and os.listdir(cfg) == [], \
        "config dir must be an empty directory (no ambient keylog)"


def test_run_capture_spawns_tshark_with_isolated_config(monkeypatch):
    captured: dict = {}

    class _FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        return _FakeProc()

    monkeypatch.setattr(tshark_mod.subprocess, "run", fake_run)
    tshark_mod._run_capture(["tshark", "-v"])
    _assert_isolated_config(captured["env"])


def test_stream_packets_spawns_tshark_with_isolated_config(monkeypatch):
    captured: dict = {}

    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            self.stdout = iter(())
            self.stderr = iter(())

        def wait(self):
            return 0

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _FakePopen)
    list(tshark_mod.stream_packets(["tshark", "-T", "ek"]))
    _assert_isolated_config(captured["env"])


# ---------------------------------------------------------------------------
# Real-tshark semantic integration (hermetic premaster fixture)
# ---------------------------------------------------------------------------

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PREMASTER_PCAP = os.path.join(_FIXTURE_DIR, "dump_premaster.pcapng")
_PREMASTER_KEYLOG = os.path.join(_FIXTURE_DIR, "premaster.txt")
# Real app-api QUIC capture whose decrypted HTTP/2 frames tshark mislabels as
# "tls" on TCP/443 (no DSB, no keys). Regression guard for the keyless classifier.
_H2_PLAINTEXT_PCAP = os.path.join(_FIXTURE_DIR, "weather6_apiapi_h2_plaintext.pcapng")
# Real encrypted Chrome QUIC (no keys); DLT_RAW so QUIC only dissects with an explicit Decode-As.
_QUIC_ENCRYPTED_PCAP = os.path.join(_FIXTURE_DIR, "chrome_quic_encrypted.pcapng")


def _fixtures_available(*paths: str) -> bool:
    """True when a real tshark binary exists and every fixture *path* is present.
    Gates the integration tests so they skip cleanly without tshark/fixtures."""
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return all(os.path.isfile(p) for p in paths)


def _premaster_available() -> bool:
    return _fixtures_available(_PREMASTER_PCAP, _PREMASTER_KEYLOG)


def _h2_plaintext_available() -> bool:
    return _fixtures_available(_H2_PLAINTEXT_PCAP)


def _quic_encrypted_available() -> bool:
    return _fixtures_available(_QUIC_ENCRYPTED_PCAP)


@pytest.mark.skipif(not _premaster_available(),
                    reason="real tshark binary or premaster fixture unavailable")
def test_real_tshark_premaster_decrypts_http_semantics(tmp_path):
    """End-to-end on a real capture with an explicit keylog. Asserts decoded
    *meaning* (method/status/url), which is what catches both ciphertext fed to
    the parser and HPACK desync — failures a "a flow exists" check would miss.

    Runs hermetically: the isolated WIRESHARK_CONFIG_DIR means decryption
    depends only on the keylog we pass, not on any ambient Wireshark profile.
    The fixture is an openssl ``s_server`` HTTP/1.0 capture, so requests carry
    no Host header (host is asserted in the synthetic HPACK tests instead)."""
    tap = tmp_path / "premaster.tap"
    result = p2t.convert_pcap_to_tap(
        _PREMASTER_PCAP, keylog_path=_PREMASTER_KEYLOG, tap_path=str(tap)
    )

    assert tap.exists()
    assert result.decrypted_packet_count > 0, "nothing decrypted — keylog ignored?"

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()

    requests = [f for f in flows if f.request and f.request.method]
    assert requests, "no decrypted HTTP requests recovered"
    assert any(f.request.method == "GET" for f in requests)
    assert any(f.request.url == "/" for f in requests)

    statuses = {f.response.status_code for f in flows if f.response}
    assert 200 in statuses, f"expected a 200 response, got {statuses}"


@pytest.mark.skipif(not _h2_plaintext_available(),
                    reason="real tshark binary or h2-plaintext fixture unavailable")
def test_real_tshark_keyless_ingests_mislabeled_h2_plaintext(tmp_path):
    """Regression: a keyless app-api capture (no DSB, no keylog) whose decrypted
    HTTP/2 frames tshark heuristically tags 'tls' on TCP/443 must NOT be reported
    as encrypted/skipped. Before the fix, 3 streams were skipped and the HTTP/2
    HEADERS (carrying 'application/json') were dropped from the .tap."""
    tap = tmp_path / "h2_plaintext.tap"
    result = p2t.convert_pcap_to_tap(_H2_PLAINTEXT_PCAP, tap_path=str(tap))

    assert tap.exists()
    # The whole point: zero false-positive encrypted streams (was 3).
    assert result.encrypted_streams_skipped == 0
    # The previously-skipped HTTP/2 frames are now ingested (was 25 → all 33).
    assert result.decrypted_packet_count > 25

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()
    # The recovered HTTP/2 HEADERS frame carries a literal 'application/json'
    # content-type in its HPACK block — proof the dropped data is now present.
    blob = b"".join(c.data for f in flows for c in (f.chunks or []))
    assert b"application/json" in blob


@pytest.mark.skipif(not _quic_encrypted_available(),
                    reason="real tshark binary or encrypted-QUIC fixture unavailable")
def test_real_tshark_quic_marker_calibration():
    """Calibrate the QUIC "encrypted record" marker against a real capture.

    Wireshark renames dissector fields between releases, so this asserts that a
    living tshark still emits the exact field the predicate keys on
    (``quic.header_form``, read from the shared ``ENCRYPTED_RECORD_MARKERS``
    constant so the test follows the constant if it ever changes) AND that
    ``_is_encrypted_record`` actually fires on genuinely-encrypted QUIC.

    The fixture is a DLT_RAW capture (``raw:ip:udp:data``): tshark does NOT
    dissect it as QUIC by default — ``quic.header_form`` stays empty unless we
    pass the Decode-As ``-d udp.port==443,quic`` (the same mapping the real QUIC
    path uses). We therefore add that Decode-As here so QUIC dissects and the
    marker populates. Note plainly: the keyless ``build_plaintext_command`` does
    NOT add this Decode-As, so this test calibrates the marker field name and the
    predicate as they behave when QUIC dissection is enabled.
    """
    quic_marker = dict(tshark_mod.ENCRYPTED_RECORD_MARKERS)["quic"]

    tshark_bin = tshark_mod.find_tshark()
    cmd = [
        tshark_bin, "-r", _QUIC_ENCRYPTED_PCAP, "-2", "-T", "ek",
        "-d", "udp.port==443,quic",
        "-e", "frame.protocols", "-e", quic_marker, "-e", "udp.stream",
    ]

    packets = list(tshark_mod.stream_packets(cmd))
    assert packets, "tshark produced no packets for the encrypted-QUIC fixture"

    marker_seen = False
    fired = False
    for p in packets:
        layers = p.get("layers") or {}
        proto_layers = str(
            p2t._first(p2t._field(layers, "frame.protocols")) or ""
        ).lower().split(":")
        if "quic" in proto_layers and p2t._first(p2t._field(layers, quic_marker)) is not None:
            marker_seen = True
        if "quic" in proto_layers and p2t._is_encrypted_record(layers, proto_layers):
            fired = True

    assert marker_seen, (
        f"tshark no longer emits {quic_marker!r} on dissected QUIC — calibration drift"
    )
    assert fired, (
        "_is_encrypted_record did not classify genuine encrypted QUIC as encrypted"
    )


# ---------------------------------------------------------------------------
# Handshake-anchored encrypted-QUIC detection for the KEYLESS plaintext path
# ---------------------------------------------------------------------------


def test_build_quic_detection_command_argv_shape():
    """The detection-command builder produces the expected ``-T ek`` argv: the
    core flags, the default ``udp.port==443,quic`` Decode-As, ``udp.stream`` as
    the only exported field, and the conservative handshake-marker display
    filter. Custom ports and raw decode-as rules pass through too."""
    cmd = tshark_mod.build_quic_detection_command("cap.pcapng")

    # Core invocation shape, in order.
    assert cmd[:6] == ["tshark", "-r", "cap.pcapng", "-2", "-T", "ek"]
    # Default Decode-As (no explicit ports) maps UDP/443 to QUIC.
    assert "udp.port==443,quic" in cmd
    # The udp.stream field is exported (so streams can be keyed).
    assert _consecutive(cmd, "-e", "udp.stream")
    # The display filter is the shared zero-false-positive handshake marker.
    assert _consecutive(cmd, "-Y", tshark_mod._QUIC_DETECTION_DISPLAY_FILTER)

    # Custom QUIC ports add their own Decode-As rule.
    cmd_custom = tshark_mod.build_quic_detection_command(
        "cap.pcapng", quic_ports=[8443])
    assert "udp.port==8443,quic" in cmd_custom

    # Raw extra Decode-As rules pass through verbatim.
    cmd_extra = tshark_mod.build_quic_detection_command(
        "cap.pcapng", extra_decode_as=["udp.port==9000,quic"])
    assert "udp.port==9000,quic" in cmd_extra


def test_plaintext_packet_to_events_skips_handshake_confirmed_quic_stream():
    """A bare UDP packet (no per-packet TLS/QUIC record marker) is skipped when
    its stream was confirmed as genuine QUIC by the handshake pre-scan: it
    yields no event and the stream is recorded for the 'needs keys' hint. The
    SAME packet with an empty confirmed-set and no marker is ingested."""
    tracker = p2t._StreamDirectionTracker(server_ports=(443,))

    # udp.stream 7, plain UDP stack (no quic.header_form / tls marker) — only the
    # handshake pre-scan can flag this opaque 1-RTT-style packet as encrypted.
    pkt = _plaintext_ek_packets(
        ("10.0.0.1", 50000, "93.184.216.34", 443),
        [("write", b"\x40opaque-1rtt-bytes")],
        stream=7, transport="udp", protocols="eth:ethertype:ip:udp",
    )[0]

    skipped: set[str] = set()
    assert p2t._plaintext_packet_to_events(
        pkt, tracker, skipped,
        encrypted_quic_streams=frozenset({"udp:7"})) == []
    assert "udp:7" in skipped

    # Contrast: without the confirmed-set and with no record marker, the very
    # same opaque UDP payload is ingested as plaintext (one event, not skipped).
    not_skipped: set[str] = set()
    events = p2t._plaintext_packet_to_events(
        pkt, tracker, not_skipped, encrypted_quic_streams=frozenset())
    assert len(events) == 1
    assert events[0].transport == "udp"
    assert not_skipped == set()


def test_detect_encrypted_quic_streams_parses_udp_stream_ids(monkeypatch):
    """``_detect_encrypted_quic_streams`` turns the detection pass's per-packet
    ``udp.stream`` values into a ``udp:<id>`` frozenset, and degrades to an empty
    frozenset when the underlying stream_packets call raises."""
    detection_packets = [
        {"layers": {"udp_stream": ["3"]}},
        {"layers": {"udp_stream": ["5"]}},
    ]
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(detection_packets))

    streams = p2t._detect_encrypted_quic_streams(
        "/usr/bin/tshark", "cap.pcapng",
        quic_ports=(), extra_decode_as=(), heuristic=False)
    assert streams == frozenset({"udp:3", "udp:5"})

    # Detection failure is non-fatal: a raising stream_packets yields empty set.
    def _boom(cmd):
        raise RuntimeError("tshark blew up")
    monkeypatch.setattr(p2t, "stream_packets", _boom)

    assert p2t._detect_encrypted_quic_streams(
        "/usr/bin/tshark", "cap.pcapng",
        quic_ports=(), extra_decode_as=(), heuristic=False) == frozenset()


def _craft_quic_v1_initial_payload() -> bytes:
    """Return a long-header QUIC v1 Initial UDP payload tshark recognizes.

    First byte ``0xC3`` = long header, fixed bit, Initial packet type; then the
    32-bit cleartext version (``0x00000001`` = QUIC v1), an 8-byte DCID, empty
    SCID, empty token, a 2-byte length, packet number and padded payload. The
    version field is NOT under header protection, so this is the exact key-free
    signal the detection filter anchors on."""
    return (bytes([0xC3]) + struct.pack(">I", 0x00000001)
            + bytes([8]) + b"\xde\xad\xbe\xef\xca\xfe\x00\x01"
            + bytes([0]) + bytes([0]) + b"\x44\x10" + b"\x00\x00\x00\x00"
            + b"\x00" * 40)


@pytest.mark.skipif(not _fixtures_available(),
                    reason="real tshark binary unavailable")
def test_detect_encrypted_quic_streams_real_tshark(tmp_path):
    """INTEGRATION: a crafted QUIC v1 Initial is detected (every returned key
    starts with ``udp:``), while a plain non-QUIC UDP datagram is NOT — no false
    positive. Exercises the real detection pass through tshark end-to-end."""
    scapy_all = pytest.importorskip("scapy.all")
    IP, UDP, Raw, wrpcap = (
        scapy_all.IP, scapy_all.UDP, scapy_all.Raw, scapy_all.wrpcap)

    # Positive: a genuine QUIC v1 Initial long-header packet.
    quic_pcap = tmp_path / "quic_initial.pcap"
    quic_pkt = (IP(src="10.0.0.1", dst="2.2.2.2")
                / UDP(sport=50000, dport=443)
                / Raw(_craft_quic_v1_initial_payload()))
    wrpcap(str(quic_pcap), [quic_pkt])

    streams = p2t._detect_encrypted_quic_streams(
        tshark_mod.find_tshark(), str(quic_pcap),
        quic_ports=(), extra_decode_as=(), heuristic=False)
    assert streams, "the crafted QUIC v1 Initial was not detected"
    assert all(s.startswith("udp:") for s in streams)

    # Negative: a plain non-QUIC UDP datagram must yield no false positive.
    plain_pcap = tmp_path / "plain_udp.pcap"
    plain_pkt = (IP(src="10.0.0.1", dst="2.2.2.2")
                 / UDP(sport=51111, dport=53)
                 / Raw(b"hello-plaintext-not-quic"))
    wrpcap(str(plain_pcap), [plain_pkt])

    assert p2t._detect_encrypted_quic_streams(
        tshark_mod.find_tshark(), str(plain_pcap),
        quic_ports=(), extra_decode_as=(), heuristic=False) == frozenset()


@pytest.mark.skipif(not _fixtures_available(),
                    reason="real tshark binary unavailable")
def test_convert_keyless_skips_encrypted_quic_ingests_plaintext(tmp_path):
    """INTEGRATION end-to-end: a keyless capture mixing a genuine QUIC v1
    connection (Initial handshake + opaque 1-RTT follow-ups) with a plaintext UDP
    datagram on a different 5-tuple must skip the QUIC stream (counted as
    encrypted) and ingest only the plaintext packet — proving the handshake
    pre-scan stops cipher-text being ingested as bogus plaintext."""
    scapy_all = pytest.importorskip("scapy.all")
    IP, UDP, Raw, wrpcap = (
        scapy_all.IP, scapy_all.UDP, scapy_all.Raw, scapy_all.wrpcap)

    # QUIC connection on 10.0.0.1:50000 <-> 2.2.2.2:443 — an Initial that the
    # detector recognizes, plus two opaque follow-up packets on the SAME 5-tuple
    # (these carry no per-packet marker; only the handshake pre-scan flags them).
    quic_initial = (IP(src="10.0.0.1", dst="2.2.2.2")
                    / UDP(sport=50000, dport=443)
                    / Raw(_craft_quic_v1_initial_payload()))
    quic_followup = (IP(src="10.0.0.1", dst="2.2.2.2")
                     / UDP(sport=50000, dport=443)
                     / Raw(b"\x40" + b"\x99" * 200))
    # Plaintext UDP on a DIFFERENT 5-tuple — must be ingested.
    plaintext = (IP(src="10.0.0.1", dst="9.9.9.9")
                 / UDP(sport=51111, dport=53)
                 / Raw(b"hello-plaintext-udp"))

    pcap = tmp_path / "mixed.pcap"
    wrpcap(str(pcap), [quic_initial, quic_followup, quic_followup, plaintext])

    tap = tmp_path / "mixed.tap"
    result = p2t.convert_pcap_to_tap(str(pcap), tap_path=str(tap))

    assert result.encrypted_streams_skipped == 1, \
        "the genuine QUIC stream was not skipped as encrypted"
    assert result.decrypted_packet_count == 1, \
        "exactly the one plaintext UDP datagram should have been ingested"
    assert tap.exists()


# ---------------------------------------------------------------------------
# Public API: convert_pcap_to_tap / ConvertResult identity + serialization
# ---------------------------------------------------------------------------

import importlib as _importlib  # noqa: E402

# Reach the pcap_to_tap *submodule* unambiguously. The public wrapper
# ``pcap_to_tap`` *function* lives INSIDE this submodule (and is re-exported at
# the package root as ``friTap.pcap_to_tap``); it is deliberately NOT bound in
# friTap/offline/__init__.py so it does not shadow the same-named submodule
# attribute. importlib.import_module always returns the module object, and
# ``_p2t_mod.pcap_to_tap`` is the wrapper function.
_p2t_mod = _importlib.import_module("friTap.offline.pcap_to_tap")


def test_convert_symbols_identity_from_top_level_package():
    """The offline symbols are the SAME objects when imported from ``friTap``."""
    import friTap

    assert friTap.convert_pcap_to_tap is _p2t_mod.convert_pcap_to_tap
    assert friTap.ConvertResult is _p2t_mod.ConvertResult
    assert friTap.NoDecryptionKeysError is _p2t_mod.NoDecryptionKeysError


def test_convert_result_to_dict_roundtrips_all_fields():
    """ConvertResult.to_dict() exposes all fields and is JSON-serializable.

    The generic ``per_protocol`` map is the cross-protocol counter view; the
    only legacy named counters that survive are the public MTProto ones (any
    other protocol's counters live solely under ``per_protocol``).
    """
    result = _p2t_mod.ConvertResult(
        tap_path="out.tap",
        flow_count=3,
        decrypted_packet_count=10,
        stream_count=2,
        dropped_packet_count=1,
        dropped_stream_count=4,
        findings_count=5,
        encrypted_streams_skipped=6,
    )
    d = result.to_dict()

    expected = {
        "tap_path": "out.tap",
        "flow_count": 3,
        "decrypted_packet_count": 10,
        "stream_count": 2,
        "dropped_packet_count": 1,
        "dropped_stream_count": 4,
        "findings_count": 5,
        "encrypted_streams_skipped": 6,
        # MTProto counters (default 0 here; exercised in the MTProto e2e tests).
        "mtproto_messages": 0,
        "mtproto_streams": 0,
        "mtproto_records_undecryptable": 0,
        "mtproto_streams_degraded": 0,
        # Protocol-generic counters (empty here; populated by registry-driven
        # decryptors via ConvertResult.record_protocol).
        "per_protocol": {},
    }
    assert d == expected
    assert len(d) == 13
    # Round-trips through JSON cleanly.
    assert json.loads(json.dumps(d)) == expected


# ---------------------------------------------------------------------------
# Public API: pcap_to_tap manifest-merge precedence (monkeypatched, no tshark)
# ---------------------------------------------------------------------------

def _capture_convert_kwargs(monkeypatch) -> dict:
    """Patch ``friTap.offline.pcap_to_tap.convert_pcap_to_tap`` to record the
    kwargs it gets and return a dummy ConvertResult, so no real tshark is ever
    invoked. The ``pcap_to_tap`` wrapper looks up ``convert_pcap_to_tap`` in its
    own (submodule) namespace, so that is the name we must patch."""
    captured: dict = {}

    def fake_convert(pcap_path, **kwargs):
        captured["pcap_path"] = pcap_path
        captured.update(kwargs)
        return _p2t_mod.ConvertResult(tap_path=kwargs.get("tap_path") or "x.tap")

    monkeypatch.setattr(_p2t_mod, "convert_pcap_to_tap", fake_convert)
    return captured


def _write_sidecar(pcap, payload: dict) -> None:
    sidecar = pcap.parent / f"{pcap.name}.fritap.json"
    sidecar.write_text(json.dumps(payload))


def test_pcap_to_tap_manifest_fills_unset_values(tmp_path, monkeypatch):
    """When the caller passes nothing, the manifest supplies the values."""
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    _write_sidecar(pcap, {
        "tls_ports": [8443], "quic_ports": [9443], "keylog": "/tmp/manifest.log",
    })

    captured = _capture_convert_kwargs(monkeypatch)
    _p2t_mod.pcap_to_tap(str(pcap))

    assert captured["keylog_path"] == "/tmp/manifest.log"
    assert captured["tls_ports"] == (8443,)
    assert captured["quic_ports"] == (9443,)


def test_pcap_to_tap_explicit_args_win_over_manifest(tmp_path, monkeypatch):
    """Explicit caller arguments always beat the manifest values."""
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    _write_sidecar(pcap, {
        "tls_ports": [8443], "quic_ports": [9443], "keylog": "/tmp/manifest.log",
    })

    captured = _capture_convert_kwargs(monkeypatch)
    _p2t_mod.pcap_to_tap(
        str(pcap),
        keylog_path="/tmp/explicit.log",
        tls_ports=(1111,),
        quic_ports=(2222,),
    )

    assert captured["keylog_path"] == "/tmp/explicit.log"
    assert captured["tls_ports"] == (1111,)
    assert captured["quic_ports"] == (2222,)


def test_pcap_to_tap_manifest_fills_only_unset_values(tmp_path, monkeypatch):
    """A partial override: explicit tls_ports wins, manifest still fills keylog."""
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    _write_sidecar(pcap, {
        "tls_ports": [8443], "keylog": "/tmp/manifest.log",
    })

    captured = _capture_convert_kwargs(monkeypatch)
    _p2t_mod.pcap_to_tap(str(pcap), tls_ports=(1111,))

    assert captured["tls_ports"] == (1111,)            # explicit wins
    assert captured["keylog_path"] == "/tmp/manifest.log"  # manifest fills the gap


def test_pcap_to_tap_use_manifest_false_ignores_sidecar(tmp_path, monkeypatch):
    """``use_manifest=False`` ignores the sidecar even when one is present."""
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    _write_sidecar(pcap, {
        "tls_ports": [8443], "quic_ports": [9443], "keylog": "/tmp/manifest.log",
    })

    captured = _capture_convert_kwargs(monkeypatch)
    _p2t_mod.pcap_to_tap(str(pcap), use_manifest=False)

    assert captured["keylog_path"] is None
    assert captured["tls_ports"] == ()
    assert captured["quic_ports"] == ()
