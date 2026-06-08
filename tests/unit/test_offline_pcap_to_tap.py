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
import json
import logging
import os
import struct

import pytest

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
# Fail-loud: no keylog AND no DSB must error, not silently emit an empty .tap
# ---------------------------------------------------------------------------

def test_classic_pcap_without_keys_fails_loud(tmp_path):
    """Hermeticity check: a classic pcap with no keylog used to "decrypt" only
    by inheriting the ambient Wireshark profile keylog. It must now error
    clearly before tshark is ever spawned, depending on nothing hidden."""
    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    with pytest.raises(p2t.NoDecryptionKeysError):
        p2t.convert_pcap_to_tap(str(pcap))


def test_missing_keylog_file_fails_loud(tmp_path):
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


def test_cli_no_keys_no_dsb_returns_exit_5(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(offline_cli, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    pcap = tmp_path / "classic.pcap"
    pcap.write_bytes(_classic_pcap_header())
    rc = offline_cli.run_offline_pcap_to_tap(["--from-pcap", str(pcap)])
    assert rc == 5
    assert "Cannot decrypt" in capsys.readouterr().out


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


def _premaster_available() -> bool:
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return os.path.isfile(_PREMASTER_PCAP) and os.path.isfile(_PREMASTER_KEYLOG)


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
