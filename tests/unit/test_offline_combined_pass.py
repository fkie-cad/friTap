"""The single combined tshark ``-T ek`` pass of the keyed offline conversion.

Covers the argv builders, the row routing (gating and ordering) of
:class:`~friTap.offline.pipeline_api.TlsSinglePass` and
``pcap_to_tap._run_keyed_combined_pass``, the number of tshark runs per
conversion, the ``stream_packets`` process handling (real subprocesses, no
tshark needed) and the ``tshark_version`` cache. Real-tshark parity with the
former separate passes lives in ``test_offline_tshark_calibration.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

import pytest

from friTap.events import DatalogEvent, EventBus, SessionEvent
from friTap.offline import pcap_to_tap as p2t
from friTap.offline import pipeline_api
from friTap.offline import tshark as tshark_mod
from friTap.offline.registry import (
    OfflineDecryptorEntry,
    get_offline_decryptor_registry,
)
from tests.unit import _fake_tshark as ft


def _option_values(cmd: list, flag: str) -> list:
    return [cmd[i + 1] for i, token in enumerate(cmd) if token == flag]


# ---------------------------------------------------------------------------
# argv
# ---------------------------------------------------------------------------

def test_keyed_combined_command_argv():
    cmd = tshark_mod.build_combined_command(
        "cap.pcapng", "keys.log", tls_ports=(8443,), extra_decode_as=("tcp.port==9,tls",),
        heuristic=True)

    assert cmd[:6] == ["tshark", "-r", "cap.pcapng", "-2", "-T", "ek"]
    assert _option_values(cmd, "-o") == ["tcp.try_heuristic_first:TRUE",
                                         "tls.keylog_file:keys.log"]
    assert _option_values(cmd, "--disable-protocol") == ["http", "http2"]
    assert _option_values(cmd, "-d") == [
        "tcp.port==8443,tls", "udp.port==443,quic", "tcp.port==9,tls"]
    assert _option_values(cmd, "-Y") == ["tls.handshake || tls.app_data || quic || ssh"]
    fields = _option_values(cmd, "-e")
    assert len(fields) == len(set(fields)), "the -e union must be deduplicated"
    for name in ("tls.handshake", "count(tls.app_data)", "tls.stream", "data.data",
                 "frame.number", "quic", "quic.version", "quic.stream_data",
                 "quic.stream.fin", "ssh", "ssh.protocol", "tcp.stream", "udp.stream"):
        assert name in fields
    assert "tls.app_data" not in fields  # the count marker replaces it on 4.4+
    # The -Y filter comes last, after every -d rule.
    assert cmd[-2] == "-Y"


def test_tls_only_combined_command_for_schannel():
    cmd = tshark_mod.build_combined_command(
        "cap.pcap", "derived.keylog", tls_ports=(4433,),
        include_quic=False, include_ssh=False)
    assert _option_values(cmd, "-Y") == ["tls.handshake || tls.app_data"]
    assert _option_values(cmd, "-d") == ["tcp.port==4433,tls"]
    fields = _option_values(cmd, "-e")
    assert not [f for f in fields if f.startswith(("quic", "ssh", "udp."))]


def test_quic_ports_replace_the_default_quic_port():
    cmd = tshark_mod.build_combined_command("c.pcap", None, quic_ports=(4443, 8443))
    assert _option_values(cmd, "-d") == ["udp.port==4443,quic", "udp.port==8443,quic"]
    assert "-o" not in cmd  # no keylog, no heuristic


def test_plaintext_command_default_is_unchanged():
    expected = ["tshark", "-r", "c.pcap", "-2", "-T", "ek", "-o",
                "tcp.try_heuristic_first:TRUE"]
    for name in tshark_mod._PLAINTEXT_FIELDS:
        expected += ["-e", name]
    expected += ["-d", "x==1,y", "-Y", "tcp.payload or udp.payload"]
    assert tshark_mod.build_plaintext_command(
        "c.pcap", extra_decode_as=("x==1,y",), heuristic=True) == expected


def test_plaintext_command_with_ssh_rows():
    cmd = tshark_mod.build_plaintext_command("c.pcap", include_ssh=True)
    assert _option_values(cmd, "-Y") == ["(tcp.payload or udp.payload) || ssh"]
    fields = _option_values(cmd, "-e")
    assert {"ssh", "ssh.protocol", "tcp.payload", "frame.protocols"} <= set(fields)
    assert len(fields) == len(set(fields))
    assert "--disable-protocol" not in cmd and "-o" not in cmd


@pytest.mark.parametrize("version, marker", [
    ((4, 6, 7), "count(tls.app_data)"), ((4, 4), "count(tls.app_data)"),
    ((4, 2, 9), "tls.app_data"), ((), "tls.app_data"), (None, "tls.app_data"),
])
def test_app_data_marker_by_version(version, marker):
    assert tshark_mod.tls_app_data_marker(version) == marker


def test_raw_marker_is_exported_instead_of_the_count():
    cmd = tshark_mod.build_combined_command("c.pcap", None, app_data_marker="tls.app_data")
    fields = _option_values(cmd, "-e")
    assert "tls.app_data" in fields and "count(tls.app_data)" not in fields


def test_ek_helpers_are_shared_with_pipeline_api():
    for name in ("ek_field", "ek_as_list", "ek_first"):
        assert getattr(pipeline_api, name) is getattr(tshark_mod, name)


def test_ek_columns_reproduce_fields_columns():
    layers = {"tls_handshake_type": ["2", "8"], "tls_stream": ["3"]}
    assert tshark_mod.ek_columns(layers, ("tls.stream", "tls.handshake.type", "x")) == [
        "3", "2,8", ""]


# ---------------------------------------------------------------------------
# Row predicates and accumulators
# ---------------------------------------------------------------------------

def test_row_predicates():
    hello = ft.tls_handshake_row()["layers"]
    app = ft.tls_app_data_row(b"x")["layers"]
    quic = ft.quic_stream_row([(0, 0, b"a", False)])["layers"]
    assert tshark_mod.is_tls_handshake_row(hello) and not tshark_mod.is_tls_app_data_row(hello)
    assert tshark_mod.is_tls_app_data_row(app) and not tshark_mod.is_tls_handshake_row(app)
    assert tshark_mod.is_quic_row(quic) and tshark_mod.is_quic_stream_row(quic)
    assert not tshark_mod.is_quic_stream_row(ft.quic_row()["layers"])
    assert tshark_mod.is_ssh_row(ft.ssh_row()["layers"])
    assert not tshark_mod.has_plaintext_payload(ft.ssh_row()["layers"])
    assert tshark_mod.has_plaintext_payload(ft.ssh_row(payload=b"SSH-2.0-x\r\n")["layers"])


def test_tls_accumulator_ek_rows_match_column_rows():
    rows = [ft.tls_handshake_row(sni="a.example"), ft.server_hello_row(alpn="h2")]
    accumulator = tshark_mod.TlsMetadataAccumulator()
    assert [accumulator.feed_ek(r["layers"]) for r in rows] == [0, 0]
    by_columns = tshark_mod.TlsMetadataAccumulator()
    for r in rows:
        by_columns.feed_columns(tshark_mod.ek_columns(r["layers"], tshark_mod._TLS_META_FIELDS))
    assert accumulator.result() == by_columns.result()
    assert accumulator.result() == {0: {"sni": "a.example", "cipher": "TLS_AES_128_GCM_SHA256",
                                        "version": "TLS 1.3", "alpn": "h2"}}


def test_quic_crypto_rows_never_reach_the_tls_metadata():
    # A QUIC Initial matches tls.handshake but carries no tls.stream.
    row = ft.quic_row(hs_types=("1",), sni="quic.example")["layers"]
    assert tshark_mod.is_tls_handshake_row(row)
    assert tshark_mod.TlsMetadataAccumulator().feed_ek(row) is None


def test_ssh_result_is_fresh_and_repeatable():
    accumulator = tshark_mod.SshConnectionAccumulator()
    accumulator.feed_ek(ft.ssh_row(banner="SSH-2.0-A")["layers"])
    first = accumulator.result()
    first[0]["client_version"] = "mutated"
    assert accumulator.result()[0]["client_version"] == "SSH-2.0-A"
    assert "_banners" not in accumulator.result()[0]


# ---------------------------------------------------------------------------
# TlsSinglePass: gating and ordering
# ---------------------------------------------------------------------------

class _State:
    """Minimal writer-state stand-in."""

    def __init__(self) -> None:
        self.opened = False
        self.tls_spans: dict = {}

    def ensure_open(self, capture_start: float = 0.0) -> None:
        self.opened = True


def _tls_pass(marker=tshark_mod.TLS_APP_DATA_COUNT_FIELD, server_ports=()):
    bus = ft.RecordingBus()
    result = pipeline_api.ConvertResult(tap_path="x.tap")
    tls = pipeline_api.TlsSinglePass(
        bus=bus, state=_State(), result=result,
        tracker=pipeline_api.StreamDirectionTracker(server_ports=server_ports),
        app_data_marker=marker)
    return tls, bus, result


def _kinds(events) -> list:
    return ["S" if isinstance(e, SessionEvent) else "D" for e in events]


def test_session_event_precedes_the_first_data_event():
    tls, bus, result = _tls_pass()
    for row in (ft.tls_handshake_row(sni="example.com"), ft.server_hello_row(),
                ft.tls_app_data_row(b"GET /"),
                ft.tls_app_data_row(b"200", src=ft.SERVER, dst=ft.CLIENT)):
        tls.feed(row)
    tls.finish()
    assert _kinds(bus.events) == ["S", "D", "D"]
    session = bus.events[0]
    assert (session.server_name, session.cipher_suite, session.protocol_version,
            session.alpn) == ("example.com", "TLS_AES_128_GCM_SHA256", "TLS 1.3", "h2")
    assert result.decrypted_packet_count == 2 and result.stream_count == 1


def test_handshake_and_app_data_in_the_same_frame():
    tls, bus, _result = _tls_pass()
    tls.feed(ft.tls_handshake_row(sni="example.com"))
    tls.feed(ft.same_frame(ft.server_hello_row(),
                           ft.tls_app_data_row(b"early", src=ft.SERVER, dst=ft.CLIENT)))
    assert _kinds(bus.events) == ["S", "D"]
    assert bus.events[0].cipher_suite == "TLS_AES_128_GCM_SHA256"
    assert bus.events[1].data == b"early"


def test_late_handshake_announces_the_changed_metadata_once():
    tls, bus, _result = _tls_pass()
    tls.feed(ft.tls_handshake_row(sni="example.com"))
    tls.feed(ft.tls_app_data_row(b"0-rtt"))         # only the SNI is known yet
    tls.feed(ft.server_hello_row())                  # cipher/version/alpn arrive
    tls.feed(ft.tls_handshake_row(hs_types=("4",), src=ft.SERVER, dst=ft.CLIENT))
    tls.feed(ft.tls_app_data_row(b"more"))
    assert _kinds(bus.events) == ["S", "D", "S", "D"]
    first, second = bus.events[0], bus.events[2]
    assert (first.server_name, first.cipher_suite) == ("example.com", "")
    assert (second.server_name, second.cipher_suite) == (
        "example.com", "TLS_AES_128_GCM_SHA256")
    assert second.connection_id == first.connection_id


def test_handshake_after_metadata_less_first_data_announces_late():
    tls, bus, _result = _tls_pass()
    tls.feed(ft.tls_app_data_row(b"data"))
    tls.feed(ft.server_hello_row())
    assert _kinds(bus.events) == ["D", "S"]


def test_app_data_needs_a_positive_count():
    tls, bus, result = _tls_pass()
    tls.feed(ft.tls_app_data_row(b"not app data", app_records=0))
    tls.finish()
    assert bus.events == [] and result.stream_count == 0


def test_server_first_handshake_does_not_seed_direction():
    # No known server port: direction falls back to first-packet-is-client,
    # so a ServerHello reaching the tracker would invert every label.
    server, client = ("10.0.0.2", 8443), ("10.0.0.1", 50000)
    tls, bus, _result = _tls_pass()
    tls.feed(ft.server_hello_row(src=server, dst=client))
    tls.feed(ft.tls_app_data_row(b"req", src=client, dst=server))
    tls.feed(ft.tls_app_data_row(b"resp", src=server, dst=client))
    data = [e for e in bus.events if isinstance(e, DatalogEvent)]
    assert [(e.data, e.direction) for e in data] == [(b"req", "write"), (b"resp", "read")]


def test_raw_marker_mode_gates_on_the_app_data_field():
    tls, bus, _result = _tls_pass(marker="tls.app_data")
    tls.feed(ft.tls_app_data_row(b"yes", marker="raw"))
    tls.feed(ft.tls_app_data_row(b"no", marker="raw", app_records=0))
    assert [e.data for e in bus.events] == [b"yes"]


def test_run_tls_combined_pass_is_one_run_and_returns_the_metadata(monkeypatch):
    fake = ft.FakeTshark([ft.tls_handshake_row(sni="example.com"),
                          ft.server_hello_row(), ft.tls_app_data_row(b"GET /")])
    fake.install(monkeypatch)
    bus, result = ft.RecordingBus(), pipeline_api.ConvertResult(tap_path="x")
    meta = pipeline_api.run_tls_combined_pass(
        "/usr/bin/tshark", "x.pcap", "k.log", tls_ports=(4433,), extra_decode_as=(),
        heuristic=False, bus=bus, state=_State(), result=result,
        tracker=pipeline_api.StreamDirectionTracker())
    assert meta[0]["sni"] == "example.com"
    assert _kinds(bus.events) == ["S", "D"]
    assert fake.filters() == ["tls.handshake || tls.app_data"]
    assert fake.calls[0][0] == "/usr/bin/tshark" and fake.run_capture_calls == []


# ---------------------------------------------------------------------------
# The keyed conversion: event order and spawn counts
# ---------------------------------------------------------------------------

class _RecordingEventBus(EventBus):
    """The real bus, also recording the emitted Session/Datalog events.

    The collector's own FlowEvents ride the same bus and are not recorded.
    The last instance wins.
    """

    last = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.events: list = []
        type(self).last = self

    def emit(self, event) -> None:
        if isinstance(event, (SessionEvent, DatalogEvent)):
            self.events.append(event)
        super().emit(event)


def _inputs(tmp_path, *, keyed: bool = True):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = None
    if keyed:
        keylog = tmp_path / "keys.log"
        keylog.write_text("")
        keylog = str(keylog)
    return str(pcap), keylog, str(tmp_path / "out.tap")


def _interleaved_rows():
    """TLS and QUIC rows interleaved by frame, with one held-back QUIC frame."""
    quic_server = ("8.8.8.8", 443)
    return [
        ft.quic_row(hs_types=("1",), sni="h3.example", alpn="h3", dst=quic_server,
                    ts=1.0),
        ft.tls_handshake_row(sni="example.com", ts=2.0),
        ft.quic_stream_row([(0, 0, b"Q0", False)], dst=quic_server, ts=3.0),
        ft.server_hello_row(ts=4.0),
        # Offset 10 behind a gap: held until the end, then drained as leftover.
        ft.quic_stream_row([(4, 10, b"LATE", False)], dst=quic_server, ts=5.0),
        ft.tls_app_data_row(b"GET / HTTP/1.1\r\n\r\n", ts=6.0),
        ft.quic_stream_row([(0, 2, b"Q1", False)], dst=quic_server, ts=7.0),
        ft.tls_app_data_row(b"HTTP/1.1 204 No Content\r\n\r\n",
                            src=ft.SERVER, dst=ft.CLIENT, ts=8.0),
    ]


def _describe(event) -> tuple:
    if isinstance(event, SessionEvent):
        return ("S", event.protocol, event.server_name)
    return ("D", event.transport, bytes(event.data))


def test_keyed_event_order_matches_the_former_passes(tmp_path, monkeypatch):
    fake = ft.FakeTshark(_interleaved_rows()).install(monkeypatch)
    monkeypatch.setattr(p2t, "EventBus", _RecordingEventBus)
    pcap, keylog, tap = _inputs(tmp_path)

    result = p2t.convert_pcap_to_tap(pcap, keylog_path=keylog, tap_path=tap)

    assert [_describe(e) for e in _RecordingEventBus.last.events] == [
        ("S", "tls", "example.com"),
        ("D", "tcp", b"GET / HTTP/1.1\r\n\r\n"),
        ("D", "tcp", b"HTTP/1.1 204 No Content\r\n\r\n"),
        ("S", "quic", "h3.example"),          # QUIC metadata, before QUIC data
        ("D", "udp", b"Q0"),
        ("D", "udp", b"Q1"),
        ("D", "udp", b"LATE"),                 # reassembly leftover, last
    ]
    leftover = _RecordingEventBus.last.events[-1]
    assert leftover.timestamp == 7.0  # stamped with the last QUIC data timestamp
    assert result.stream_count == 3   # 1 TLS stream + 2 QUIC streams
    assert result.decrypted_packet_count == 5
    assert len(fake.calls) == 1 and fake.run_capture_calls == []


def test_keyed_conversion_spawns_one_pass(tmp_path, monkeypatch):
    rows = [*_interleaved_rows(), ft.ssh_row(banner="SSH-2.0-A")]
    fake = ft.FakeTshark(rows).install(monkeypatch)
    pcap, keylog, tap = _inputs(tmp_path)
    p2t.convert_pcap_to_tap(pcap, keylog_path=keylog, tap_path=tap)
    assert fake.filters() == ["tls.handshake || tls.app_data || quic || ssh"]
    assert fake.run_capture_calls == []


def test_keyless_conversion_spawns_detection_plus_plaintext(tmp_path, monkeypatch):
    fake = ft.FakeTshark(plaintext_rows=[
        ft.plaintext_row(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ft.ssh_row(banner="SSH-2.0-OpenSSH_9.6", payload=b"SSH-2.0-OpenSSH_9.6\r\n"),
        ft.ssh_row(src=("10.0.0.2", 22), dst=("10.0.0.1", 51000),
                   banner="SSH-2.0-OpenSSH_8.9"),  # an ssh row without payload
    ]).install(monkeypatch)
    pcap, _keylog, tap = _inputs(tmp_path, keyed=False)

    result = p2t.convert_pcap_to_tap(pcap, tap_path=tap)

    assert len(fake.calls) == 2 and fake.run_capture_calls == []
    assert fake.filters()[1] == "(tcp.payload or udp.payload) || ssh"
    # Rows with a payload become events (as before); the payload-less SSH row not.
    assert result.decrypted_packet_count == 2
    from friTap.flow.tap_reader import TapReader
    with TapReader(tap) as reader:
        ssh_flows = [f for f in reader.read_all_flows() if f.detected_protocol == "SSH"]
    assert [(f.ssh.client_version, f.ssh.server_version) for f in ssh_flows] == [
        ("SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_8.9")]


def test_ssh_flows_follow_the_bus_events_and_precede_tls_riding_emitters(
        tmp_path, monkeypatch):
    rows = [*_interleaved_rows(), ft.ssh_row(banner="SSH-2.0-A")]
    ft.FakeTshark(rows).install(monkeypatch)
    monkeypatch.setattr(p2t, "EventBus", _RecordingEventBus)
    order = []
    real_add = p2t._add_ssh_synthetic_flows

    def recording_add(connections, collector, state):
        order.append(("ssh", len(_RecordingEventBus.last.events), len(connections)))
        real_add(connections, collector, state)

    def rider(**kwargs):
        order.append(("rider", len(_RecordingEventBus.last.events)))

    monkeypatch.setattr(p2t, "_add_ssh_synthetic_flows", recording_add)
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", {"rider": OfflineDecryptorEntry(
        protocol_name="rider", cli_flag="--rider-keylog", cli_dest="rider_keylog",
        requires_tls_strip=True, emitter=rider, layer_cls=object,
        counter_prefix="rider")})
    pcap, keylog, tap = _inputs(tmp_path)
    rider_keylog = tmp_path / "rider.log"
    rider_keylog.write_text("x\n")

    p2t.convert_pcap_to_tap(pcap, keylog_path=keylog, tap_path=tap,
                            protocol_keylogs={"rider": str(rider_keylog)})

    total = 7  # the 7 Session/Datalog events listed in the event-order test above
    assert order == [("ssh", total, 1), ("rider", total)]


# ---------------------------------------------------------------------------
# stream_packets: real subprocesses (no tshark needed)
# ---------------------------------------------------------------------------

_EK_LINES = (
    'print(\'{"index":{"_index":"packets"}}\')\n'
    'print(\'{"timestamp":"1","layers":{"frame_number":["1"]}}\')\n'
)


def _python_cmd(body: str) -> list:
    return [sys.executable, "-c", "import sys\n" + body]


def _run_with_timeout(fn, timeout: float):
    outcome: dict = {}

    def target():
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "stream_packets did not finish (deadlock?)"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def test_large_stderr_before_stdout_does_not_deadlock():
    body = ("sys.stderr.write('x' * (2 * 1024 * 1024))\nsys.stderr.flush()\n"
            + _EK_LINES)
    packets = _run_with_timeout(
        lambda: list(tshark_mod.stream_packets(_python_cmd(body))), timeout=60)
    assert packets == [{"timestamp": "1", "layers": {"frame_number": ["1"]}}]


def test_early_exit_reaps_an_endless_writer(monkeypatch):
    spawned = []

    class _TrackingPopen(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            spawned.append(self)

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _TrackingPopen)
    body = ("line = '{\"layers\":{\"frame_number\":[\"1\"]}}'\n"
            "while True:\n    print(line, flush=True)\n")
    packets = tshark_mod.stream_packets(_python_cmd(body))
    assert next(packets) == {"layers": {"frame_number": ["1"]}}
    started = time.monotonic()
    packets.close()  # the consumer stops early: no RuntimeError, process reaped
    assert time.monotonic() - started < 5.0
    assert spawned and spawned[0].poll() is not None


def test_nonzero_exit_after_full_consumption_raises_with_the_stderr_tail():
    body = _EK_LINES + "sys.stderr.write('first\\nboom: bad keylog\\n')\nsys.exit(3)\n"
    packets = tshark_mod.stream_packets(_python_cmd(body))
    assert next(packets)["layers"] == {"frame_number": ["1"]}
    with pytest.raises(RuntimeError) as excinfo:
        list(packets)
    assert "code 3" in str(excinfo.value)
    assert "boom: bad keylog" in str(excinfo.value)


# ---------------------------------------------------------------------------
# tshark_version cache
# ---------------------------------------------------------------------------

@pytest.fixture
def version_runs(monkeypatch):
    """Fake ``tshark --version`` (4.6.7); yields the list of recorded runs."""
    # In-memory cache only: the on-disk one is covered (in tmp_path) by
    # test_offline_tshark_robustness.py and must never touch the real home.
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    tshark_mod._clear_tshark_version_cache()
    runs: list = []

    class _Completed:
        stdout = "TShark (Wireshark) 4.6.7 (Git commit b439fb7b47a9).\n"

    def fake_run(cmd, **kwargs):
        runs.append(cmd)
        return _Completed()

    monkeypatch.setattr(tshark_mod.subprocess, "run", fake_run)
    yield runs
    tshark_mod._clear_tshark_version_cache()


def test_version_is_cached_per_binary_and_mtime(tmp_path, version_runs):
    binary = tmp_path / "tshark"
    binary.write_text("#!/bin/sh\n")
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(version_runs) == 1
    stat = os.stat(binary)
    os.utime(binary, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(version_runs) == 2  # an upgraded binary is asked again


def test_version_failures_are_not_cached(tmp_path, monkeypatch):
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    tshark_mod._clear_tshark_version_cache()
    runs = []

    class _Completed:
        stdout = "no version here"

    monkeypatch.setattr(tshark_mod.subprocess, "run",
                        lambda cmd, **kw: runs.append(cmd) or _Completed())
    binary = tmp_path / "tshark"
    binary.write_text("")
    assert tshark_mod.tshark_version(str(binary)) == ()
    assert tshark_mod.tshark_version(str(binary)) == ()
    assert len(runs) == 2
    tshark_mod._clear_tshark_version_cache()
