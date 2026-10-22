#!/usr/bin/env python3

"""Real-tshark calibration harness for the offline metadata extractors.

These tests are GATED: the WHOLE module skips when tshark cannot be located OR
scapy cannot be imported. When both are present (as in CI/dev environments with
Wireshark + scapy installed) they craft minimal real pcaps with scapy and run
the offline extractors through the REAL tshark binary, verifying that the field
names and codepoint renderings the pure parsers depend on are still accurate.

A calibration mismatch here is a REAL finding (e.g. tshark renamed a field or
changed a rendering), not a flaky test — do not weaken the assertions to make
it pass.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import warnings
from pathlib import Path

import pytest

# Gate 1: locate tshark (None when unavailable).
try:
    from friTap.offline.tshark import find_tshark
    try:
        _TSHARK = find_tshark()
    except Exception:
        _TSHARK = None
except Exception:  # pragma: no cover - import-time failure
    _TSHARK = None

# Gate 2: scapy must be importable.
scapy = pytest.importorskip("scapy")

pytestmark = pytest.mark.skipif(_TSHARK is None, reason="tshark not installed")

# scapy's TLS/SSH crafting is noisy; silence the warnings module-wide.
warnings.filterwarnings("ignore")

from friTap.events import SessionEvent  # noqa: E402  (after the gates)
from friTap.offline import pcap_to_tap as p2t  # noqa: E402
from friTap.offline.pipeline_api import (  # noqa: E402
    ConvertResult,
    StreamDirectionTracker,
)
from friTap.offline.tshark import (  # noqa: E402
    QuicMetadataAccumulator,
    TlsMetadataAccumulator,
    build_combined_command,
    extract_ssh_connections,
    is_quic_row,
    is_tls_app_data_row,
    is_tls_handshake_row,
    stream_packets,
    tls_app_data_marker,
    tshark_version,
)


def _combined_metadata(pcap_path, accumulator, is_row):
    """Fold the combined pass's *is_row* rows over *pcap_path* into *accumulator*."""
    cmd = build_combined_command(
        str(pcap_path), None,
        app_data_marker=tls_app_data_marker(tshark_version(_TSHARK)))
    cmd[0] = _TSHARK
    for pkt in stream_packets(cmd):
        layers = pkt.get("layers") or {}
        if is_row(layers):
            accumulator.feed_ek(layers)
    return accumulator.result()


def test_tls_metadata_calibration(tmp_path):
    """A crafted TLS 1.3 handshake yields SNI/cipher/version/ALPN via tshark."""
    from scapy.all import IP, TCP, raw, wrpcap
    from scapy.layers.tls.extensions import (
        ProtocolName,
        ServerName,
        TLS_Ext_ALPN,
        TLS_Ext_ServerName,
        TLS_Ext_SupportedVersion_SH,
    )
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    from scapy.layers.tls.record import TLS

    pcap_path = tmp_path / "tls_calib.pcap"
    C = ("10.0.0.1", 50000)
    S = ("93.184.216.34", 443)
    ch = TLS(msg=[TLSClientHello(
        ciphers=[0x1301, 0xc02f],
        ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.com")]),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ])])
    sh = TLS(msg=[TLSServerHello(
        cipher=0x1301,
        ext=[
            TLS_Ext_SupportedVersion_SH(version=0x0304),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ])])
    p1 = IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                      seq=1, ack=1) / raw(ch)
    p2 = IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                      seq=1, ack=len(raw(ch)) + 1) / raw(sh)
    wrpcap(str(pcap_path), [p1, p2])

    meta = _combined_metadata(pcap_path, TlsMetadataAccumulator(), is_tls_handshake_row)
    assert meta == {0: {
        "sni": "example.com",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "version": "TLS 1.3",
        "alpn": "h2",
    }}


def test_ssh_metadata_calibration(tmp_path):
    """A crafted SSH banner + KEXINIT exchange yields connection metadata."""
    import struct

    from scapy.all import IP, TCP, Raw, wrpcap

    def namelist(s):
        b = s.encode()
        return struct.pack(">I", len(b)) + b

    def kexinit(kex, enc, mac):
        payload = (bytes([20]) + b"\x00" * 16
                   + namelist(kex) + namelist("ssh-ed25519")
                   + namelist(enc) + namelist(enc)
                   + namelist(mac) + namelist(mac)
                   + namelist("none") * 2 + namelist("") * 2
                   + b"\x00" + b"\x00\x00\x00\x00")
        pad = 8 - ((len(payload) + 5) % 8)
        pad = pad if pad >= 4 else pad + 8
        pkt = bytes([pad]) + payload + b"\x00" * pad
        return struct.pack(">I", len(pkt)) + pkt

    pcap_path = tmp_path / "ssh_calib.pcap"
    C = ("10.0.0.1", 51000)
    S = ("2.2.2.2", 22)
    cb = b"SSH-2.0-OpenSSH_9.6\r\n"
    sb = b"SSH-2.0-OpenSSH_8.9\r\n"
    ck = kexinit("curve25519-sha256", "aes256-gcm@openssh.com", "hmac-sha2-256")
    sk = kexinit("curve25519-sha256", "chacha20-poly1305@openssh.com",
                 "hmac-sha2-512")
    pkts = [
        IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                     seq=1, ack=1) / Raw(cb),
        IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                     seq=1, ack=len(cb) + 1) / Raw(sb),
        IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                     seq=len(cb) + 1, ack=len(sb) + 1) / Raw(ck),
        IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                     seq=len(sb) + 1,
                                     ack=len(cb) + len(ck) + 1) / Raw(sk),
    ]
    wrpcap(str(pcap_path), pkts)

    conns = extract_ssh_connections(_TSHARK, str(pcap_path))
    assert len(conns) == 1
    c = conns[0]
    assert c["client_version"] == "SSH-2.0-OpenSSH_9.6"
    assert c["server_version"] == "SSH-2.0-OpenSSH_8.9"
    assert c["kex"] == "curve25519-sha256"
    assert c["cipher"] == "aes256-gcm@openssh.com"
    assert c["mac"] == "hmac-sha2-256"


def test_quic_version_calibration(tmp_path):
    """A crafted QUIC v1 Initial long header yields version "1" via tshark.

    ALPN/cipher are empty here — a bare Initial carries no decryptable TLS
    handshake, so only the plaintext quic.version is recoverable.
    """
    import struct

    from scapy.all import IP, UDP, Raw, wrpcap

    pcap_path = tmp_path / "quic_calib.pcap"
    hdr = (bytes([0xC3]) + struct.pack(">I", 0x00000001)
           + bytes([8]) + b"\xde\xad\xbe\xef\xca\xfe\x00\x01"
           + bytes([0]) + bytes([0])
           + b"\x44\x10" + b"\x00\x00\x00\x00" + b"\x00" * 40)
    pkt = IP(src="10.0.0.1", dst="2.2.2.2") / UDP(sport=50000, dport=443) / Raw(hdr)
    wrpcap(str(pcap_path), [pkt])

    meta = _combined_metadata(pcap_path, QuicMetadataAccumulator(), is_quic_row)
    assert meta, "tshark produced no QUIC metadata for the crafted Initial"
    assert meta[0]["version"] == "1"


# ---------------------------------------------------------------------------
# Combined `-T ek` pass == the former separate passes (recorded expectations)
# ---------------------------------------------------------------------------
#
# The keyed conversion used to run five tshark passes (TLS metadata, TLS data,
# QUIC metadata, QUIC data, SSH); it now runs one. Before the separate passes
# were removed, their output over these captures was recorded as fingerprints
# under tests/fixtures/combined_pass/ (events in order with payload digests,
# the ConvertResult counters, the per-frame TLS spans and the SSH
# connections). The combined pass must still reproduce them exactly. Never
# re-record them from the combined pass: they are the legacy ground truth.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "tests" / "fixtures"


class _Bus:
    def __init__(self) -> None:
        self.events: list = []

    def emit(self, event) -> None:
        self.events.append(event)


class _State:
    def __init__(self) -> None:
        self.opened = False
        self.tls_spans: dict = {}

    def ensure_open(self, capture_start: float = 0.0) -> None:
        self.opened = True


def _context(pcap, keylog, *, tls_ports=(), quic_ports=(), heuristic=False):
    ctx = p2t._ConversionContext(
        pcap_path=str(pcap), keylog_path=str(keylog) if keylog else None,
        tap_path="unused.tap", tls_ports=tuple(tls_ports), quic_ports=tuple(quic_ports),
        extra_decode_as=(), heuristic=heuristic, capture_target="",
        resync_search_depth=None, tls_midstream_secrets=None, progress=None,
    )
    ctx.tshark_bin = _TSHARK
    ctx.tshark_release = tshark_version(_TSHARK)
    ctx.bus, ctx.state = _Bus(), _State()
    ctx.result = ConvertResult(tap_path="unused.tap")
    ctx.tracker = StreamDirectionTracker(server_ports=ctx.quic_ports)
    ctx.tls_tracker = StreamDirectionTracker(server_ports=ctx.tls_ports)
    return ctx


def _event_record(event) -> tuple:
    """An event as comparable data (a SessionEvent's wall-clock timestamp excluded)."""
    skip = {"_cancelled"} | ({"timestamp"} if isinstance(event, SessionEvent) else set())
    return (type(event).__name__,
            tuple((f.name, getattr(event, f.name)) for f in dataclasses.fields(event)
                  if f.name not in skip))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _event_fingerprint(event) -> dict:
    """A compact, JSON-safe identity of one emitted event.

    A DatalogEvent keeps its connection, direction, timestamp, length and a
    payload digest readable, plus a digest of every other field; a
    SessionEvent keeps all its (short) fields except the wall-clock timestamp.
    """
    kind, fields = _event_record(event)
    values = dict(fields)
    if kind != "DatalogEvent":
        return {"type": kind, **values}
    data = values.pop("data")
    rest = {k: v for k, v in values.items()
            if k not in ("src_addr", "src_port", "dst_addr", "dst_port",
                         "direction", "timestamp")}
    return {
        "type": kind,
        "conn": f"{values['src_addr']}:{values['src_port']}>"
                f"{values['dst_addr']}:{values['dst_port']}",
        "dir": values["direction"],
        "ts": values["timestamp"],
        "len": len(data),
        "sha256": _sha(data),
        "fields": _sha(repr(sorted(rest.items())).encode()),
    }


def _spans_fingerprint(tls_spans: dict) -> dict:
    """Span count per connection/direction plus one digest over every span."""
    counts, digest = {}, hashlib.sha256()
    for key in sorted(tls_spans, key=repr):
        for direction in sorted(tls_spans[key]):
            spans = tls_spans[key][direction]
            counts[f"{key}|{direction}"] = len(spans)
            for span in spans:
                fields = dataclasses.asdict(span)
                data = fields.pop("data")
                digest.update(repr((sorted(fields.items()), _sha(data))).encode())
    return {"counts": counts, "sha256": digest.hexdigest()}


def _fingerprint(ctx, ssh_connections) -> dict:
    """The JSON-normalized fingerprint of one pass run (events, counters, spans, SSH)."""
    return json.loads(json.dumps({
        "events": [_event_fingerprint(e) for e in ctx.bus.events],
        "result": ctx.result.to_dict(),
        "tls_spans": _spans_fingerprint(ctx.state.tls_spans),
        "ssh": ssh_connections,
    }))


def _digest_only(fingerprint: dict) -> dict:
    """*fingerprint* with every endpoint/name hashed away (for private captures).

    The research-corpus captures are not part of the repository, so their
    recorded expectations keep only digests: one per event, plus the counters.
    """
    def digest(value) -> str:
        return _sha(json.dumps(value, sort_keys=True).encode())

    return {
        "events": [digest(e) for e in fingerprint["events"]],
        "result": fingerprint["result"],
        "tls_spans": {"count": sum(fingerprint["tls_spans"]["counts"].values()),
                      "sha256": fingerprint["tls_spans"]["sha256"]},
        "ssh": digest(fingerprint["ssh"]),
    }


_RECORDED = _FIXTURES / "combined_pass"


def _assert_matches_recording(runner, mode, case, pcap, keylog, **options) -> dict:
    """Run *runner* over *pcap* and compare its fingerprint with the recording."""
    recorded = json.loads((_RECORDED / f"{mode}_{case}.json").read_text())
    ctx = _context(pcap, keylog, **options)
    ssh_connections = runner(ctx)
    actual = _fingerprint(ctx, ssh_connections)
    if recorded["digest_only"]:
        actual = _digest_only(actual)
    assert len(actual["events"]) == len(recorded["events"])
    for index, (want, got) in enumerate(zip(recorded["events"], actual["events"])):
        assert got == want, f"event #{index} differs"
    expected = {key: recorded[key] for key in ("events", "result", "tls_spans", "ssh")}
    assert actual == expected
    return actual


def _research_cases() -> list:
    """The research-corpus captures (dev/golden/corpus.json), skipped when absent.

    Marked ``slow``: real captures take seconds each; set FRITAP_SLOW_TESTS=1.
    """
    wanted = {"rs_stress_capture", "rs_stress_capturec", "rs_stress_ccccapture",
              "rs_signal_s1capture"}
    corpus_path = _REPO_ROOT / "dev" / "golden" / "corpus.json"
    entries = json.loads(corpus_path.read_text())["entries"] if corpus_path.exists() else []
    cases = []
    for entry in entries:
        if entry["id"] in wanted:
            cases.append(pytest.param(
                _REPO_ROOT / entry["pcap"], _REPO_ROOT / entry["args"]["keylog_path"], {},
                id=entry["id"], marks=pytest.mark.slow))
    return cases


_KEYED_CASES = [
    pytest.param(_FIXTURES / "dump_premaster.pcapng", _FIXTURES / "premaster.txt",
                 {"tls_ports": (4430, 4431, 4432), "heuristic": True},
                 id="dump_premaster"),
    pytest.param(_FIXTURES / "signal_grpc_h2.pcapng", _FIXTURES / "signal_grpc_h2.tls.log",
                 {}, id="signal_grpc_h2"),
    pytest.param(_FIXTURES / "chrome_quic_encrypted.pcapng", None, {},
                 id="chrome_quic_encrypted"),
    *_research_cases(),
]


@pytest.mark.parametrize("pcap, keylog, options", _KEYED_CASES)
def test_combined_pass_matches_the_recorded_separate_passes(request, pcap, keylog, options):
    if not pcap.exists() or (keylog is not None and not keylog.exists()):
        pytest.skip(f"capture not present: {pcap.name}")
    _assert_matches_recording(p2t._run_keyed_combined_pass, "keyed",
                              request.node.callspec.id, pcap, keylog, **options)


@pytest.mark.parametrize("pcap", [
    _FIXTURES / "weather6_apiapi_h2_plaintext.pcapng",
    _FIXTURES / "chrome_quic_encrypted.pcapng",
], ids=["weather6", "chrome_quic"])
def test_keyless_pass_matches_the_recorded_separate_passes(request, pcap):
    if not pcap.exists():
        pytest.skip(f"capture not present: {pcap.name}")
    _assert_matches_recording(p2t._run_keyless_passes, "keyless",
                              request.node.callspec.id, pcap, None)


_SSH_PCAP_EPOCH = 1_700_000_000


def _write_ssh_pcap(pcap_path, *, server_first: bool = False) -> None:
    """Two SSH connections (banners + KEXINIT each), one on a non-standard port.

    *server_first* puts each server's banner before its client's (the usual
    order on the wire).
    """
    import struct

    from scapy.all import IP, TCP, Raw, wrpcap

    def namelist(text):
        return struct.pack(">I", len(text)) + text.encode()

    def kexinit(kex, enc, mac):
        payload = (bytes([20]) + b"\x00" * 16 + namelist(kex) + namelist("ssh-ed25519")
                   + namelist(enc) * 2 + namelist(mac) * 2 + namelist("none") * 2
                   + namelist("") * 2 + b"\x00" + b"\x00" * 4)
        pad = 8 - ((len(payload) + 5) % 8)
        pad = pad if pad >= 4 else pad + 8
        packet = bytes([pad]) + payload + b"\x00" * pad
        return struct.pack(">I", len(packet)) + packet

    packets = []
    for client, server, version in ((("10.0.0.1", 51000), ("2.2.2.2", 22), "9.6"),
                                    (("10.0.0.3", 51001), ("2.2.2.4", 22), "8.4")):
        messages = [
            (client, server, f"SSH-2.0-OpenSSH_{version}\r\n".encode()),
            (server, client, b"SSH-2.0-OpenSSH_8.9\r\n"),
            (client, server, kexinit("curve25519-sha256", "aes256-gcm@openssh.com",
                                     "hmac-sha2-256")),
            (server, client, kexinit("sntrup761x25519-sha512", "chacha20-poly1305@"
                                     "openssh.com", "hmac-sha2-512")),
        ]
        if server_first:
            messages[0], messages[1] = messages[1], messages[0]
        seq = {client: 1, server: 1}
        for src, dst, data in messages:
            packet = IP(src=src[0], dst=dst[0]) / TCP(
                sport=src[1], dport=dst[1], flags="PA", seq=seq[src], ack=seq[dst]) / Raw(data)
            packet.time = _SSH_PCAP_EPOCH + len(packets)  # deterministic capture times
            packets.append(packet)
            seq[src] += len(data)
    wrpcap(str(pcap_path), packets)


def test_combined_pass_parity_on_ssh(tmp_path):
    pcap = tmp_path / "ssh.pcap"
    _write_ssh_pcap(pcap)
    keylog = tmp_path / "empty.keylog"
    keylog.write_text("")
    outcome = _assert_matches_recording(p2t._run_keyed_combined_pass, "keyed",
                                        "ssh_synthetic", pcap, keylog)
    assert [c["client_version"] for c in outcome["ssh"]] == [
        "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_8.4"]
    keyless = _assert_matches_recording(p2t._run_keyless_passes, "keyless",
                                        "ssh_synthetic", pcap, None)
    assert keyless["ssh"] == outcome["ssh"]


def test_ssh_server_banner_first_is_attributed_to_the_server(tmp_path):
    pcap = tmp_path / "ssh_server_first.pcap"
    _write_ssh_pcap(pcap, server_first=True)
    conns = extract_ssh_connections(_TSHARK, str(pcap))
    assert [(c["client_version"], c["server_version"]) for c in conns] == [
        ("SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_8.9"),
        ("SSH-2.0-OpenSSH_8.4", "SSH-2.0-OpenSSH_8.9")]
    assert [(c["src_addr"], c["dst_port"]) for c in conns] == [
        ("10.0.0.1", 22), ("10.0.0.3", 22)]


def _app_data_frames_by_filter(pcap, keylog) -> set:
    cmd = [_TSHARK, "-r", str(pcap), "-2", "-o", f"tls.keylog_file:{keylog}",
           "-Y", "tls.app_data", "-T", "fields", "-e", "frame.number"]
    from friTap.offline.tshark import _run_capture

    return {int(line) for line in _run_capture(cmd).split()}


@pytest.mark.parametrize("marker", ["count(tls.app_data)", "tls.app_data"])
def test_app_data_marker_calibration(marker):
    """Rows gated by either marker are exactly the frames ``-Y tls.app_data`` matches."""
    if marker == "count(tls.app_data)" and tls_app_data_marker(
            tshark_version(_TSHARK)) != marker:
        pytest.skip("tshark < 4.4 has no count() field function")
    pcap = _FIXTURES / "signal_grpc_h2.pcapng"
    keylog = _FIXTURES / "signal_grpc_h2.tls.log"
    if not pcap.exists() or not keylog.exists():
        pytest.skip(f"capture not present: {pcap.name}")
    cmd = build_combined_command(str(pcap), str(keylog), app_data_marker=marker)
    cmd[0] = _TSHARK
    gated = {int(pkt["layers"]["frame_number"][0]) for pkt in stream_packets(cmd)
             if is_tls_app_data_row(pkt["layers"], marker)}
    expected = _app_data_frames_by_filter(pcap, keylog)
    assert expected, "the fixture should carry TLS application data"
    assert gated == expected


def test_presence_markers_render_as_documented():
    """``-e tls.handshake`` / ``-e quic`` render as "1" / "quic" items in -T ek,
    and the count marker is present on every row (tshark >= 4.4)."""
    marker = tls_app_data_marker(tshark_version(_TSHARK))
    pcap = _FIXTURES / "signal_grpc_h2.pcapng"
    keylog = _FIXTURES / "signal_grpc_h2.tls.log"
    if not pcap.exists() or not keylog.exists():
        pytest.skip(f"capture not present: {pcap.name}")
    cmd = build_combined_command(str(pcap), str(keylog),
                                 app_data_marker=marker)
    cmd[0] = _TSHARK
    rows = [pkt["layers"] for pkt in stream_packets(cmd)]
    handshake_items = {v for r in rows for v in r.get("tls_handshake", ())}
    quic_items = {v for r in rows for v in r.get("quic", ())}
    assert handshake_items == {"1"} and quic_items == {"quic"}
    if marker == "count(tls.app_data)":
        assert all("count(tls_app_data)" in r for r in rows)
