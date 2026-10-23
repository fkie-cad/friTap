"""A fake tshark ``-T ek`` boundary for the combined-pass tests.

Row builders return packet-source dicts exactly as :func:`friTap.offline.tshark.
stream_packets` yields them (``{"layers": {...}}``, every value a list of
strings, ek's underscore spelling). Every combined-pass row carries the
``count(tls_app_data)`` marker, as real tshark >= 4.4 renders it on all rows.

:class:`FakeTshark` replaces the tshark boundary of ``pcap_to_tap`` (and of
``pipeline_api`` for the schannel path): ``stream_packets`` answers by the
argv's ``-Y`` filter, every call is recorded, and ``tshark._run_capture``
fails (recorded too), so a test can assert which passes ran.
"""

from __future__ import annotations

from friTap.offline import pcap_to_tap as p2t
from friTap.offline import pipeline_api
from friTap.offline import tshark as tshark_mod

CLIENT = ("10.0.0.1", 50000)
SERVER = ("93.184.216.34", 443)
_APP_DATA_COUNT_KEY = "count(tls_app_data)"


def _endpoint_layers(transport: str, src, dst, stream: int) -> dict:
    return {
        "ip_src": [src[0]], "ip_dst": [dst[0]],
        f"{transport}_stream": [str(stream)],
        f"{transport}_srcport": [str(src[1])], f"{transport}_dstport": [str(dst[1])],
    }


def _base(transport: str, src, dst, stream: int, ts: float, frame: int | None) -> dict:
    layers = {"frame_time_epoch": [f"{ts}"], _APP_DATA_COUNT_KEY: ["0"]}
    if frame is not None:
        layers["frame_number"] = [str(frame)]
    layers.update(_endpoint_layers(transport, src, dst, stream))
    return layers


def tls_handshake_row(*, tls_stream: int = 0, tcp_stream: int | None = None,
                      hs_types=("1",), sni: str = "", ciphersuites=(),
                      version: str = "", supported_version: str = "", alpn: str = "",
                      src=CLIENT, dst=SERVER, ts: float = 1700000000.0,
                      frame: int | None = None) -> dict:
    """One ``tls.handshake`` row (ClientHello by default)."""
    layers = _base("tcp", src, dst, tls_stream if tcp_stream is None else tcp_stream,
                   ts, frame)
    layers["tls_handshake"] = ["1"]
    layers["tls_stream"] = [str(tls_stream)]
    layers["tls_handshake_type"] = [str(t) for t in hs_types]
    optional = {
        "tls_handshake_extensions_server_name": [sni] if sni else [],
        "tls_handshake_ciphersuite": list(ciphersuites),
        "tls_handshake_version": [version] if version else [],
        "tls_handshake_extensions_supported_version":
            [supported_version] if supported_version else [],
        "tls_handshake_extensions_alpn_str": [alpn] if alpn else [],
    }
    layers.update({key: value for key, value in optional.items() if value})
    return {"layers": layers}


def server_hello_row(*, cipher: str = "0x1301", supported_version: str = "0x0304",
                     alpn: str = "h2", src=SERVER, dst=CLIENT, **kwargs) -> dict:
    """A ServerHello row (TLS 1.3 / AES-128-GCM / h2 by default)."""
    return tls_handshake_row(hs_types=("2",), ciphersuites=(cipher,),
                             version="0x0303", supported_version=supported_version,
                             alpn=alpn, src=src, dst=dst, **kwargs)


def tls_app_data_row(data, *, tcp_stream: int = 0, tls_stream: int | None = None,
                     src=CLIENT, dst=SERVER, ts: float = 1700000001.0,
                     frame: int | None = None, marker: str = "count",
                     app_records: int = 1) -> dict:
    """One app-data row; *data* is bytes or a list of record plaintexts.

    *marker* ``"count"`` sets ``count(tls_app_data)`` to *app_records*;
    ``"raw"`` emits the pre-4.4 ``tls_app_data`` field instead (and no count).
    """
    records = data if isinstance(data, list) else [data]
    layers = _base("tcp", src, dst, tcp_stream, ts, frame)
    layers["tls_stream"] = [str(tcp_stream if tls_stream is None else tls_stream)]
    if records:
        layers["data_data"] = [record.hex() for record in records]
    if marker == "count":
        layers[_APP_DATA_COUNT_KEY] = [str(app_records)]
    else:
        del layers[_APP_DATA_COUNT_KEY]
        if app_records:
            layers["tls_app_data"] = ["17030300"] * app_records
    return {"layers": layers}


def quic_row(*, udp_stream: int = 0, src=CLIENT, dst=SERVER, version: str = "0x00000001",
             hs_types=(), sni: str = "", cipher: str = "", alpn: str = "",
             ts: float = 1700000000.0, frame: int | None = None) -> dict:
    """One QUIC metadata row (the ``quic`` marker plus long-header fields)."""
    layers = _base("udp", src, dst, udp_stream, ts, frame)
    layers["quic"] = ["quic"]
    if version:
        layers["quic_version"] = [version]
    if hs_types:
        layers["tls_handshake"] = ["1"]
        layers["tls_handshake_type"] = [str(t) for t in hs_types]
    for key, value in (("tls_handshake_extensions_server_name", sni),
                       ("tls_handshake_ciphersuite", cipher),
                       ("tls_handshake_extensions_alpn_str", alpn)):
        if value:
            layers[key] = [value]
    return {"layers": layers}


def quic_stream_row(frames, *, udp_stream: int = 0, src=CLIENT, dst=SERVER,
                    ts: float = 1700000002.0, frame: int | None = None) -> dict:
    """One QUIC data row; *frames* is ``[(stream_id, offset, data, fin), ...]``.

    The OFF/LEN/FIN flag lists are exported, so the reassembler sees offsets.
    """
    layers = _base("udp", src, dst, udp_stream, ts, frame)
    layers["quic"] = ["quic"]
    layers["quic_stream_stream_id"] = [str(sid) for sid, *_ in frames]
    layers["quic_stream_data"] = [data.hex() for _sid, _off, data, _fin in frames]
    layers["quic_stream_off"] = ["True" if off else "False" for _s, off, _d, _f in frames]
    layers["quic_stream_offset"] = [str(off) for _s, off, _d, _f in frames if off]
    layers["quic_stream_len"] = ["True"] * len(frames)
    layers["quic_stream_length"] = [str(len(data)) for _s, _o, data, _f in frames]
    layers["quic_stream_fin"] = ["True" if fin else "False" for *_rest, fin in frames]
    return {"layers": {k: v for k, v in layers.items() if v}}


def ssh_row(*, tcp_stream: int = 5, src=("10.0.0.1", 51000), dst=("10.0.0.2", 22),
            banner: str = "", kex: str = "", cipher: str = "", mac: str = "",
            payload: bytes | None = None, ts: float = 1700000003.0) -> dict:
    """One SSH metadata row (``ssh`` marker); *payload* adds ``tcp.payload``."""
    layers = _base("tcp", src, dst, tcp_stream, ts, None)
    layers["ssh"] = ["ssh"]
    for key, value in (("ssh_protocol", banner), ("ssh_kex_algorithms", kex),
                       ("ssh_encryption_algorithms_client_to_server", cipher),
                       ("ssh_mac_algorithms_client_to_server", mac)):
        if value:
            layers[key] = [value]
    if payload is not None:
        layers["tcp_payload"] = [payload.hex()]
        layers["frame_protocols"] = ["eth:ethertype:ip:tcp:ssh"]
    return {"layers": layers}


def plaintext_row(data: bytes, *, tcp_stream: int = 0, src=CLIENT,
                  dst=("93.184.216.34", 80), ts: float = 1700000000.0) -> dict:
    """One keyless raw-payload row."""
    layers = _base("tcp", src, dst, tcp_stream, ts, None)
    del layers[_APP_DATA_COUNT_KEY]
    layers["frame_protocols"] = ["eth:ethertype:ip:tcp"]
    layers["tcp_payload"] = [data.hex()]
    return {"layers": layers}


def same_frame(*rows) -> dict:
    """Merge rows into ONE frame (list values concatenated, markers kept once)."""
    merged: dict = {}
    for row in rows:
        for key, value in row["layers"].items():
            if key == _APP_DATA_COUNT_KEY:
                total = int(merged.get(key, ["0"])[0]) + int(value[0])
                merged[key] = [str(total)]
            elif key in ("tls_handshake", "quic", "ssh", "frame_time_epoch",
                         "frame_number", "ip_src", "ip_dst", "tcp_stream",
                         "tcp_srcport", "tcp_dstport", "tls_stream"):
                merged.setdefault(key, value)
            else:
                merged[key] = merged.get(key, []) + list(value)
    return {"layers": merged}


def stub_tshark_discovery(monkeypatch) -> None:
    """Let a conversion run without a tshark install (as on CI).

    Stubs the binary lookup, the version probe and the SSH metadata pass, the
    only tshark use of a keyless conversion with raw-TCP decryptors only.
    """
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda *a, **k: None)
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda *a, **k: None)
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)


class FakeTshark:
    """Answer ``stream_packets`` by the argv's ``-Y`` filter and record every pass.

    *rows* answer the keyed combined pass (and the TLS-only pass),
    *plaintext_rows* the keyless plaintext pass, *detection_rows* the keyless
    QUIC detection pass.
    """

    def __init__(self, rows=(), *, plaintext_rows=(), detection_rows=()) -> None:
        self.rows = list(rows)
        self.plaintext_rows = list(plaintext_rows)
        self.detection_rows = list(detection_rows)
        self.calls: list[list[str]] = []
        self.run_capture_calls: list[list[str]] = []

    def stream_packets(self, cmd):
        cmd = list(cmd)
        self.calls.append(cmd)
        display_filter = cmd[cmd.index("-Y") + 1] if "-Y" in cmd else ""
        if "tcp.payload" in display_filter:
            return iter(self.plaintext_rows)
        if display_filter.startswith("tls.handshake.type == 1"):
            return iter(self.detection_rows)
        return iter(self.rows)

    def _run_capture(self, cmd):
        self.run_capture_calls.append(list(cmd))
        raise RuntimeError("fake tshark: _run_capture is not expected here")

    def install(self, monkeypatch, version=(4, 6, 0)) -> "FakeTshark":
        """Patch the tshark boundary of pcap_to_tap / pipeline_api / tshark."""
        for module in (p2t, pipeline_api):
            monkeypatch.setattr(module, "stream_packets", self.stream_packets)
            monkeypatch.setattr(module, "tshark_version", lambda path: version)
        monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
        monkeypatch.setattr(tshark_mod, "_run_capture", self._run_capture)
        return self

    def filters(self) -> list[str]:
        """The ``-Y`` filter of every recorded pass, in order."""
        return [cmd[cmd.index("-Y") + 1] for cmd in self.calls if "-Y" in cmd]


class RecordingBus:
    """A minimal bus that records every emitted event, in order."""

    def __init__(self) -> None:
        self.events: list = []

    def emit(self, event) -> None:
        self.events.append(event)
