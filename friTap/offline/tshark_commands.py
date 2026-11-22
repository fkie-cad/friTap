"""tshark argv builders and `-T ek` row predicates.

Pure functions building ``tshark`` command lines (combined keyed pass, data-only
and plaintext exports, QUIC detection) and classifying `-T ek` rows. No
subprocess work; :mod:`friTap.offline.tshark` re-exports every name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .tshark_meta import (
    _QUIC_META_FIELDS,
    _SSH_FIELDS,
    _TLS_META_FIELDS,
    ek_field,
    ek_first,
)

# Default QUIC server port included when no explicit --quic-port is given.
DEFAULT_QUIC_PORT = 443

# QUIC fields for `-T ek`. The dissector already decrypts the payload, so it comes from a display field. `quic.stream.stream_id` and `quic.stream_data` are PARALLEL lists when a packet has several stream frames.
_QUIC_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "quic.stream.stream_id",
    "quic.stream_data",
# Per-STREAM-frame flag lists plus sparse offset/length values (only frames with the OFF/LEN bit set); used to reassemble retransmitted or out-of-order data offline.
    "quic.stream.off",
    "quic.stream.len",
    "quic.stream.fin",
    "quic.stream.offset",
    "quic.stream.length",
)

_QUIC_DISPLAY_FILTER = "quic.stream_data"


def build_quic_command(
    pcap: str,
    keylog: str | None,
    *,
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """argv exporting only decrypted QUIC stream data (``quic_data`` section of :data:`_EK_SECTIONS`).

    The conversion itself uses :func:`build_combined_command`. *quic_ports*
    defaults to 443; argv[0] is the literal ``"tshark"`` (callers resolve it via :func:`find_tshark`).
"""
    return _build_ek_pass(pcap, keylog, ("quic_data",), quic_ports=quic_ports,
                          extra_decode_as=extra_decode_as, heuristic=heuristic)


# QUIC versions for the fallback half of the detection filter (the ClientHello clause is primary). Decrypted HTTP/3 force-parsed as QUIC never carries these.
_KNOWN_QUIC_VERSIONS = ("1", "0x6b3343cf")  # QUIC v1 (RFC 9000), v2 (RFC 9369)

# Genuine undecryptable QUIC: a ClientHello (Initial keys derive from the public salt + DCID) or a long-header Initial with a registered version. Decrypted HTTP/3 cannot fake either; mid-connection captures without a handshake are undetectable.
_QUIC_DETECTION_DISPLAY_FILTER = (
    "tls.handshake.type == 1 || (quic.long.packet_type == 0 && ("
    + " || ".join(f"quic.version == {v}" for v in _KNOWN_QUIC_VERSIONS)
    + "))"
)


def build_quic_detection_command(
    pcap: str,
    *,
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """argv listing udp.streams carrying genuine QUIC, so the keyless plaintext path skips them.

    Same Decode-As shape as :func:`build_quic_command` (DLT_RAW needs ``udp.port==443,quic``)
    but exports only ``udp.stream`` under :data:`_QUIC_DETECTION_DISPLAY_FILTER`. argv[0] is ``"tshark"``.
"""
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]
    cmd += _heuristic_flags(heuristic)
    cmd += _decode_as_flags("udp.port", "quic", quic_ports, extra_decode_as,
                            default_port=DEFAULT_QUIC_PORT)
    cmd += ["-e", "udp.stream", "-Y", _QUIC_DETECTION_DISPLAY_FILTER]
    return cmd


# TLS-over-TCP fields for the single pass. No display field carries decrypted TLS, so the sections disable HTTP subdissectors and the plaintext arrives as ``data.data`` (a parallel list when a frame has several records). Keyed by ``tcp.stream``.
_TLS_DATA_FIELDS = (
    "frame.time_epoch",
# Per-frame provenance for TLS-riding decryptors (friTap.offline.tls_spans); read via pcap_to_tap._field.
    "frame.number",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
# The metadata pass keys by ``tls.stream``; exported so the single pass can look it up.
    "tls.stream",
    "tcp.srcport",
    "tcp.dstport",
    "data.data",
)
# Filter on tls.app_data, not data.data, so unrelated raw-TCP payloads stay out.
_TLS_DATA_DISPLAY_FILTER = "tls.app_data"
# Disabled so decrypted TLS surfaces as data.data; friTap parses it with its own parsers.
_TLS_DISABLED_SUBDISSECTORS = ("http", "http2")

# (frame.protocols token, field proving a genuinely dissected record): present only when tshark parsed real cleartext framing. plaintext_events._is_encrypted_record uses these to tell ciphertext from decrypted payload the heuristic merely tagged tls/quic; _PLAINTEXT_FIELDS derives from here too.
ENCRYPTED_RECORD_MARKERS = (
    ("tls", "tls.record.content_type"),
    ("quic", "quic.header_form"),
)

# Plaintext (no-keys) single pass: raw transport payload plus ``frame.protocols`` (e.g. "eth:ethertype:ip:tcp:tls") so streams with a tls/quic token plus record marker (ENCRYPTED_RECORD_MARKERS) are skipped.
_PLAINTEXT_FIELDS = (
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.payload",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.payload",
) + tuple(field for _proto, field in ENCRYPTED_RECORD_MARKERS)
# Every frame with transport payload; the Python side skips encrypted TLS/QUIC streams.
_PLAINTEXT_DISPLAY_FILTER = "tcp.payload or udp.payload"


def build_tls_command(
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """argv exporting only decrypted TLS app data (``tls_data`` section; plaintext arrives as ``data.data``).

    The conversion itself uses :func:`build_combined_command`; argv[0] is ``"tshark"``.
"""
    return _build_ek_pass(pcap, keylog, ("tls_data",), tls_ports=tls_ports,
                          extra_decode_as=extra_decode_as, heuristic=heuristic)


def build_plaintext_command(
    pcap: str,
    *,
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
    include_ssh: bool = False,
) -> list[str]:
    """argv for a single-pass raw-payload export without keys.

    Exports ``tcp.payload`` / ``udp.payload`` plus ``frame.protocols`` so the caller
    can skip encrypted streams; *include_ssh* adds SSH metadata rows. argv[0] is ``"tshark"``.
"""
    sections = ("plaintext", "ssh") if include_ssh else ("plaintext",)
    return _build_ek_pass(pcap, None, sections,
                          extra_decode_as=extra_decode_as, heuristic=heuristic)



# App-data row marker: ``count(tls.app_data)`` (tshark >= 4.4) is > 0 exactly where ``tls.app_data`` matches; older tshark exports the field itself. Record content types cannot substitute (opaque type 23 also marks undecryptable TLS 1.3 and decrypted handshake records).
TLS_APP_DATA_COUNT_FIELD = "count(tls.app_data)"
TLS_APP_DATA_FIELD = "tls.app_data"
_APP_DATA_COUNT_MIN_VERSION = (4, 4)

# Presence markers: requesting a protocol as a field makes `-T ek` render it on every row carrying it.
TLS_HANDSHAKE_MARKER = "tls.handshake"
QUIC_MARKER = "quic"
SSH_MARKER = "ssh"

# Placeholder in a section's field list for the version-dependent app-data marker.
_APP_DATA_MARKER_SLOT = "<tls-app-data-marker>"


def tls_app_data_marker(version: Sequence[int] | None) -> str:
    """The app-data marker field for a tshark *version* (``()``/None = unknown)."""
    if version and tuple(version) >= _APP_DATA_COUNT_MIN_VERSION:
        return TLS_APP_DATA_COUNT_FIELD
    return TLS_APP_DATA_FIELD


def is_tls_handshake_row(layers: dict) -> bool:
    """True for a row the ``tls.handshake`` filter matches (QUIC CRYPTO frames match but carry no ``tls.stream``)."""
    return ek_field(layers, TLS_HANDSHAKE_MARKER) is not None


def is_tls_app_data_row(layers: dict, marker: str = TLS_APP_DATA_COUNT_FIELD) -> bool:
    """True for a row the ``tls.app_data`` filter matches (see :func:`tls_app_data_marker`)."""
    value = ek_field(layers, marker)
    if marker != TLS_APP_DATA_COUNT_FIELD:
        return value is not None
    try:
        return int(str(ek_first(value))) > 0
    except (TypeError, ValueError):
        return False


def is_quic_row(layers: dict) -> bool:
    """True for a row the ``quic`` filter matches (QUIC metadata rows)."""
    return ek_field(layers, QUIC_MARKER) is not None


def is_quic_stream_row(layers: dict) -> bool:
    """True for a row the ``quic.stream_data`` filter matches (QUIC data rows)."""
    return ek_field(layers, "quic.stream_data") is not None


def is_ssh_row(layers: dict) -> bool:
    """True for a row the ``ssh`` filter matches (SSH metadata rows)."""
    return ek_field(layers, SSH_MARKER) is not None


def has_plaintext_payload(layers: dict) -> bool:
    """True for a row the ``tcp.payload or udp.payload`` filter matches."""
    return (ek_field(layers, "tcp.payload") is not None
            or ek_field(layers, "udp.payload") is not None)


@dataclass(frozen=True)
class _EkSection:
    """One consumer's share of a combined `-T ek` pass.

    *display_filters* are OR-ed into ``-Y``; *decode_as* is ``(dissector table, protocol, default port)``.
"""

    fields: tuple[str, ...]
    display_filters: tuple[str, ...]
    decode_as: tuple[str, str, int | None] | None = None
    disabled_protocols: tuple[str, ...] = ()


_EK_SECTIONS: dict[str, _EkSection] = {
# Handshake metadata + decrypted application data (HTTP subdissectors disabled).
    "tls": _EkSection(
        fields=(TLS_HANDSHAKE_MARKER, *_TLS_META_FIELDS, _APP_DATA_MARKER_SLOT,
                *_TLS_DATA_FIELDS),
        display_filters=("tls.handshake", "tls.app_data"),
        decode_as=("tcp.port", "tls", None),
        disabled_protocols=_TLS_DISABLED_SUBDISSECTORS,
    ),
# QUIC metadata (every QUIC row) + decrypted stream data; the clause is ``quic`` so metadata rows export.
    "quic": _EkSection(
        fields=(QUIC_MARKER, *_QUIC_META_FIELDS, *_QUIC_FIELDS),
        display_filters=("quic",),
        decode_as=("udp.port", "quic", DEFAULT_QUIC_PORT),
    ),
    "ssh": _EkSection(fields=(SSH_MARKER, *_SSH_FIELDS), display_filters=("ssh",)),
    # The data-only exports (build_tls_command / build_quic_command).
    "tls_data": _EkSection(
        fields=_TLS_DATA_FIELDS,
        display_filters=(_TLS_DATA_DISPLAY_FILTER,),
        decode_as=("tcp.port", "tls", None),
        disabled_protocols=_TLS_DISABLED_SUBDISSECTORS,
    ),
    "quic_data": _EkSection(
        fields=_QUIC_FIELDS,
        display_filters=(_QUIC_DISPLAY_FILTER,),
        decode_as=("udp.port", "quic", DEFAULT_QUIC_PORT),
    ),
    "plaintext": _EkSection(fields=_PLAINTEXT_FIELDS,
                            display_filters=(_PLAINTEXT_DISPLAY_FILTER,)),
}


def _unique(items) -> list:
    """*items* without duplicates, first occurrence kept."""
    return list(dict.fromkeys(items))


def _combined_display_filter(clauses: list[str]) -> str:
    """OR *clauses* together, parenthesizing compound ones when there are several."""
    if len(clauses) == 1:
        return clauses[0]
    return " || ".join(f"({c})" if " " in c else c for c in clauses)


def _build_ek_pass(
    pcap: str,
    keylog: str | None,
    sections: Sequence[str],
    *,
    tls_ports: Sequence[int] = (),
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
    app_data_marker: str = TLS_APP_DATA_COUNT_FIELD,
) -> list[str]:
    """One `-T ek` argv serving the named sections of :data:`_EK_SECTIONS`.

    Layout: ``tshark -r PCAP -2 -T ek``, heuristic flags, keylog, disabled
    subdissectors, the deduplicated ``-e`` union, per-section port Decode-As, the
    raw *extra_decode_as* rules once, then the OR of the sections' filters.
"""
    specs = [_EK_SECTIONS[name] for name in sections]
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]
    cmd += _heuristic_flags(heuristic)
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    for proto in _unique(p for spec in specs for p in spec.disabled_protocols):
        cmd += ["--disable-protocol", proto]
    fields = (app_data_marker if f == _APP_DATA_MARKER_SLOT else f
              for spec in specs for f in spec.fields)
    for field_name in _unique(fields):
        cmd += ["-e", field_name]
    ports_by_table = {"tcp.port": tls_ports, "udp.port": quic_ports}
    for spec in specs:
        if spec.decode_as is not None:
            table, proto, default_port = spec.decode_as
            cmd += _decode_as_flags(table, proto, ports_by_table[table], (),
                                    default_port=default_port)
    cmd += _decode_as_flags("tcp.port", "tls", (), extra_decode_as)
    clauses = _unique(c for spec in specs for c in spec.display_filters)
    cmd += ["-Y", _combined_display_filter(clauses)]
    return cmd


def build_combined_command(
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
    include_quic: bool = True,
    include_ssh: bool = True,
    app_data_marker: str = TLS_APP_DATA_COUNT_FIELD,
) -> list[str]:
    """The single keyed `-T ek` argv for all metadata and data.

    Exports TLS metadata and decrypted app data plus, unless excluded, QUIC and SSH.
    Consumers split rows with the row predicates; *app_data_marker* comes from
    :func:`tls_app_data_marker`. argv[0] is ``"tshark"``.
"""
    sections = ["tls"]
    if include_quic:
        sections.append("quic")
    if include_ssh:
        sections.append("ssh")
    return _build_ek_pass(
        pcap, keylog, sections, tls_ports=tls_ports, quic_ports=quic_ports,
        extra_decode_as=extra_decode_as, heuristic=heuristic,
        app_data_marker=app_data_marker)


def _heuristic_flags(heuristic: bool) -> list[str]:
    """``-o tcp.try_heuristic_first:TRUE`` when *heuristic* (recognizes TLS without a Decode-As rule), else ``[]``."""
    if not heuristic:
        return []
    return ["-o", "tcp.try_heuristic_first:TRUE"]


def _decode_as_flags(
    filter_key: str,
    proto: str,
    ports: Sequence[int],
    extra_decode_as: Sequence[str],
    *,
    default_port: int | None = None,
) -> list[str]:
    """tshark ``-d`` Decode-As flags for *ports* plus raw *extra* rules.

    *filter_key* is ``tcp.port`` / ``udp.port``, *proto* the dissector; empty *ports* fall back to *default_port*.
"""
    effective = list(ports) or ([default_port] if default_port is not None else [])
    flags: list[str] = []
    for port in effective:
        flags += ["-d", f"{filter_key}=={port},{proto}"]
    for rule in extra_decode_as:
        flags += ["-d", rule]
    return flags
