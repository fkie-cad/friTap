#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""tshark discovery, command building, and packet streaming for offline decryption.

This module is the thin boundary between friTap and the external ``tshark``
binary. It locates tshark and exposes two decryption strategies:

* **TLS/TCP** (HTTP/1.1, HTTP/2, WebSocket): tshark's ``-z follow,tls,raw``
  yields the *decrypted* plaintext bytes of a TLS stream, direction-tagged by
  indentation. There is no generic "decrypted TLS" display field, so Follow is
  the only reliable way to recover plaintext. We enumerate the TLS streams,
  then follow each one.
* **QUIC** (HTTP/3): ``quic.stream_data`` is already decrypted by the QUIC
  dissector, so a single ``-T ek`` export recovers the plaintext directly.

Both paths feed friTap's existing parsers; no protocol parsing is duplicated.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections import deque
from typing import Iterator, Sequence

logger = logging.getLogger(__name__)

# Cached per-process empty Wireshark config dir (see _hermetic_env).
_EMPTY_CONFIG_DIR: str | None = None


def _cleanup_empty_config_dir() -> None:
    """Remove the per-process empty Wireshark config dir on interpreter exit.

    ``_hermetic_env`` mkdtemp's ``_EMPTY_CONFIG_DIR`` once and reuses it for the
    whole process; without this it would leak a temp directory per process. We
    clean up only at exit so the directory stays valid for every tshark
    invocation during the run. ``ignore_errors=True`` makes shutdown robust to a
    dir already removed by other means.
    """
    global _EMPTY_CONFIG_DIR
    if _EMPTY_CONFIG_DIR is not None:
        shutil.rmtree(_EMPTY_CONFIG_DIR, ignore_errors=True)
        _EMPTY_CONFIG_DIR = None


def _hermetic_env() -> dict[str, str]:
    """Return an environment that isolates tshark from the user's Wireshark profile.

    tshark otherwise reads ``~/.config/wireshark`` (or ``%APPDATA%\\Wireshark``),
    which can carry an ambient ``tls.keylog_file`` preference. That made offline
    decryption depend on hidden machine state: a capture would silently
    "decrypt" using the user's profile keylog and then fail on another machine
    or after the profile changed. Pointing ``WIRESHARK_CONFIG_DIR`` at an empty
    directory forces decryption to depend ONLY on what friTap passes explicitly
    via ``-o tls.keylog_file``.
    """
    global _EMPTY_CONFIG_DIR
    if _EMPTY_CONFIG_DIR is None:
        _EMPTY_CONFIG_DIR = tempfile.mkdtemp(prefix="fritap-tshark-cfg-")
        # Reap the temp dir at interpreter exit so we don't leak one per process.
        atexit.register(_cleanup_empty_config_dir)
    return {**os.environ, "WIRESHARK_CONFIG_DIR": _EMPTY_CONFIG_DIR}


# pcapng Section Header Block type (byte-order independent palindrome) and the
# Decryption Secrets Block type that carries embedded TLS key material.
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_DSB = 0x0000000A
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
# Classic .pcap magics (us/ns resolution, both byte orders). A classic pcap
# cannot carry a DSB — there is no block structure for embedded secrets.
_PCAP_CLASSIC_MAGICS = frozenset({
    0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1,
})


def capture_has_dsb(pcap_path: str) -> bool:
    """Return True if *pcap_path* is a pcapng carrying a Decryption Secrets Block.

    A DSB embeds TLS key material directly in the capture, so it self-decrypts
    without an external keylog. Classic ``.pcap`` files cannot carry one. The
    offline pipeline uses this to decide whether decryption can proceed when no
    ``--keylog`` was supplied. Any parse/IO error returns False — "unknown"
    is treated as "no embedded keys" so the caller fails loud rather than
    silently producing an empty ``.tap``.
    """
    try:
        with open(pcap_path, "rb") as fh:
            magic = fh.read(4)
            if len(magic) < 4:
                return False
            if (int.from_bytes(magic, "little") in _PCAP_CLASSIC_MAGICS
                    or int.from_bytes(magic, "big") in _PCAP_CLASSIC_MAGICS):
                return False  # classic pcap — no DSB possible
            if int.from_bytes(magic, "big") != _PCAPNG_SHB:
                return False  # not a pcapng we recognize

            # The first block is the SHB: total length (4) + byte-order magic (4).
            rest = fh.read(8)
            if len(rest) < 8:
                return False
            if int.from_bytes(rest[4:8], "little") == _PCAPNG_BYTE_ORDER_MAGIC:
                endian = "little"
            elif int.from_bytes(rest[4:8], "big") == _PCAPNG_BYTE_ORDER_MAGIC:
                endian = "big"
            else:
                return False

            shb_total_len = int.from_bytes(rest[0:4], endian)
            if shb_total_len < 12:
                return False
            fh.seek(shb_total_len)  # skip past the SHB to the first block

            while True:
                header = fh.read(8)
                if len(header) < 8:
                    break
                block_type = int.from_bytes(header[0:4], endian)
                if block_type == _PCAPNG_DSB:
                    return True
                block_total_len = int.from_bytes(header[4:8], endian)
                if block_total_len < 12:
                    break  # malformed length — stop walking
                fh.seek(block_total_len - 8, os.SEEK_CUR)
    except OSError:
        return False
    return False

# Environment variables that may point directly at a tshark binary.
_TSHARK_ENV_VARS = ("FRITAP_TSHARK", "TSHARK_PATH")

# Common install locations checked when tshark is not on PATH. tshark is
# frequently NOT on PATH on macOS (bundled inside Wireshark.app) and Windows.
_TSHARK_FALLBACK_PATHS = (
    "/Applications/Wireshark.app/Contents/MacOS/tshark",  # macOS bundle
    "/opt/homebrew/bin/tshark",                           # macOS (Apple-silicon brew)
    "/usr/local/bin/tshark",                              # macOS (Intel brew) / Linux
    "/usr/bin/tshark",                                    # Linux
    r"C:\Program Files\Wireshark\tshark.exe",             # Windows
    r"C:\Program Files (x86)\Wireshark\tshark.exe",       # Windows (32-bit)
)

# tshark releases below this version use older/unstable QUIC field names.
# We warn (never hard-fail) when an older tshark is detected.
MINIMUM_RECOMMENDED_TSHARK = (4, 0)

# Default QUIC server port included when no explicit --quic-port is given.
DEFAULT_QUIC_PORT = 443

# QUIC-only fields requested from the `-T ek` export (one per `-e`). QUIC's
# stream payload is already decrypted by the dissector, so unlike TLS it can be
# pulled from a display field. `quic.stream.stream_id` and `quic.stream_data`
# are PARALLEL lists when a packet carries multiple stream frames.
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
)

# Display filter for the QUIC export: only packets carrying decrypted QUIC
# stream payload.
_QUIC_DISPLAY_FILTER = "quic.stream_data"


# ---------------------------------------------------------------------------
# TLS handshake metadata (offline, plaintext handshake fields)
# ---------------------------------------------------------------------------

# Map the common modern TLS ciphersuite codepoints to their IANA/OpenSSL names.
# Unknown codepoints are passed through verbatim (hex passthrough) so a capture
# with an exotic suite still records *something* rather than dropping the value.
CIPHER_SUITE_NAMES: dict[str, str] = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0xc02f": "ECDHE-RSA-AES128-GCM-SHA256",
    "0xc02b": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "0xc030": "ECDHE-RSA-AES256-GCM-SHA384",
    "0xc02c": "ECDHE-ECDSA-AES256-GCM-SHA384",
}

# Map the TLS version codepoints to display strings. Unknown codepoints are
# passed through verbatim (hex passthrough).
TLS_VERSION_NAMES: dict[str, str] = {
    "0x0304": "TLS 1.3",
    "0x0303": "TLS 1.2",
    "0x0302": "TLS 1.1",
    "0x0301": "TLS 1.0",
}

# Fields requested for the TLS-handshake metadata pass, IN ORDER. The parser
# (:func:`parse_tls_metadata_fields`) consumes the tab-separated columns by
# this exact position, so the order here and there MUST stay in lockstep.
# NOTE the dotted ``tls.handshake.extensions.supported_version`` (the TLS 1.3
# negotiated version) vs. the underscored extension fields around it.
_TLS_META_FIELDS = (
    "tls.stream",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str",
)


def _normalize_hex_codepoint(value: str) -> str:
    """Return *value* lowercased and zero-padded to ``0xNNNN`` when hex-like.

    tshark may render a codepoint as ``0x1301``, ``0x1301`` upper/lower, or
    sometimes a bare decimal. We canonicalize the common ``0x`` form so the
    name-table lookups hit; anything we cannot canonicalize is returned
    stripped so it can pass through verbatim.
    """
    token = value.strip()
    if not token:
        return ""
    low = token.lower()
    if low.startswith("0x"):
        digits = low[2:]
        if digits and all(c in "0123456789abcdef" for c in digits):
            return "0x" + digits.zfill(4)
        return low
    return token


def _map_cipher(raw: str) -> str:
    """Map a raw ciphersuite codepoint to a name, else pass the hex through."""
    canon = _normalize_hex_codepoint(raw)
    if not canon:
        return ""
    return CIPHER_SUITE_NAMES.get(canon, canon)


def _map_version(raw: str) -> str:
    """Map a raw TLS version codepoint to a name, else pass the hex through."""
    canon = _normalize_hex_codepoint(raw)
    if not canon:
        return ""
    return TLS_VERSION_NAMES.get(canon, canon)


def _first_token(value: str) -> str:
    """Return the first comma-joined token of *value* (tshark occurrence=a)."""
    for token in value.split(","):
        token = token.strip()
        if token:
            return token
    return ""


def parse_tls_metadata_fields(output: str) -> dict[int, dict]:
    """Parse a TLS-handshake ``-T fields`` dump into per-stream metadata.

    The dump has one row per matching packet, tab-separated, with columns in
    the order of :data:`_TLS_META_FIELDS`. A ClientHello (handshake type ``1``)
    carries the SNI; a ServerHello (handshake type ``2``) carries the SELECTED
    ciphersuite, version and ALPN. We merge per ``tls.stream`` across rows,
    never overwriting an already-set value with an empty one.

    Returns ``{tls_stream_index: {"sni", "cipher", "version", "alpn"}}``.

    This is the PURE, unit-tested core. It is defensive: malformed rows are
    skipped, never raised.

    Calibrated against tshark 4.6.5: the field names (incl. the dotted
    ``tls.handshake.extensions.supported_version``) and the ``0xNNNN`` hex
    rendering of ciphersuite/version are VERIFIED end-to-end by
    ``tests/unit/test_offline_tshark_calibration.py`` (which crafts a real TLS
    handshake pcap and runs the extractor through tshark when it is installed).
    """
    result: dict[int, dict] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        # Pad to the expected width so positional access never IndexErrors.
        while len(cols) < len(_TLS_META_FIELDS):
            cols.append("")
        try:
            stream = int(_first_token(cols[0]))
        except (ValueError, TypeError):
            continue  # no usable tls.stream -> skip the row

        hs_type = cols[1]
        sni = cols[2].strip()
        ciphersuite = cols[3].strip()
        version = cols[4].strip()
        supported_version = cols[5].strip()
        alpn = cols[6].strip()

        entry = result.setdefault(
            stream, {"sni": "", "cipher": "", "version": "", "alpn": ""})

        # ClientHello (type 1) carries the SNI.
        if "1" in _split_types(hs_type) and sni and not entry["sni"]:
            entry["sni"] = sni

        # ServerHello (type 2) carries the negotiated suite/version/alpn.
        if "2" in _split_types(hs_type):
            if ciphersuite and not entry["cipher"]:
                entry["cipher"] = _map_cipher(ciphersuite)
            # Prefer the TLS 1.3 supported_version extension over the legacy
            # handshake.version (which is frozen at 0x0303 for TLS 1.3).
            mapped_version = ""
            if supported_version:
                mapped_version = _map_version(_first_token(supported_version))
            elif version:
                mapped_version = _map_version(_first_token(version))
            if mapped_version and not entry["version"]:
                entry["version"] = mapped_version
            if alpn and not entry["alpn"]:
                entry["alpn"] = _first_token(alpn)

    return result


def _split_types(hs_type: str) -> list[str]:
    """Split a comma/space-joined ``tls.handshake.type`` field into tokens."""
    return [t.strip() for t in hs_type.replace(",", " ").split() if t.strip()]


def extract_tls_metadata(
    tshark_bin: str,
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> dict[int, dict]:
    """Extract per-stream TLS handshake metadata from *pcap* via tshark.

    Runs a single ``-T fields`` pass over the TLS handshake records and hands
    the raw text to the pure :func:`parse_tls_metadata_fields`. The handshake
    is PLAINTEXT, so no keylog is strictly required for SNI/ALPN/version, but
    we pass it through (and honor decode-as/heuristic flags) for parity with
    the follow path.

    Returns ``{tls_stream_index: {"sni", "cipher", "version", "alpn"}}``.
    """
    cmd = [tshark_bin, "-r", pcap]
    cmd += _heuristic_flags(heuristic)
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += _decode_as_flags("tcp.port", "tls", tls_ports, extra_decode_as)
    cmd += ["-Y", "tls.handshake", "-T", "fields",
            "-E", "separator=\t", "-E", "occurrence=a"]
    for field_name in _TLS_META_FIELDS:
        cmd += ["-e", field_name]

    out = _run_capture(cmd)
    return parse_tls_metadata_fields(out)


# ---------------------------------------------------------------------------
# QUIC metadata (transport version + the TLS handshake carried inside QUIC)
# ---------------------------------------------------------------------------

# Map QUIC transport version codepoints (FT_UINT32, rendered "0x00000001") to
# short display strings. Unknown versions pass through verbatim.
QUIC_VERSION_NAMES: dict[str, str] = {
    "0x00000001": "1",          # RFC 9000 (QUIC v1)
    "0x6b3343cf": "2",          # RFC 9369 (QUIC v2)
    "0xff00001d": "draft-29",   # common pre-RFC draft still seen in the wild
}

# Fields for the QUIC metadata pass, IN ORDER (parser consumes positionally).
# quic.version is plaintext (long header); the cipher/ALPN come from the TLS
# handshake carried inside QUIC (SNI/ClientHello is decryptable from the Initial
# secret without a keylog; the negotiated cipher/ALPN need the keylog).
_QUIC_META_FIELDS = (
    "udp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "quic.version",
    "tls.handshake.type",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.extensions_server_name",
)


def _map_quic_version(raw: str) -> str:
    """Map a raw QUIC version codepoint to a short name, else pass it through."""
    token = raw.strip().lower()
    if not token:
        return ""
    return QUIC_VERSION_NAMES.get(token, token)


def parse_quic_metadata_fields(output: str) -> dict[int, dict]:
    """Parse a QUIC ``-T fields`` dump into per-(udp.stream) metadata.

    One row per matching packet, tab-separated, columns in the order of
    :data:`_QUIC_META_FIELDS`. Merged per ``udp.stream``: the transport version
    (first seen), the negotiated cipher (from the ServerHello, handshake type
    ``2``) and the ALPN (first token), plus the connection endpoints (anchored
    from the first row that carries them).

    Returns ``{udp_stream_index: {"src_addr","src_port","dst_addr","dst_port",
    "version","sni","alpn","cipher"}}``.

    Calibrated against tshark 4.6.5: the field names and the ``quic.version``
    ``0xNNNNNNNN`` rendering are VERIFIED by the gated calibration test (which
    crafts a QUIC Initial long header). The SNI comes from the ClientHello in the
    Initial packet (decryptable from the Initial secret without a keylog); the
    negotiated cipher/ALPN come from the QUIC-embedded TLS Handshake and require
    the keylog. The grouping is unit-tested with synthetic rows. PURE/defensive.
    """
    result: dict[int, dict] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        while len(cols) < len(_QUIC_META_FIELDS):
            cols.append("")
        try:
            stream = int(_first_token(cols[0]))
        except (ValueError, TypeError):
            continue

        src_addr = cols[1].strip() or cols[2].strip()
        dst_addr = cols[3].strip() or cols[4].strip()
        src_port = _safe_int(cols[5])
        dst_port = _safe_int(cols[6])
        version = cols[7].strip()
        hs_type = cols[8]
        cipher = cols[9].strip()
        alpn = cols[10].strip()
        sni = cols[11].strip()

        entry = result.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "version": "", "sni": "", "alpn": "", "cipher": "",
        })

        if not entry["src_addr"] and src_addr:
            entry["src_addr"] = src_addr
            entry["src_port"] = src_port
            entry["dst_addr"] = dst_addr
            entry["dst_port"] = dst_port

        if version and not entry["version"]:
            entry["version"] = _map_quic_version(_first_token(version))
        # SNI comes from the ClientHello (handshake type 1) in the Initial.
        if "1" in _split_types(hs_type) and sni and not entry["sni"]:
            entry["sni"] = sni
        # Negotiated cipher comes from the ServerHello (handshake type 2).
        if "2" in _split_types(hs_type) and cipher and not entry["cipher"]:
            entry["cipher"] = _map_cipher(cipher)
        if alpn and not entry["alpn"]:
            entry["alpn"] = _first_token(alpn)

    return result


def extract_quic_metadata(
    tshark_bin: str,
    pcap: str,
    keylog: str | None,
    *,
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> dict[int, dict]:
    """Extract per-(udp.stream) QUIC metadata from *pcap* via tshark.

    Runs a single ``-T fields`` pass over QUIC packets and hands the raw text to
    the pure :func:`parse_quic_metadata_fields`. ``quic.version`` is plaintext;
    the negotiated cipher/ALPN are recovered from the QUIC-embedded TLS handshake
    when *keylog* decrypts the Handshake packets.

    Returns ``{udp_stream_index: {... ,"version","alpn","cipher"}}``.
    """
    cmd = [tshark_bin, "-r", pcap]
    cmd += _heuristic_flags(heuristic)
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += _decode_as_flags("udp.port", "quic", quic_ports, extra_decode_as,
                            default_port=DEFAULT_QUIC_PORT)
    cmd += ["-Y", "quic", "-T", "fields",
            "-E", "separator=\t", "-E", "occurrence=a"]
    for field_name in _QUIC_META_FIELDS:
        cmd += ["-e", field_name]

    out = _run_capture(cmd)
    return parse_quic_metadata_fields(out)


# ---------------------------------------------------------------------------
# SSH plaintext metadata (banners + KEXINIT — no keys needed)
# ---------------------------------------------------------------------------

# Fields requested for the SSH metadata pass, IN ORDER. The parser
# (:func:`parse_ssh_fields`) consumes these tab-separated columns positionally,
# so the order here and there MUST stay in lockstep.
_SSH_FIELDS = (
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "ssh.protocol",
    "ssh.kex_algorithms",
    "ssh.encryption_algorithms_client_to_server",
    "ssh.mac_algorithms_client_to_server",
)


def parse_ssh_fields(output: str) -> list[dict]:
    """Parse an SSH ``-T fields`` dump into one dict per SSH connection.

    The dump has one row per matching SSH packet, tab-separated, with columns
    in the order of :data:`_SSH_FIELDS`. We merge per ``tcp.stream``:

      * the SSH banner (``ssh.protocol``) appears once from each side — the two
        DISTINCT banner values are the client and server versions. We attribute
        the first banner seen to the client and the next distinct one to the
        server (the SSH client sends its banner first).
      * ``kex`` / ``cipher`` / ``mac`` are the FIRST token of the respective
        comma-joined algorithm lists (the negotiation preference order).

    Returns a list of
    ``{"src_addr","src_port","dst_addr","dst_port","client_version",
    "server_version","kex","cipher","mac"}`` dicts.

    PURE and defensive: malformed rows are skipped, never raised.

    Calibrated against tshark 4.6.5: the SSH field names and the
    client-banner-first attribution are VERIFIED end-to-end by
    ``tests/unit/test_offline_tshark_calibration.py`` (which crafts a real SSH
    banner + KEXINIT pcap and runs the extractor through tshark when present).
    """
    by_stream: dict[int, dict] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        while len(cols) < len(_SSH_FIELDS):
            cols.append("")
        try:
            stream = int(_first_token(cols[0]))
        except (ValueError, TypeError):
            continue

        src_addr = cols[1].strip() or cols[2].strip()
        dst_addr = cols[3].strip() or cols[4].strip()
        src_port = _safe_int(cols[5])
        dst_port = _safe_int(cols[6])
        banner = cols[7].strip()
        kex = _first_token(cols[8])
        cipher = _first_token(cols[9])
        mac = _first_token(cols[10])

        entry = by_stream.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "client_version": "", "server_version": "",
            "kex": "", "cipher": "", "mac": "",
            "_banners": [],
        })

        # Anchor the connection endpoints from the first row that has them.
        if not entry["src_addr"] and src_addr:
            entry["src_addr"] = src_addr
            entry["src_port"] = src_port
            entry["dst_addr"] = dst_addr
            entry["dst_port"] = dst_port

        if banner and banner not in entry["_banners"]:
            entry["_banners"].append(banner)

        if kex and not entry["kex"]:
            entry["kex"] = kex
        if cipher and not entry["cipher"]:
            entry["cipher"] = cipher
        if mac and not entry["mac"]:
            entry["mac"] = mac

    connections: list[dict] = []
    for entry in by_stream.values():
        banners = entry.pop("_banners")
        # First banner = client (client sends its banner first); second
        # distinct banner = server.
        if banners:
            entry["client_version"] = banners[0]
        if len(banners) > 1:
            entry["server_version"] = banners[1]
        connections.append(entry)
    return connections


def _safe_int(value: str, default: int = 0) -> int:
    """Best-effort int from a (possibly comma-joined) tshark field token."""
    token = _first_token(value)
    try:
        return int(token)
    except (ValueError, TypeError):
        return default


def extract_ssh_connections(
    tshark_bin: str,
    pcap: str,
    *,
    heuristic: bool = False,
) -> list[dict]:
    """Extract SSH connection metadata from *pcap* via tshark.

    The SSH handshake (banners + KEXINIT) is PLAINTEXT, so no keys are needed.
    Runs a single ``-T fields`` pass filtered to ``ssh`` and hands the raw text
    to the pure :func:`parse_ssh_fields`. Returns one dict per SSH connection
    (empty list when the capture carries no SSH).
    """
    cmd = [tshark_bin, "-r", pcap]
    cmd += _heuristic_flags(heuristic)
    cmd += ["-Y", "ssh", "-T", "fields", "-E", "separator=\t"]
    for field_name in _SSH_FIELDS:
        cmd += ["-e", field_name]

    out = _run_capture(cmd)
    return parse_ssh_fields(out)


def extract_ipsec_connections(
    tshark_bin: str,
    pcap: str,
    *,
    heuristic: bool = False,
) -> list[dict]:
    """STUB: extract IPsec (IKE/ESP) connection metadata from *pcap*.

    Returns an empty list for now. Real IKE/ESP metadata extraction (IKE
    version, negotiated encryption/integrity/DH transforms) is future work and
    is intentionally not wired into the offline conversion yet.

    TODO(real-tshark): implement using ``isakmp.*`` / ``esp.*`` fields.
    """
    return []


def _resolve_executable(candidate: str) -> str | None:
    """Return an executable path for *candidate*, or None.

    Accepts either a full path to a binary or a bare command name resolvable
    via PATH.
    """
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    via_path = shutil.which(candidate)
    return via_path


def find_tshark(explicit_path: str | None = None) -> str:
    """Return the path to the ``tshark`` executable.

    Resolution order: (1) *explicit_path* (e.g. ``--tshark-path``), (2) the
    ``FRITAP_TSHARK`` / ``TSHARK_PATH`` env vars, (3) ``PATH``, (4) common
    install locations (notably macOS' ``Wireshark.app`` bundle and Windows'
    ``Program Files``, where tshark is usually NOT on ``PATH``).

    Args:
        explicit_path: A user-supplied tshark path/command. When given but not
            executable, raises immediately (don't silently ignore user intent).

    Raises:
        RuntimeError: When tshark cannot be located, with an actionable message.
    """
    # 1. Explicit path — honor user intent; fail loudly if wrong.
    if explicit_path:
        resolved = _resolve_executable(explicit_path)
        if resolved:
            return resolved
        raise RuntimeError(
            f"The tshark path you provided is not an executable: {explicit_path!r}"
        )

    # 2. Environment variables — warn and continue if set but invalid.
    for env_var in _TSHARK_ENV_VARS:
        value = os.environ.get(env_var)
        if not value:
            continue
        resolved = _resolve_executable(value)
        if resolved:
            return resolved
        logger.warning("%s=%r is not an executable; ignoring it.", env_var, value)

    # 3. PATH.
    path = shutil.which("tshark")
    if path:
        return path

    # 4. Common install locations off PATH (macOS bundle, Windows, etc.).
    for candidate in _TSHARK_FALLBACK_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            logger.info("tshark not on PATH; using fallback location: %s", candidate)
            return candidate

    raise RuntimeError(
        "tshark could not be located. The offline pcap-to-tap pipeline needs it "
        "to decrypt captures. Install Wireshark/tshark (e.g. 'brew install "
        "wireshark', 'apt install tshark', or download from "
        "https://www.wireshark.org/). If it is installed in a non-standard "
        "location (e.g. macOS' Wireshark.app), pass --tshark-path /path/to/tshark "
        "or set the FRITAP_TSHARK environment variable."
    )


def tshark_version(path: str) -> tuple[int, ...]:
    """Parse the version tuple from ``tshark --version``.

    Returns an empty tuple when the version cannot be parsed (the caller
    treats that as "unknown" and skips the warning).
    """
    try:
        out = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            env=_hermetic_env(),
        ).stdout
    except Exception:
        logger.debug("Could not run 'tshark --version'", exc_info=True)
        return ()

    return _parse_version_numbers(out)


def _parse_version_numbers(version_output: str) -> tuple[int, ...]:
    """Extract the first dotted-numeric run (e.g. '4.2.0') from version text."""
    for token in version_output.replace(",", " ").split():
        parts = token.split(".")
        if len(parts) >= 2 and all(p.isdigit() for p in parts):
            return tuple(int(p) for p in parts)
    return ()


def warn_if_outdated(version: tuple[int, ...]) -> None:
    """Log a warning when *version* is below the recommended minimum."""
    if version and version < MINIMUM_RECOMMENDED_TSHARK:
        recommended = ".".join(str(n) for n in MINIMUM_RECOMMENDED_TSHARK)
        found = ".".join(str(n) for n in version)
        logger.warning(
            "tshark %s is older than the recommended %s; QUIC field names may "
            "be unstable and decryption results may be incomplete.",
            found, recommended,
        )


def build_quic_command(
    pcap: str,
    keylog: str | None,
    *,
    quic_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """Build the ``tshark`` argv for exporting decrypted QUIC stream data.

    QUIC's ``quic.stream_data`` field is already plaintext (the dissector
    decrypts it), so a single ``-T ek`` export recovers HTTP/3 payloads. TLS
    decryption is handled separately via :func:`follow_tls_stream`.

    Args:
        pcap: Path to the encrypted capture (pcap or pcapng).
        keylog: Path to an NSS SSLKEYLOGFILE. ``None`` for a DSB-embedded
            pcapng that already carries its own keys.
        quic_ports: Extra UDP ports to Decode-As QUIC. 443 is always included
            when this is empty.
        extra_decode_as: Raw ``-d`` rule strings passed through verbatim.
        heuristic: Enable tshark's TCP heuristic-first dissection (see
            :func:`_heuristic_flags`).

    Returns:
        The full argv list (the first element is the literal ``"tshark"``;
        callers resolve the real path via :func:`find_tshark`).
    """
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]

    cmd += _heuristic_flags(heuristic)

    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]

    for field in _QUIC_FIELDS:
        cmd += ["-e", field]

    cmd += _decode_as_flags("udp.port", "quic", quic_ports, extra_decode_as,
                            default_port=DEFAULT_QUIC_PORT)
    cmd += ["-Y", _QUIC_DISPLAY_FILTER]
    return cmd


# QUIC versions whose long-header Initial tshark recognizes — the FALLBACK half of
# the detection filter (the ClientHello clause is the primary, version-INDEPENDENT
# signal). A genuine Initial carries one of these in its CLEARTEXT version field
# (not under header protection); decrypted HTTP/3 force-parsed as QUIC never hits
# these exact values (verified: zero matches). A brand-new version is still caught
# via its ClientHello, so this list is belt-and-suspenders — but extend it as IANA
# registers versions to keep the fallback current.
_KNOWN_QUIC_VERSIONS = ("1", "0x6b3343cf")  # QUIC v1 (RFC 9000), v2 (RFC 9369)

# A capture carries a genuine, undecryptable QUIC connection when tshark sees a
# QUIC ClientHello (it derives Initial keys from the public salt + client DCID — no
# private keys needed) OR a long-header Initial bearing a registered version. Both
# are impossible for friTap's decrypted HTTP/3 to fake, so this filter never
# matches a decrypted capture. Captures with no handshake (mid-connection 1-RTT)
# carry no such marker and are intentionally NOT detectable without keys.
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
    """Build the ``tshark`` argv that lists udp.streams carrying genuine QUIC.

    Used by the KEYLESS plaintext path to find encrypted-QUIC streams it must skip
    rather than ingest as bogus plaintext. Mirrors :func:`build_quic_command`'s
    Decode-As/heuristic shape (QUIC is only dissected on DLT_RAW captures when a
    ``udp.port==443,quic`` rule is supplied), but exports ONLY ``udp.stream`` and
    filters to :data:`_QUIC_DETECTION_DISPLAY_FILTER` — a conservative,
    zero-false-positive handshake marker. The plaintext pass itself stays
    Decode-As-free, so this detection never alters how decrypted bytes are read.

    Args:
        pcap: Path to the capture (pcap or pcapng).
        quic_ports: Extra UDP ports to Decode-As QUIC. 443 is always included
            when this is empty.
        extra_decode_as: Raw ``-d`` rule strings passed through verbatim.
        heuristic: Enable tshark's TCP heuristic-first dissection.

    Returns:
        The full argv list (first element is the literal ``"tshark"``; callers
        resolve the real path via :func:`find_tshark`).
    """
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]
    cmd += _heuristic_flags(heuristic)
    cmd += _decode_as_flags("udp.port", "quic", quic_ports, extra_decode_as,
                            default_port=DEFAULT_QUIC_PORT)
    cmd += ["-e", "udp.stream", "-Y", _QUIC_DETECTION_DISPLAY_FILTER]
    return cmd


# TLS-over-TCP fields for the single-pass decrypted-data export. There is NO
# decrypted-TLS display field (``tls.app_data`` is the ENCRYPTED record), so the
# decrypted bytes are recovered indirectly: build_tls_command disables the HTTP
# subdissectors, which makes tshark hand the decrypted application data to the
# generic Data dissector — surfaced here as ``data.data`` on every app-data
# frame. ``data.data`` may be a PARALLEL list when one frame carries several
# TLS records. Keyed/demuxed by ``tcp.stream`` (the TLS stream index).
_TLS_DATA_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "data.data",
)
# Select only frames carrying a TLS Application Data record (the decrypted
# bytes live in data.data on the SAME frame). Filtering on tls.app_data — rather
# than on data.data — scopes the export strictly to TLS, so unrelated raw-TCP
# payloads that also produce data.data are never ingested.
_TLS_DATA_DISPLAY_FILTER = "tls.app_data"
# Subdissectors disabled so decrypted TLS app data surfaces as data.data rather
# than being consumed by tshark's own parsing (friTap re-parses the cleartext
# with its own protocol parsers, so tshark's interpretation is unwanted).
_TLS_DISABLED_SUBDISSECTORS = ("http", "http2")

# (frame.protocols token -> tshark field that proves a genuinely-dissected
# record). A real TLS record / QUIC packet exposes cleartext framing even without
# keys, so the field is present ONLY when tshark actually parsed one. friTap.offline
# .pcap_to_tap._is_encrypted_record uses these to tell genuine cipher-text from
# payload the heuristic dissector merely *tagged* "tls"/"quic" (e.g. friTap's own
# decrypted HTTP/2 on TCP/443). Declared once here because the field must be
# exported in _PLAINTEXT_FIELDS AND looked up by the consumer — the two MUST stay
# in lockstep, so both derive from this single source.
ENCRYPTED_RECORD_MARKERS = (
    ("tls", "tls.record.content_type"),
    ("quic", "quic.header_form"),
)

# Fields for the plaintext (no-keys) single-pass: the raw transport payload of an
# already-cleartext capture, plus the per-frame protocol stack so encrypted
# (TLS/QUIC) streams can be detected and skipped. frame.protocols looks like
# "eth:ethertype:ip:tcp:tls"; a "tls"/"quic" token PLUS its record marker (see
# ENCRYPTED_RECORD_MARKERS) marks a stream that needs keys and cannot be ingested.
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
# Export every frame that carries raw transport payload. TLS/QUIC frames also
# match (their records ride in tcp.payload/udp.payload), so the Python side skips
# those streams by inspecting frame.protocols PLUS a corroborating record marker
# (see ENCRYPTED_RECORD_MARKERS) — keeping the tshark side simple.
_PLAINTEXT_DISPLAY_FILTER = "tcp.payload or udp.payload"


def build_tls_command(
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """Build the ``tshark`` argv for a SINGLE-pass decrypted TLS export.

    Replaces the per-stream ``-z follow,tls,raw`` model (one full-pcap pass per
    TLS stream, O(streams x pcap)) with one ``-T ek`` pass demuxed in Python,
    mirroring :func:`build_quic_command`. Because TLS exposes no decrypted
    display field, the HTTP subdissectors are disabled so the decrypted
    application data falls through to ``data.data`` (validated byte-for-byte
    against ``follow,tls,raw`` — see ``TASK_offline_tls_singlepass.md``).

    Args:
        pcap: Path to the encrypted capture (pcap or pcapng).
        keylog: Path to an NSS SSLKEYLOGFILE, or ``None`` for a DSB-embedded
            pcapng that carries its own keys.
        tls_ports: Extra TCP ports to Decode-As TLS.
        extra_decode_as: Raw ``-d`` rule strings passed through verbatim.
        heuristic: Enable tshark's TCP heuristic-first dissection.

    Returns:
        The full argv list (first element is the literal ``"tshark"``; callers
        resolve the real path via :func:`find_tshark`).
    """
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]

    cmd += _heuristic_flags(heuristic)

    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]

    for proto in _TLS_DISABLED_SUBDISSECTORS:
        cmd += ["--disable-protocol", proto]

    for field in _TLS_DATA_FIELDS:
        cmd += ["-e", field]

    cmd += _decode_as_flags("tcp.port", "tls", tls_ports, extra_decode_as)
    cmd += ["-Y", _TLS_DATA_DISPLAY_FILTER]
    return cmd


def build_plaintext_command(
    pcap: str,
    *,
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[str]:
    """Build the ``tshark`` argv for a SINGLE-pass raw-payload export (no keys).

    For an already-plaintext capture there is nothing to decrypt: the application
    bytes ARE the raw transport payload. We export ``tcp.payload`` / ``udp.payload``
    in one ``-T ek`` pass (mirroring :func:`build_tls_command`) and let friTap's
    own parsers reconstruct the protocols. ``frame.protocols`` is exported so the
    caller can detect and skip encrypted (TLS/QUIC) streams that would need keys.

    Args:
        pcap: Path to the capture (pcap or pcapng).
        extra_decode_as: Raw ``-d`` rule strings passed through verbatim.
        heuristic: Enable tshark's TCP heuristic-first dissection.

    Returns:
        The full argv list (first element is the literal ``"tshark"``; callers
        resolve the real path via :func:`find_tshark`).
    """
    cmd: list[str] = ["tshark", "-r", pcap, "-2", "-T", "ek"]
    cmd += _heuristic_flags(heuristic)
    for field in _PLAINTEXT_FIELDS:
        cmd += ["-e", field]
    # No port-based Decode-As (plaintext has no protocol to map a port to); reuse
    # the shared helper purely to append the raw `-d` rules, as every other
    # command builder does, so extra_decode_as handling stays consistent.
    cmd += _decode_as_flags("tcp.port", "tls", (), extra_decode_as)
    cmd += ["-Y", _PLAINTEXT_DISPLAY_FILTER]
    return cmd


def _heuristic_flags(heuristic: bool) -> list[str]:
    """Build the tshark ``-o`` flags that enable TLS-over-TCP heuristic dissection.

    When *heuristic* is True we ask tshark to attempt heuristic dissectors first
    on TCP payloads (``tcp.try_heuristic_first``), so TLS carried on a
    non-standard port that has no Decode-As rule still gets recognized. Returns
    an empty list when *heuristic* is False, so callers can splice the result
    unconditionally without changing the default command shape.
    """
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
    """Build tshark ``-d`` Decode-As flags for *ports* + raw *extra* rules.

    *filter_key* is the dissector-table field (``tcp.port`` / ``udp.port``),
    *proto* the dissector (``tls`` / ``quic``). When *ports* is empty and
    *default_port* is given, that port is used (QUIC defaults to 443).
    """
    effective = list(ports) or ([default_port] if default_port is not None else [])
    flags: list[str] = []
    for port in effective:
        flags += ["-d", f"{filter_key}=={port},{proto}"]
    for rule in extra_decode_as:
        flags += ["-d", rule]
    return flags


def list_tls_streams(
    tshark_bin: str,
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[int]:
    """Return the sorted, unique ``tls.stream`` indices carrying app data.

    Runs a fast ``-T fields`` pass filtered to ``tls.app_data`` and collects
    the distinct ``tls.stream`` values. These indices are then fed one at a
    time to :func:`follow_tls_stream`. When *heuristic* is True, TCP
    heuristic-first dissection is enabled so TLS on unconfigured ports is found.
    """
    cmd = [tshark_bin, "-r", pcap]
    cmd += _heuristic_flags(heuristic)
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += _decode_as_flags("tcp.port", "tls", tls_ports, extra_decode_as)
    cmd += ["-Y", "tls.app_data", "-T", "fields", "-e", "tls.stream"]

    out = _run_capture(cmd)
    streams: set[int] = set()
    for line in out.splitlines():
        # A single packet may report multiple comma-joined stream ids.
        for token in line.replace(",", " ").split():
            try:
                streams.add(int(token))
            except ValueError:
                continue
    return sorted(streams)


def follow_tls_stream(
    tshark_bin: str,
    pcap: str,
    stream_id: int,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> tuple[tuple[str, int, str, int], list[tuple[str, bytes]]]:
    """Follow one TLS stream and return its endpoints and decrypted segments.

    Uses ``-z follow,tls,raw,<stream_id>``, whose output gives the *decrypted*
    plaintext of the stream as hex, one contiguous same-direction segment per
    line (non-indented = Node 0's data, tab-indented = Node 1's data).

    Returns:
        A ``((client_addr, client_port, server_addr, server_port), segments)``
        tuple. ``segments`` is a list of ``(direction, data)`` pairs in capture
        order, where direction is ``"write"`` for client->server bytes and
        ``"read"`` for server->client bytes.
    """
    cmd = [tshark_bin, "-r", pcap]
    cmd += _heuristic_flags(heuristic)
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += _decode_as_flags("tcp.port", "tls", tls_ports, extra_decode_as)
    cmd += ["-q", "-z", f"follow,tls,raw,{stream_id}"]

    output = _run_capture(cmd)
    return _parse_follow_output(output, tls_ports=tls_ports)


def _parse_follow_output(
    output: str,
    *,
    tls_ports: Sequence[int] = (),
) -> tuple[tuple[str, int, str, int], list[tuple[str, bytes]]]:
    """Parse ``follow,tls,raw`` text into endpoints and direction-tagged data.

    See :func:`follow_tls_stream` for the return contract.
    """
    node0: tuple[str, int] | None = None
    node1: tuple[str, int] | None = None
    raw_segments: list[tuple[int, bytes]] = []  # (node_index, data)

    for line in output.splitlines():
        if line.startswith("Node 0:"):
            node0 = _parse_node_endpoint(line.split(":", 1)[1].strip())
        elif line.startswith("Node 1:"):
            node1 = _parse_node_endpoint(line.split(":", 1)[1].strip())
        elif _is_follow_hex_line(line):
            # Tab-indented lines belong to Node 1; non-indented to Node 0.
            node_index = 1 if line[0] == "\t" else 0
            data = decode_hex(line)
            if data:
                raw_segments.append((node_index, data))

    if node0 is None or node1 is None:
        # Stream had no resolvable endpoints (e.g. handshake-only) — nothing
        # to reconstruct.
        return (("", 0, "", 0), [])

    # The node that produced the first data segment is, in a normal TLS
    # exchange, the client (the TLS client writes application data first). We
    # pass it as a tiebreaker for when no known TLS port identifies the server.
    first_data_node = raw_segments[0][0] if raw_segments else None
    server_index = _server_node_index(
        node0, node1, tls_ports, first_data_node=first_data_node,
    )
    client_node = node1 if server_index == 0 else node0
    server_node = node0 if server_index == 0 else node1

    segments = [
        ("read" if node_index == server_index else "write", data)
        for node_index, data in raw_segments
    ]
    endpoints = (client_node[0], client_node[1], server_node[0], server_node[1])
    return endpoints, segments


def _is_follow_hex_line(line: str) -> bool:
    """True when *line* is a follow data segment (hex, possibly tab-indented)."""
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(("=", "Follow:", "Filter:", "Node ")):
        return False
    return all(c in "0123456789abcdefABCDEF:" for c in stripped)


def decode_hex(value: str) -> bytes:
    """Decode a tshark hex string to bytes (tab/whitespace/':'-separator tolerant).

    Shared by the Follow-stream parser and the QUIC ``-T ek`` packet decoder.
    Returns ``b""`` for empty or non-hex input.
    """
    cleaned = value.strip().replace(":", "").replace(" ", "")
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        logger.debug("Could not hex-decode tshark payload: %.40r", value)
        return b""


def _parse_node_endpoint(text: str) -> tuple[str, int]:
    """Parse a ``Node N:`` ``addr:port`` value, splitting on the LAST colon.

    IPv6 addresses contain colons, so the port is everything after the final
    colon and the address is the remainder. tshark brackets IPv6 endpoints in
    follow output (``[2001:db8::1]:443``); we strip the brackets so the address
    matches friTap's canonical unbracketed form (the same form tshark's
    ``ipv6.src``/``ipv6.dst`` fields use), keeping the 4-tuple key consistent
    across the follow-stream and field-based paths.
    """
    addr, _, port = text.rpartition(":")
    if not addr:  # no colon at all — treat the whole token as the address
        addr, port = text, "0"
    if addr.startswith("[") and addr.endswith("]"):  # bracketed IPv6: [::1]:443
        addr = addr[1:-1]
    try:
        return addr, int(port)
    except ValueError:
        return addr, 0


def _server_node_index(
    node0: tuple[str, int],
    node1: tuple[str, int],
    tls_ports: Sequence[int],
    *,
    first_data_node: int | None = None,
) -> int:
    """Return which node (0 or 1) is the server endpoint.

    The server is the endpoint whose port is a known TLS port (443 plus any
    ``tls_ports``). For correct read/write direction labelling on non-standard
    TLS ports you MUST pass the server port via ``--tls-port``; that is the only
    way to guarantee the server side is identified.

    When no known TLS port matches we fall back to the first data segment's
    direction: in a normal TLS exchange the client writes application data
    first, so the node that produced the first segment (*first_data_node*) is
    the client and the other node is the server. This is more reliable than the
    old "smaller port wins" heuristic, which inverted direction whenever the
    server port happened to be larger than the client's ephemeral port. If no
    data segment is available we keep the smaller-port tiebreaker as a last
    resort.
    """
    server_ports = {443, *tls_ports}
    if node0[1] in server_ports:
        return 0
    if node1[1] in server_ports:
        return 1
    # No known TLS port: prefer the first-data-segment direction tiebreaker.
    if first_data_node is not None:
        # The first writer is the client, so the server is the OTHER node.
        return 1 if first_data_node == 0 else 0
    return 0 if node0[1] <= node1[1] else 1


def _run_capture(cmd: Sequence[str]) -> str:
    """Run *cmd* and return its stdout, raising on a non-zero exit.

    Used for the small fixed-size outputs (stream lists, single-stream follow);
    the streaming ``-T ek`` path uses :func:`stream_packets` instead.
    """
    proc = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        env=_hermetic_env(),
    )
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.splitlines()[-20:])
        raise RuntimeError(
            f"tshark exited with code {proc.returncode}.\n"
            f"--- tshark stderr (tail) ---\n{tail}"
        )
    return proc.stdout


def stream_packets(cmd: Sequence[str]) -> Iterator[dict]:
    """Run *cmd* and yield one packet-source dict per decrypted packet.

    The ``-T ek`` (Elasticsearch bulk) format emits two lines per packet: an
    ``{"index": ...}`` control line followed by the actual source object that
    holds the requested fields under a ``"layers"`` key. We skip the index
    lines and yield only the source dicts. Output is consumed line-by-line so
    arbitrarily large captures never load fully into memory.

    Raises:
        RuntimeError: When tshark exits non-zero, with a tail of stderr.
    """
    proc = subprocess.Popen(
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_hermetic_env(),
    )

    stderr_tail: deque[str] = deque(maxlen=20)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON tshark line: %.120r", line)
                continue
            # Skip ek index control lines; yield only source objects (those
            # carrying a "layers" payload).
            if "index" in obj and "layers" not in obj:
                continue
            if "layers" in obj:
                yield obj
    finally:
        # Drain any remaining stderr for diagnostics.
        if proc.stderr is not None:
            for err_line in proc.stderr:
                stderr_tail.append(err_line.rstrip("\n"))
        returncode = proc.wait()

    if returncode != 0:
        tail = "\n".join(stderr_tail)
        raise RuntimeError(
            f"tshark exited with code {returncode}.\n--- tshark stderr (tail) ---\n{tail}"
        )
