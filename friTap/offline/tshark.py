#!/usr/bin/env python3

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

The keyed conversion runs ONE combined ``-T ek`` pass
(:func:`build_combined_command`): TLS handshake metadata, decrypted TLS
application data, QUIC metadata and stream data and SSH metadata all arrive as
rows of the same export. The row predicates (:func:`is_tls_handshake_row`, ...)
tell the consumers which rows are theirs, and the metadata accumulators
(:class:`TlsMetadataAccumulator`, ...) fold those rows exactly like the
``-T fields`` parsers fold their lines.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# tshark `-T ek` field helpers
# ---------------------------------------------------------------------------

# tshark `-T ek` flattens field names by replacing '.' with '_' under the
# "layers" object. We look up both spellings so the code is robust to either.
def ek_field(layers: dict, dotted_name: str):
    """Return the raw value for *dotted_name* from a `-T ek` layers dict.

    Handles both ``"tls.app_data"`` and the flattened ``"tls_app_data"``
    spellings, and unwraps single-element lists to scalars.
    """
    value = layers.get(dotted_name)
    if value is None:
        value = layers.get(dotted_name.replace(".", "_"))
    return value


def ek_as_list(value) -> list:
    """Normalize a `-T ek` field value to a list (scalars become 1-element)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ek_first(value):
    """Return the first element of a list-or-scalar field, or None."""
    items = ek_as_list(value)
    return items[0] if items else None


def ek_columns(layers: dict, fields: Sequence[str]) -> list[str]:
    """Render *fields* of one `-T ek` row as ``-T fields`` columns.

    `-T ek` renders every ``-e`` value as a list of strings; joining each list
    with ``","`` reproduces the ``-T fields -E occurrence=a`` column exactly
    (an absent field becomes ``""``), so the column parsers below serve both
    exports.
    """
    return [",".join(str(v) for v in ek_as_list(ek_field(layers, name)))
            for name in fields]

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

# Single source of truth for the user-facing "tshark is missing" message. Both
# front-ends render this exact text: the CLI prints it, the TUI shows it in a
# modal (see TsharkNotFoundError). Keep it actionable and platform-agnostic.
TSHARK_INSTALL_MESSAGE = (
    "tshark could not be located. The offline pcap-to-tap pipeline needs it "
    "to decrypt captures. Install Wireshark/tshark (e.g. 'brew install "
    "wireshark', 'apt install tshark', or download from "
    "https://www.wireshark.org/). If it is installed in a non-standard "
    "location (e.g. macOS' Wireshark.app), pass --tshark-path /path/to/tshark "
    "or set the FRITAP_TSHARK environment variable."
)


class TsharkNotFoundError(RuntimeError):
    """Raised by :func:`find_tshark` when a usable tshark cannot be located.

    Subclasses ``RuntimeError`` so existing ``except RuntimeError`` handlers keep
    working, while letting front-ends distinguish "tshark is missing" (present a
    dedicated install message / modal) from any other conversion failure. Because
    every tshark invocation resolves the binary through ``find_tshark``, this
    exception surfaces at every call site.
    """


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
    # Per-STREAM-frame flag lists (aligned with quic.stream.stream_id) plus the
    # sparse offset/length values they gate: quic.stream.offset only has entries
    # for frames whose OFF bit is set, quic.stream.length only where LEN is set.
    # Used to reassemble retransmitted / out-of-order stream data offline.
    "quic.stream.off",
    "quic.stream.len",
    "quic.stream.fin",
    "quic.stream.offset",
    "quic.stream.length",
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

# Fields of one TLS-handshake row, IN ORDER. :class:`TlsMetadataAccumulator`
# consumes the columns by this exact position, so the order here and there
# MUST stay in lockstep.
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


def _padded(cols: Sequence[str], width: int) -> list[str]:
    """*cols* as a list padded with ``""`` to *width* (positional access never fails)."""
    cols = list(cols)
    cols.extend([""] * (width - len(cols)))
    return cols


def _stream_index(column: str) -> int | None:
    """The stream index in a stream column, or ``None`` when it has none."""
    try:
        return int(_first_token(column))
    except (ValueError, TypeError):
        return None


class TlsMetadataAccumulator:
    """Fold TLS-handshake rows into per-``tls.stream`` metadata.

    One row is the columns of :data:`_TLS_META_FIELDS` (a ``-T fields`` line, or
    a `-T ek` row via :meth:`feed_ek`). A ClientHello (handshake type ``1``)
    carries the SNI; a ServerHello (type ``2``) the SELECTED ciphersuite,
    version and ALPN. Values merge per stream, never overwriting a set value.
    Defensive: a row without a usable ``tls.stream`` is skipped.
    """

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    @property
    def by_stream(self) -> dict[int, dict]:
        """The live per-stream metadata (read-only use; see :meth:`result`)."""
        return self._by_stream

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``tls.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _TLS_META_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``tls.stream`` it touched, if any."""
        cols = _padded(cols, len(_TLS_META_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(
            stream, {"sni": "", "cipher": "", "version": "", "alpn": ""})
        types = _split_types(cols[1])
        sni = cols[2].strip()
        # ClientHello (type 1) carries the SNI.
        if "1" in types and sni and not entry["sni"]:
            entry["sni"] = sni
        # ServerHello (type 2) carries the negotiated suite/version/alpn.
        if "2" in types:
            _merge_server_hello(entry, *(c.strip() for c in cols[3:7]))
        return stream

    def result(self) -> dict[int, dict]:
        """``{tls_stream: {"sni", "cipher", "version", "alpn"}}`` (fresh copies)."""
        return {stream: dict(entry) for stream, entry in self._by_stream.items()}


def _merge_server_hello(entry: dict, ciphersuite: str, version: str,
                        supported_version: str, alpn: str) -> None:
    """Fill *entry*'s empty cipher/version/alpn from one ServerHello row."""
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


def _split_types(hs_type: str) -> list[str]:
    """Split a comma/space-joined ``tls.handshake.type`` field into tokens."""
    return [t.strip() for t in hs_type.replace(",", " ").split() if t.strip()]


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

# Fields of one QUIC metadata row, IN ORDER (:class:`QuicMetadataAccumulator`
# consumes them positionally).
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


def _anchor_endpoints(entry: dict, cols: list[str]) -> None:
    """Set *entry*'s endpoints from the first row that carries them.

    *cols* starts with the stream column, then ``ip.src``, ``ipv6.src``,
    ``ip.dst``, ``ipv6.dst``, the source port and the destination port (the
    shared prefix of :data:`_QUIC_META_FIELDS` and :data:`_SSH_FIELDS`).
    """
    src_addr = cols[1].strip() or cols[2].strip()
    if entry["src_addr"] or not src_addr:
        return
    entry["src_addr"] = src_addr
    entry["src_port"] = _safe_int(cols[5])
    entry["dst_addr"] = cols[3].strip() or cols[4].strip()
    entry["dst_port"] = _safe_int(cols[6])


class QuicMetadataAccumulator:
    """Fold QUIC rows into per-``udp.stream`` metadata.

    One row is the columns of :data:`_QUIC_META_FIELDS`. Merged per stream:
    the endpoints (first row carrying them), the transport version (first
    seen), the SNI (ClientHello, type ``1``), the negotiated cipher
    (ServerHello, type ``2``) and the ALPN (first token). Defensive: a row
    without a usable ``udp.stream`` is skipped.
    """

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``udp.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _QUIC_META_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``udp.stream`` it touched, if any."""
        cols = _padded(cols, len(_QUIC_META_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "version": "", "sni": "", "alpn": "", "cipher": "",
        })
        _anchor_endpoints(entry, cols)
        version, types = cols[7].strip(), _split_types(cols[8])
        cipher, alpn, sni = (c.strip() for c in cols[9:12])
        if version and not entry["version"]:
            entry["version"] = _map_quic_version(_first_token(version))
        # SNI comes from the ClientHello (handshake type 1) in the Initial.
        if "1" in types and sni and not entry["sni"]:
            entry["sni"] = sni
        # Negotiated cipher comes from the ServerHello (handshake type 2).
        if "2" in types and cipher and not entry["cipher"]:
            entry["cipher"] = _map_cipher(cipher)
        if alpn and not entry["alpn"]:
            entry["alpn"] = _first_token(alpn)
        return stream

    def result(self) -> dict[int, dict]:
        """``{udp_stream: {endpoints, "version", "sni", "alpn", "cipher"}}`` (copies)."""
        return {stream: dict(entry) for stream, entry in self._by_stream.items()}


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

      * the SSH banner (``ssh.protocol``) appears once from each side. Each
        banner is attributed by the port that sent it (see
        :func:`_ssh_server_port`): the server's port is 22 when one side uses
        22, else the lower of the two. Banner order is NOT used when the ports
        tell the sides apart — servers usually send their banner first.
      * ``src_*`` is the client and ``dst_*`` the server whenever the ports
        tell them apart (else the first row's sender is ``src``).
      * ``kex`` / ``cipher`` / ``mac`` are the FIRST token of the respective
        comma-joined algorithm lists (the negotiation preference order).

    Returns a list of
    ``{"src_addr","src_port","dst_addr","dst_port","client_version",
    "server_version","kex","cipher","mac"}`` dicts.

    PURE and defensive: malformed rows are skipped, never raised.

    Calibrated against tshark 4.6.5: the SSH field names and the banner
    attribution (client-first and server-first) are VERIFIED end-to-end by
    ``tests/unit/test_offline_tshark_calibration.py`` (which crafts a real SSH
    banner + KEXINIT pcap and runs the extractor through tshark when present).
    """
    accumulator = SshConnectionAccumulator()
    for line in output.splitlines():
        if line.strip():
            accumulator.feed_columns(line.split("\t"))
    return accumulator.result()


class SshConnectionAccumulator:
    """Fold SSH rows into one connection dict per ``tcp.stream``.

    One row is the columns of :data:`_SSH_FIELDS`. Banners are attributed to
    client or server by the port that sent them (:func:`_ssh_server_port`);
    ``kex`` / ``cipher`` / ``mac`` are the first token of the first non-empty
    algorithm list.
    Defensive: a row without a usable ``tcp.stream`` is skipped.
    """

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``tcp.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _SSH_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``tcp.stream`` it touched, if any."""
        cols = _padded(cols, len(_SSH_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "client_version": "", "server_version": "",
            "kex": "", "cipher": "", "mac": "",
            "_banners": [],
        })
        _anchor_endpoints(entry, cols)
        banner = cols[7].strip()
        sent = (_safe_int(cols[5]), banner)  # (sender port, banner)
        if banner and sent not in entry["_banners"]:
            entry["_banners"].append(sent)
        for key, column in (("kex", cols[8]), ("cipher", cols[9]), ("mac", cols[10])):
            value = _first_token(column)
            if value and not entry[key]:
                entry[key] = value
        return stream

    def result(self) -> list[dict]:
        """One finalized connection dict per stream (fresh dicts, no ``_banners``)."""
        return [_finalized_ssh_connection(entry) for entry in self._by_stream.values()]


_SSH_WELL_KNOWN_PORT = 22


def _finalized_ssh_connection(entry: dict) -> dict:
    """*entry* without its private banner list, client -> server oriented, with versions."""
    connection = {key: value for key, value in entry.items() if key != "_banners"}
    server_port = _ssh_server_port(connection["src_port"], connection["dst_port"])
    if server_port is None:
        client, server = _banners_by_order(entry["_banners"])
    else:
        client, server = _banners_by_sender(entry["_banners"], server_port)
        if connection["src_port"] == server_port:
            _swap_endpoints(connection)
    connection["client_version"] = client
    connection["server_version"] = server
    return connection


def _ssh_server_port(port_a: int, port_b: int) -> int | None:
    """The SSH server's port of a connection, or ``None`` when the ports cannot tell.

    The side on the well-known port 22 is the server; otherwise the lower port
    is (servers listen on fixed low ports, clients use ephemeral high ones).
    Equal or missing ports cannot tell the sides apart. ``ssh.direction`` is
    not used: under heuristic dissection tshark derives it from which side
    sent first, which is exactly the assumption this replaces.
    """
    if not port_a or not port_b or port_a == port_b:
        return None
    if _SSH_WELL_KNOWN_PORT in (port_a, port_b):
        return _SSH_WELL_KNOWN_PORT
    return min(port_a, port_b)


def _banners_by_sender(banners: list[tuple[int, str]], server_port: int) -> tuple[str, str]:
    """(client, server) banner: the first one each side sent."""
    client = next((text for port, text in banners if port != server_port), "")
    server = next((text for port, text in banners if port == server_port), "")
    return client, server


def _banners_by_order(banners: list[tuple[int, str]]) -> tuple[str, str]:
    """(client, server) banner when the ports cannot tell: first seen, next distinct."""
    texts = list(dict.fromkeys(text for _port, text in banners))
    return (texts[0] if texts else ""), (texts[1] if len(texts) > 1 else "")


def _swap_endpoints(connection: dict) -> None:
    """Swap *connection*'s ``src_*`` and ``dst_*`` endpoints in place."""
    connection["src_addr"], connection["dst_addr"] = connection["dst_addr"], connection["src_addr"]
    connection["src_port"], connection["dst_port"] = connection["dst_port"], connection["src_port"]


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
        raise TsharkNotFoundError(
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

    raise TsharkNotFoundError(TSHARK_INSTALL_MESSAGE)


# tshark's stdout (``-T ek`` JSON, follow dumps, ``--version``) and stderr are
# decoded as UTF-8 with ``errors="replace"``: a stray non-UTF-8 byte (a pcap
# comment, an interface name, a Lua plugin's message) must never raise mid-read.
# On stderr that would kill the drain thread and, once the pipe filled, hang
# tshark.
_TSHARK_TEXT_IO = {"encoding": "utf-8", "errors": "replace"}

# Parsed ``tshark --version`` results keyed by the binary's identity
# ``(real path, st_mtime_ns, st_size)``: an upgraded binary in place gets a new
# identity and so a fresh lookup. Only successful (non-empty) results are
# cached, in memory and in a small JSON file in the user cache dir (so a new
# process skips the ~0.2 s ``tshark --version`` spawn too).
_BinaryIdentity = tuple[str, int, int]
_TSHARK_VERSION_CACHE: dict[_BinaryIdentity, tuple[int, ...]] = {}

# Set to ``1`` to disable the on-disk ``tshark --version`` cache.
TSHARK_VERSION_CACHE_DISABLE_ENV = "FRITAP_NO_TSHARK_VERSION_CACHE"
_TSHARK_VERSION_CACHE_FILE = "tshark_version.json"


def _clear_tshark_version_cache() -> None:
    """Forget every in-memory ``tshark --version`` result (tests, binary swaps)."""
    _TSHARK_VERSION_CACHE.clear()


def _tshark_version_cache_key(path: str) -> _BinaryIdentity | None:
    """``(realpath, st_mtime_ns, st_size)`` of *path*, or ``None`` when it cannot be stat'ed."""
    try:
        real = os.path.realpath(path)
        stat = os.stat(real)
        return real, stat.st_mtime_ns, stat.st_size
    except (OSError, TypeError, ValueError):
        return None


def tshark_version(path: str) -> tuple[int, ...]:
    """Parse the version tuple from ``tshark --version`` (cached per binary).

    Returns an empty tuple when the version cannot be parsed (the caller
    treats that as "unknown" and skips the warning). A successful result is
    cached by the binary's real path, modification time and size, in memory
    and on disk (:func:`_tshark_version_cache_path`), so conversions spawn
    ``tshark --version`` once per tshark binary, not once per conversion.
    """
    key = _tshark_version_cache_key(path)
    if key is None:
        return _query_tshark_version(path)
    cached = _TSHARK_VERSION_CACHE.get(key) or _read_disk_tshark_version(key)
    if cached:
        _TSHARK_VERSION_CACHE[key] = cached
        return cached
    version = _query_tshark_version(path)
    if version:
        _TSHARK_VERSION_CACHE[key] = version
        _write_disk_tshark_version(key, version)
    return version


def _tshark_version_cache_path() -> str | None:
    """The on-disk version cache file, or ``None`` when the cache is disabled.

    ``$XDG_CACHE_HOME/fritap`` when that is set, else the platform's user
    cache dir (``platformdirs``), else ``~/.cache/fritap``.
    """
    if os.environ.get(TSHARK_VERSION_CACHE_DISABLE_ENV, "").strip() not in ("", "0"):
        return None
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    if xdg:
        base = os.path.join(xdg, "fritap")
    else:
        try:
            import platformdirs
            base = platformdirs.user_cache_dir("fritap")
        except Exception:  # noqa: BLE001 - any failure falls back to ~/.cache
            base = os.path.join(os.path.expanduser("~"), ".cache", "fritap")
    return os.path.join(base, _TSHARK_VERSION_CACHE_FILE)


def _load_disk_tshark_versions(cache_path: str) -> dict:
    """The cache file's ``{real path: entry}`` map; ``{}`` when missing or unreadable."""
    try:
        with open(cache_path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_disk_tshark_version(key: _BinaryIdentity) -> tuple[int, ...]:
    """The on-disk cached version for binary *key*; ``()`` on a miss or any failure."""
    cache_path = _tshark_version_cache_path()
    if cache_path is None:
        return ()
    entry = _load_disk_tshark_versions(cache_path).get(key[0])
    if not isinstance(entry, dict):
        return ()
    if entry.get("mtime_ns") != key[1] or entry.get("size") != key[2]:
        return ()
    version = entry.get("version")
    if not isinstance(version, list) or not version:
        return ()
    if not all(isinstance(part, int) and not isinstance(part, bool) for part in version):
        return ()
    return tuple(version)


def _write_disk_tshark_version(key: _BinaryIdentity, version: tuple[int, ...]) -> None:
    """Store *version* for binary *key* in the cache file; failures are silent.

    One entry per real path (a newer identity replaces the old one), written
    to a temp file and renamed into place so a reader never sees a torn file.
    """
    cache_path = _tshark_version_cache_path()
    if cache_path is None:
        return
    try:
        entries = _load_disk_tshark_versions(cache_path)
        entries[key[0]] = {"mtime_ns": key[1], "size": key[2], "version": list(version)}
        directory = os.path.dirname(cache_path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".tshark_version.", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entries, handle)
            os.replace(tmp_path, cache_path)
        except BaseException:
            _remove_quietly(tmp_path)
            raise
    except Exception:  # noqa: BLE001 - the cache is an optimisation only
        logger.debug("Could not write the tshark version cache", exc_info=True)


def _remove_quietly(path: str) -> None:
    """Delete *path*, ignoring every error."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _query_tshark_version(path: str) -> tuple[int, ...]:
    """Run ``tshark --version`` and parse it; ``()`` on any failure."""
    try:
        out = subprocess.run(
            [path, "--version"],
            capture_output=True,
            timeout=15,
            env=_hermetic_env(),
            **_TSHARK_TEXT_IO,
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
    """Build the ``tshark`` argv exporting only the decrypted QUIC stream data.

    The ``quic_data`` section of :data:`_EK_SECTIONS` on its own: QUIC's
    ``quic.stream_data`` field is already plaintext (the dissector decrypts it).
    The conversion itself reads QUIC through :func:`build_combined_command`.
    *quic_ports* defaults to 443; the argv's first element is the literal
    ``"tshark"`` (callers resolve the real path via :func:`find_tshark`).
    """
    return _build_ek_pass(pcap, keylog, ("quic_data",), quic_ports=quic_ports,
                          extra_decode_as=extra_decode_as, heuristic=heuristic)


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
# decrypted bytes are recovered indirectly: the TLS sections disable the HTTP
# subdissectors, which makes tshark hand the decrypted application data to the
# generic Data dissector — surfaced here as ``data.data`` on every app-data
# frame. ``data.data`` may be a PARALLEL list when one frame carries several
# TLS records. Keyed/demuxed by ``tcp.stream`` (the TLS stream index).
_TLS_DATA_FIELDS = (
    "frame.time_epoch",
    # Per-frame provenance for TLS-riding decryptors (friTap.offline.tls_spans);
    # surfaces as ``frame_number`` in -T ek, read via pcap_to_tap._field.
    "frame.number",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    # The handshake-metadata pass keys by ``tls.stream`` (not ``tcp.stream``);
    # exported so the single pass can look its stream's metadata up.
    "tls.stream",
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
    """Build the ``tshark`` argv exporting only the decrypted TLS application data.

    The ``tls_data`` section of :data:`_EK_SECTIONS` on its own. TLS exposes no
    decrypted display field, so the HTTP subdissectors are disabled and the
    decrypted application data falls through to ``data.data``. The conversion
    itself reads TLS through :func:`build_combined_command`. The argv's first
    element is the literal ``"tshark"`` (callers resolve the real path via
    :func:`find_tshark`).
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
        include_ssh: Also export the SSH metadata rows (``ssh`` marker plus
            :data:`_SSH_FIELDS`), so the keyless conversion reads SSH from the
            same pass. ``False`` (the default) keeps the argv unchanged.

    Returns:
        The full argv list (first element is the literal ``"tshark"``; callers
        resolve the real path via :func:`find_tshark`).
    """
    sections = ("plaintext", "ssh") if include_ssh else ("plaintext",)
    return _build_ek_pass(pcap, None, sections,
                          extra_decode_as=extra_decode_as, heuristic=heuristic)


# ---------------------------------------------------------------------------
# The combined `-T ek` pass: row markers, predicates and the argv builder
# ---------------------------------------------------------------------------

# The app-data row marker. ``count(tls.app_data)`` (tshark >= 4.4) is present on
# EVERY row and > 0 exactly on the frames the ``tls.app_data`` filter matches;
# older tshark falls back to exporting ``tls.app_data`` itself (present only on
# those frames). The record content types are NOT a substitute: an undecryptable
# TLS 1.3 record only carries opaque type 23, and a decrypted TLS 1.3 handshake
# record has opaque type 23 with content type 22.
TLS_APP_DATA_COUNT_FIELD = "count(tls.app_data)"
TLS_APP_DATA_FIELD = "tls.app_data"
_APP_DATA_COUNT_MIN_VERSION = (4, 4)

# Presence markers: requesting a protocol as a field makes `-T ek` render it on
# every row that carries it (``tls.handshake`` -> ["1"], ``quic`` -> ["quic"],
# ``ssh`` -> ["ssh"]).
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
    """True for a row the ``tls.handshake`` filter matches.

    QUIC CRYPTO frames match too but carry no ``tls.stream``, so the TLS
    metadata accumulator skips them (as the ``-T fields`` pass always did).
    """
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

    *display_filters* are OR-ed into the pass's ``-Y``; *decode_as* is the
    ``(dissector table, protocol, default port)`` its ports are decoded as.
    """

    fields: tuple[str, ...]
    display_filters: tuple[str, ...]
    decode_as: tuple[str, str, int | None] | None = None
    disabled_protocols: tuple[str, ...] = ()


_EK_SECTIONS: dict[str, _EkSection] = {
    # Handshake metadata + decrypted application data (data.data, with the
    # HTTP subdissectors disabled; see _TLS_DATA_FIELDS).
    "tls": _EkSection(
        fields=(TLS_HANDSHAKE_MARKER, *_TLS_META_FIELDS, _APP_DATA_MARKER_SLOT,
                *_TLS_DATA_FIELDS),
        display_filters=("tls.handshake", "tls.app_data"),
        decode_as=("tcp.port", "tls", None),
        disabled_protocols=_TLS_DISABLED_SUBDISSECTORS,
    ),
    # QUIC metadata (every QUIC row) + decrypted stream data. The clause must
    # be ``quic`` (not quic.stream_data) so the metadata rows are exported.
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
    """Build one `-T ek` argv serving every named section of :data:`_EK_SECTIONS`.

    Layout (shared with the single-purpose builders): ``tshark -r PCAP -2 -T ek``,
    the heuristic flags, the keylog, the disabled subdissectors, the ``-e``
    union (deduplicated, in section order), each section's port Decode-As,
    the raw *extra_decode_as* rules once, then the OR of the sections' filters.
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
    """Build the ONE keyed `-T ek` argv replacing the separate metadata/data passes.

    Exports the TLS handshake metadata and decrypted application data, and
    (unless excluded) the QUIC metadata and stream data and the SSH metadata,
    filtered to ``tls.handshake || tls.app_data || quic || ssh``. Consumers tell
    their rows apart with the row predicates (:func:`is_tls_handshake_row`, ...);
    *app_data_marker* comes from :func:`tls_app_data_marker`.

    Returns:
        The full argv list (first element is the literal ``"tshark"``; callers
        resolve the real path via :func:`find_tshark`).
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


# How many stderr lines a tshark failure message keeps: the last lines, plus
# every ``tshark:``-prefixed line (the actual error) that scrolled out of them.
_STDERR_TAIL_LINES = 20
_STDERR_TSHARK_LINES = 20
_TSHARK_MESSAGE_PREFIX = "tshark:"

# tshark's message for a capture whose last record is incomplete (exit 14 on
# 4.x): "The file ... appears to have been cut short in the middle of a packet."
# Every complete record before the cut was dissected normally.
_TRUNCATED_CAPTURE_MARKER = "cut short in the middle of a packet"


class _StderrSummary:
    """The part of tshark's stderr worth showing: the tail plus its ``tshark:`` lines.

    tshark prints the real error as a ``tshark:`` line and may follow it with a
    long listing (``-d`` with an unknown protocol lists every valid one), so a
    bare tail would lose the line that explains the failure.
    """

    def __init__(self) -> None:
        self.tail: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        self.tshark_lines: deque[str] = deque(maxlen=_STDERR_TSHARK_LINES)

    def add(self, line: str) -> None:
        """Record one stderr line (trailing newline stripped)."""
        line = line.rstrip("\r\n")
        self.tail.append(line)
        if line.startswith(_TSHARK_MESSAGE_PREFIX):
            self.tshark_lines.append(line)

    def text(self) -> str:
        """The ``tshark:`` lines missing from the tail, then the tail itself."""
        tail = list(self.tail)
        scrolled_out = [line for line in self.tshark_lines if line not in tail]
        return "\n".join(scrolled_out + tail)

    def reports_truncated_capture(self) -> bool:
        """True when tshark said the capture was cut short in a packet."""
        return any(_TRUNCATED_CAPTURE_MARKER in line
                   for line in (*self.tshark_lines, *self.tail))


def _summarize_stderr(stderr_text: str) -> _StderrSummary:
    """A :class:`_StderrSummary` of a complete stderr text."""
    summary = _StderrSummary()
    for line in stderr_text.splitlines():
        summary.add(line)
    return summary


def _tshark_failure(returncode: int, stderr: _StderrSummary) -> RuntimeError:
    """The ``RuntimeError`` raised for a tshark run that exited *returncode*."""
    return RuntimeError(
        f"tshark exited with code {returncode}.\n"
        f"--- tshark stderr (tail) ---\n{stderr.text()}"
    )


def _run_capture(cmd: Sequence[str]) -> str:
    """Run *cmd* and return its stdout, raising on a non-zero exit.

    Used for the small fixed-size outputs (stream lists, single-stream follow);
    the streaming ``-T ek`` path uses :func:`stream_packets` instead.
    """
    proc = subprocess.run(
        list(cmd),
        capture_output=True,
        env=_hermetic_env(),
        **_TSHARK_TEXT_IO,
    )
    if proc.returncode != 0:
        raise _tshark_failure(proc.returncode, _summarize_stderr(proc.stderr or ""))
    return proc.stdout


def stream_packets(cmd: Sequence[str]) -> Iterator[dict]:
    """Run *cmd* and yield one packet-source dict per decrypted packet.

    The ``-T ek`` (Elasticsearch bulk) format emits two lines per packet: an
    ``{"index": ...}`` control line followed by the actual source object that
    holds the requested fields under a ``"layers"`` key. We skip the index
    lines and yield only the source dicts. Output is consumed line-by-line so
    arbitrarily large captures never load fully into memory.

    stderr is drained concurrently (a thread keeps its tail and its ``tshark:``
    lines), so a chatty tshark can never fill the stderr pipe and stall; both
    pipes decode with ``errors="replace"`` so a non-UTF-8 byte cannot stop the
    drain. When the consumer stops early (closes the generator — iterate it
    under ``contextlib.closing`` so that also happens when the consumer
    raises), tshark's stdout is closed and the process terminated (killed
    after 5 s), so it is always reaped.

    A capture cut short in the middle of its last packet makes tshark exit
    non-zero after dissecting every complete packet; when packets were yielded
    that is logged as a warning instead of raised, so the readable part still
    converts.

    Raises:
        RuntimeError: When tshark completes with a non-zero exit, with its
            ``tshark:`` error lines and a tail of stderr. Not raised when the
            consumer stopped early, nor for a truncated capture that yielded
            packets.
    """
    proc = subprocess.Popen(
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_hermetic_env(),
        **_TSHARK_TEXT_IO,
    )

    stderr = _StderrSummary()
    drain = _start_stderr_drain(proc, stderr.add)
    assert proc.stdout is not None
    completed = False
    yielded = 0
    try:
        for line in proc.stdout:
            obj = _ek_source_object(line)
            if obj is not None:
                yielded += 1
                yield obj
        completed = True
    finally:
        if not completed:
            _stop_process(proc)
        returncode = proc.wait()
        if drain is not None:
            drain.join(timeout=5)

    if completed and returncode != 0:
        _raise_unless_truncated_capture(returncode, stderr, yielded)


def _raise_unless_truncated_capture(returncode: int, stderr: _StderrSummary,
                                    yielded: int) -> None:
    """Raise the tshark failure, or only warn for a truncated capture that yielded rows."""
    if yielded and stderr.reports_truncated_capture():
        logger.warning(
            "The capture is truncated (tshark exit %d after %d rows): its last "
            "packet is incomplete; converting the readable part.",
            returncode, yielded)
        logger.debug("tshark stderr (tail):\n%s", stderr.text())
        return
    raise _tshark_failure(returncode, stderr)


def _ek_source_object(line: str) -> dict | None:
    """The packet-source dict on one ``-T ek`` line, or ``None`` for any other line.

    Skips blank lines, non-JSON lines and the ``{"index": ...}`` control lines;
    only objects carrying a ``"layers"`` payload are packets.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        logger.debug("Skipping non-JSON tshark line: %.120r", line)
        return None
    if isinstance(obj, dict) and "layers" in obj:
        return obj
    return None


def _start_stderr_drain(proc, sink: Callable[[str], None]) -> threading.Thread | None:
    """Feed *proc*'s stderr lines to *sink* on a daemon thread (``None`` without stderr).

    The thread reads until EOF, whatever the lines contain: a line that fails
    to decode or that *sink* rejects is skipped, never a reason to stop reading
    (a stopped drain lets the pipe fill and blocks tshark forever). Only a pipe
    closed under it (the process was stopped early) ends it before EOF.
    """
    stream = getattr(proc, "stderr", None)
    if stream is None:
        return None

    def drain() -> None:
        lines = iter(stream)
        while True:
            try:
                line = next(lines)
            except StopIteration:
                return
            except UnicodeError:
                continue  # defensive: errors="replace" decoding never raises
            except (OSError, ValueError):
                return  # the pipe was closed under us (process stopped early)
            _feed_stderr_line(sink, line)

    thread = threading.Thread(target=drain, name="tshark-stderr", daemon=True)
    thread.start()
    return thread


def _feed_stderr_line(sink: Callable[[str], None], line) -> None:
    """Hand one stderr *line* (``str`` or ``bytes``) to *sink*, swallowing its errors."""
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    try:
        sink(line)
    except Exception:  # noqa: BLE001 - the drain must outlive any bad line
        logger.debug("Dropping a tshark stderr line", exc_info=True)


def _stop_process(proc) -> None:
    """Close *proc*'s stdout and terminate it (kill after 5 s) when still running."""
    stdout = getattr(proc, "stdout", None)
    close = getattr(stdout, "close", None)
    if close is not None:
        try:
            close()
        except OSError:
            pass
    poll = getattr(proc, "poll", None)
    if poll is not None and poll() is not None:
        return  # already exited
    terminate = getattr(proc, "terminate", None)
    if terminate is None:
        return
    try:
        terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass
