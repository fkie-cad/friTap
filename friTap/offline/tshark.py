#!/usr/bin/env python3

"""tshark discovery, command building and packet streaming for offline decryption.

Thin boundary to the external ``tshark`` binary. Plaintext is recovered two ways:
TLS/TCP via ``-z follow,tls,raw`` (direction-tagged by indentation; no display
field carries decrypted TLS) and QUIC via ``-T ek`` (``quic.stream_data``).

The keyed conversion runs one combined ``-T ek`` pass
(:func:`build_combined_command`). Row predicates (:func:`is_tls_handshake_row`,
...) route rows to consumers; the metadata accumulators fold them like the
``-T fields`` parsers fold their lines.
"""

from __future__ import annotations

import atexit
import contextlib
import functools
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

from .net.capture_validation import iter_pcapng_blocks

# Names stay importable from here; patched names (find_tshark, _run_capture, ...) stay below.
from .tshark_commands import (  # noqa: F401
    _APP_DATA_COUNT_MIN_VERSION,
    _APP_DATA_MARKER_SLOT,
    _EK_SECTIONS,
    _KNOWN_QUIC_VERSIONS,
    _PLAINTEXT_DISPLAY_FILTER,
    _PLAINTEXT_FIELDS,
    _QUIC_DETECTION_DISPLAY_FILTER,
    _QUIC_DISPLAY_FILTER,
    _QUIC_FIELDS,
    _TLS_DATA_DISPLAY_FILTER,
    _TLS_DATA_FIELDS,
    _TLS_DISABLED_SUBDISSECTORS,
    DEFAULT_QUIC_PORT,
    ENCRYPTED_RECORD_MARKERS,
    QUIC_MARKER,
    SSH_MARKER,
    TLS_APP_DATA_COUNT_FIELD,
    TLS_APP_DATA_FIELD,
    TLS_HANDSHAKE_MARKER,
    _build_ek_pass,
    _combined_display_filter,
    _decode_as_flags,
    _EkSection,
    _heuristic_flags,
    _unique,
    build_combined_command,
    build_plaintext_command,
    build_quic_command,
    build_quic_detection_command,
    build_tls_command,
    has_plaintext_payload,
    is_quic_row,
    is_quic_stream_row,
    is_ssh_row,
    is_tls_app_data_row,
    is_tls_handshake_row,
    tls_app_data_marker,
)
from .tshark_env import (  # noqa: F401
    _BYTE_SIZE_SUFFIXES,
    _DEFAULT_MAX_TSHARK_OUTPUT,
    _LIMIT_DISABLED_VALUES,
    _MIB,
    _MIN_TSHARK_TIMEOUT,
    _NO_OVERRIDE,
    _TSHARK_SECONDS_PER_MIB,
    TSHARK_MAX_OUTPUT_ENV,
    TSHARK_TIMEOUT_ENV,
    _capture_inputs,
    _env_limit,
    _format_seconds,
    _parse_byte_size,
    _parse_seconds,
    _total_size,
    _warn_invalid_env_once,
    tshark_max_output_bytes,
)
from .tshark_meta import (  # noqa: F401
    _QUIC_META_FIELDS,
    _SSH_FIELDS,
    _SSH_WELL_KNOWN_PORT,
    _TLS_META_FIELDS,
    CIPHER_SUITE_NAMES,
    QUIC_VERSION_NAMES,
    TLS_VERSION_NAMES,
    QuicMetadataAccumulator,
    SshConnectionAccumulator,
    TlsMetadataAccumulator,
    _anchor_endpoints,
    _banners_by_order,
    _banners_by_sender,
    _client_hello_random,
    _finalized_ssh_connection,
    _first_token,
    _map_cipher,
    _map_quic_version,
    _map_version,
    _merge_server_hello,
    _normalize_hex_codepoint,
    _padded,
    _safe_int,
    _split_types,
    _ssh_server_port,
    _stream_index,
    _swap_endpoints,
    ek_as_list,
    ek_columns,
    ek_field,
    ek_first,
    parse_ssh_fields,
)

logger = logging.getLogger(__name__)


# Cached per-process empty Wireshark config dir (see _hermetic_env).
_EMPTY_CONFIG_DIR: str | None = None


def _cleanup_empty_config_dir() -> None:
    """Remove the per-process empty Wireshark config dir at interpreter exit."""
    global _EMPTY_CONFIG_DIR
    if _EMPTY_CONFIG_DIR is not None:
        shutil.rmtree(_EMPTY_CONFIG_DIR, ignore_errors=True)
        _EMPTY_CONFIG_DIR = None


def _hermetic_env() -> dict[str, str]:
    """Environment isolating tshark from the user's Wireshark profile.

    An ambient ``tls.keylog_file`` there would make decryption depend on hidden
    machine state; an empty ``WIRESHARK_CONFIG_DIR`` leaves only friTap's ``-o``.
"""
    global _EMPTY_CONFIG_DIR
    if _EMPTY_CONFIG_DIR is None:
        _EMPTY_CONFIG_DIR = tempfile.mkdtemp(prefix="fritap-tshark-cfg-")
        atexit.register(_cleanup_empty_config_dir)
    return {**os.environ, "WIRESHARK_CONFIG_DIR": _EMPTY_CONFIG_DIR}


# pcapng Decryption Secrets Block (embedded TLS keys) type.
_PCAPNG_DSB = 0x0000000A


def capture_has_dsb(pcap_path: str) -> bool:
    """True if *pcap_path* is a pcapng with a Decryption Secrets Block (embedded TLS keys).

    Any parse/IO error returns False, so the caller fails loud instead of writing an empty ``.tap``.
    """
    try:
        with open(pcap_path, "rb") as fh:
            # Fail closed: classic pcap, non-pcapng and malformed blocks all end the walk with False.
            return any(block_type == _PCAPNG_DSB for block_type, _, _ in iter_pcapng_blocks(fh))
    except OSError:
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
    """Raised by :func:`find_tshark`; a ``RuntimeError`` so front-ends can show an install message."""


class TsharkLimitError(RuntimeError):
    """A tshark run exceeded a friTap run limit; front-ends print its message without a traceback."""


class TsharkTimeoutError(TsharkLimitError):
    """tshark outlived its budget (:func:`tshark_timeout_for`); ``timeout`` holds the seconds.

    A malformed capture can drive a dissector into an endless loop.
"""

    timeout: float | None = None


class TsharkOutputLimitError(TsharkLimitError):
    """A buffered run printed more than :func:`tshark_max_output_bytes` (``limit`` bytes) and was stopped."""

    limit: int | None = None


# Older tshark releases use unstable QUIC field names; detection only warns.
MINIMUM_RECOMMENDED_TSHARK = (4, 0)


def extract_ssh_connections(
    tshark_bin: str,
    pcap: str,
    *,
    heuristic: bool = False,
) -> list[dict]:
    """Extract SSH connection metadata from *pcap* via tshark.

    The banners and KEXINIT are plaintext, so no keys are needed. One
    ``-T fields`` pass filtered to ``ssh``; returns one dict per SSH connection.
    """
    cmd = [tshark_bin, "-r", pcap, *no_body_decompression_opts(tshark_bin)]
    cmd += _heuristic_flags(heuristic)
    cmd += ["-Y", "ssh", "-T", "fields", "-E", "separator=\t"]
    for field_name in _SSH_FIELDS:
        cmd += ["-e", field_name]

    out = _run_capture(cmd)
    return parse_ssh_fields(out)


def _resolve_executable(candidate: str) -> str | None:
    """Return an executable path for *candidate* (a path or a PATH command), or None."""
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    via_path = shutil.which(candidate)
    return via_path


def find_tshark(explicit_path: str | None = None) -> str:
    """Path to the ``tshark`` executable.

    Order: *explicit_path* (``--tshark-path``), ``FRITAP_TSHARK`` / ``TSHARK_PATH``,
    ``PATH``, common install locations. A non-executable explicit path raises at
    once; an invalid env var only warns. Raises :class:`TsharkNotFoundError`.
"""
    if explicit_path:
        resolved = _resolve_executable(explicit_path)
        if resolved:
            return resolved
        raise TsharkNotFoundError(
            f"The tshark path you provided is not an executable: {explicit_path!r}"
        )

    for env_var in _TSHARK_ENV_VARS:
        value = os.environ.get(env_var)
        if not value:
            continue
        resolved = _resolve_executable(value)
        if resolved:
            return resolved
        logger.warning("%s=%r is not an executable; ignoring it.", env_var, value)

    path = shutil.which("tshark")
    if path:
        return path

    for candidate in _TSHARK_FALLBACK_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            logger.info("tshark not on PATH; using fallback location: %s", candidate)
            return candidate

    raise TsharkNotFoundError(TSHARK_INSTALL_MESSAGE)


# Output is decoded as UTF-8 with replacement: a stray byte must never raise mid-read, or kill the stderr drain thread and hang tshark.
_TSHARK_TEXT_IO = {"encoding": "utf-8", "errors": "replace"}

# Parsed tshark --version keyed by (real path, st_mtime_ns, st_size); only non-empty results are cached, in memory and a small JSON file (skips the ~0.2 s spawn).
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
    """Version tuple from ``tshark --version``, cached per binary; ``()`` when unparseable.

    The cache key is the binary's real path, mtime and size, kept in memory and on
    disk (:func:`_tshark_version_cache_path`), so one spawn serves every conversion.
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
    """The on-disk version cache file, or ``None`` when disabled."""
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
    """Store *version* for binary *key*; failures are silent.

    One entry per real path, written to a temp file and renamed so a reader never sees a torn file.
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


def _run_probe(argv: Sequence[str]) -> str:
    """stdout of a tiny tshark probe (``--version``, ``-G defaultprefs``).

    Uses the short fixed :data:`TSHARK_PROBE_TIMEOUT`, not the size-scaled budget;
    callers treat every failure as "unknown".
"""
    return subprocess.run(
        list(argv),
        capture_output=True,
        timeout=TSHARK_PROBE_TIMEOUT,
        env=_hermetic_env(),
        **_TSHARK_TEXT_IO,
    ).stdout or ""


def _query_tshark_version(path: str) -> tuple[int, ...]:
    """Run ``tshark --version`` and parse it; ``()`` on any failure."""
    try:
        out = _run_probe([path, "--version"])
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


# Preferences that make a dissector decompress HTTP bodies; disabled on every run so an unpatched libbrotli (CVE-2026-111497) never decodes attacker-controlled bodies. Only prefs this binary reports are used (tshark exits on unknown -o).
_BODY_DECOMPRESSION_PREFS = (
    "http.decompress_body",
    "http2.decompress_body",
    "http3.decompress_body",
    "spdy.decompress_body",
    "websocket.decompress",
    "ws.decompress",
    "mime_multipart.uncompress_data",
)


@functools.lru_cache(maxsize=None)
def _supported_body_decompression_prefs(tshark_path: str) -> tuple[str, ...]:
    """The :data:`_BODY_DECOMPRESSION_PREFS` *tshark_path* knows, cached; ``()`` when the probe fails."""
    try:
        out = _run_probe([tshark_path, "-G", "defaultprefs"])
    except Exception:
        logger.debug("Could not probe tshark preferences", exc_info=True)
        return ()
    known = {line.lstrip("#").split(":", 1)[0].strip()
             for line in out.splitlines() if ":" in line}
    return tuple(p for p in _BODY_DECOMPRESSION_PREFS if p in known)


def no_body_decompression_opts(tshark_path: str = "tshark") -> list[str]:
    """``-o <pref>:FALSE`` flags disabling tshark's body decompression."""
    opts: list[str] = []
    for pref in _supported_body_decompression_prefs(tshark_path):
        opts += ["-o", f"{pref}:FALSE"]
    return opts


def with_no_body_decompression(cmd: Sequence[str]) -> list[str]:
    """*cmd* with :func:`no_body_decompression_opts` inserted after argv[0] (idempotent).

    The ``-T ek`` builders emit a ``"tshark"`` placeholder, so runners apply this once the real binary is known.
"""
    argv = list(cmd)
    if not argv:
        return argv
    opts = no_body_decompression_opts(argv[0])
    if not opts or all(flag in argv for flag in opts[1::2]):
        return argv
    return [argv[0], *opts, *argv[1:]]


def list_tls_streams(
    tshark_bin: str,
    pcap: str,
    keylog: str | None,
    *,
    tls_ports: Sequence[int] = (),
    extra_decode_as: Sequence[str] = (),
    heuristic: bool = False,
) -> list[int]:
    """Sorted unique ``tls.stream`` indices carrying app data (one ``-T fields`` pass)."""
    cmd = [tshark_bin, "-r", pcap, *no_body_decompression_opts(tshark_bin)]
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
    """Follow one TLS stream via ``-z follow,tls,raw,<stream_id>``.

    Output is the decrypted plaintext as hex, one same-direction segment per line
    (non-indented = Node 0, tab-indented = Node 1).

    Returns ``((client_addr, client_port, server_addr, server_port), segments)``;
    segments are ``(direction, data)`` in capture order, ``"write"`` = client->server.
"""
    cmd = [tshark_bin, "-r", pcap, *no_body_decompression_opts(tshark_bin)]
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
    """Parse ``follow,tls,raw`` text; see :func:`follow_tls_stream` for the return contract."""
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
        # No resolvable endpoints (e.g. handshake-only stream).
        return (("", 0, "", 0), [])

    # The TLS client usually writes app data first: a tiebreaker when no known
    # TLS port identifies the server.
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
    """Decode a tshark hex string (tolerates whitespace and ``:``); ``b""`` for empty or non-hex."""
    cleaned = value.strip().replace(":", "").replace(" ", "")
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        logger.debug("Could not hex-decode tshark payload: %.40r", value)
        return b""


def _parse_node_endpoint(text: str) -> tuple[str, int]:
    """Parse a ``Node N:`` ``addr:port`` value, splitting on the LAST colon (IPv6).

    Follow output brackets IPv6 (``[2001:db8::1]:443``); the brackets are stripped
    to match ``ipv6.src``/``ipv6.dst`` so 4-tuple keys agree across both paths.
"""
    addr, _, port = text.rpartition(":")
    if not addr:  # no colon: the whole token is the address
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
    """Which node (0 or 1) is the server.

    The endpoint on a known TLS port (443 plus *tls_ports*); only ``--tls-port``
    guarantees direction on non-standard ports. Otherwise the node that wrote first
    is the client (more reliable than port order). With no data, the smaller port is the server.
"""
    server_ports = {443, *tls_ports}
    if node0[1] in server_ports:
        return 0
    if node1[1] in server_ports:
        return 1
    if first_data_node is not None:
        # The first writer is the client, so the server is the other node.
        return 1 if first_data_node == 0 else 0
    return 0 if node0[1] <= node1[1] else 1



# Fixed budget of the tiny ``--version`` / ``-G defaultprefs`` probes.
TSHARK_PROBE_TIMEOUT = 30.0
# How long a tshark that is being stopped gets after SIGTERM before SIGKILL.
_TSHARK_KILL_GRACE = 5.0
_TSHARK_READ_CHUNK = _MIB


def tshark_timeout_for(path_or_paths) -> float | None:
    """Seconds one tshark run over *path_or_paths* may take; ``None`` = no limit.

    ``$FRITAP_TSHARK_TIMEOUT`` wins when valid (fixed seconds, or ``0`` / ``none`` to
    disable; invalid values warn and are ignored). Otherwise ``max(600, 10 * size_MiB)``.
    Unstat-able inputs count as empty. The budget covers consumer time between rows.
"""
    override = _env_limit(TSHARK_TIMEOUT_ENV, _parse_seconds)
    if override is not _NO_OVERRIDE:
        return override
    size_mib = _total_size(path_or_paths) / _MIB
    return max(_MIN_TSHARK_TIMEOUT, _TSHARK_SECONDS_PER_MIB * size_mib)


def _tshark_timeout_error(timeout: float, capture: str | None) -> TsharkTimeoutError:
    """The one-line :class:`TsharkTimeoutError` for a run stopped after *timeout* s."""
    on_capture = f" on {capture}" if capture else ""
    error = TsharkTimeoutError(
        f"tshark did not finish within {_format_seconds(timeout)} s{on_capture} "
        f"and was stopped (a malformed capture can loop a Wireshark dissector "
        f"forever); set {TSHARK_TIMEOUT_ENV}=<seconds> to allow longer runs "
        f"or {TSHARK_TIMEOUT_ENV}=0 to disable the limit.")
    error.timeout = timeout
    return error


def _tshark_output_limit_error(limit: int) -> TsharkOutputLimitError:
    """The one-line :class:`TsharkOutputLimitError` for a run past *limit* bytes."""
    error = TsharkOutputLimitError(
        f"tshark printed more than {limit} bytes of output and was stopped "
        f"before it exhausted memory; set {TSHARK_MAX_OUTPUT_ENV}=<bytes, e.g. 8G> "
        f"to raise the cap or {TSHARK_MAX_OUTPUT_ENV}=0 to disable it.")
    error.limit = limit
    return error


class _Watchdog:
    """Stops a tshark process that outlives its time budget.

    A daemon ``threading.Timer`` terminates it after *timeout* s and kills it
    :data:`_TSHARK_KILL_GRACE` s later if still alive. The dying process closes its
    pipes so the reader sees EOF; :attr:`fired` tells a timeout from a failure. It
    never touches the pipes. ``timeout=None`` arms nothing; always :meth:`cancel`
    once the process is reaped.
"""

    def __init__(self, proc, timeout: float | None) -> None:
        self.timeout = timeout
        self.fired = False
        self._proc = proc
        self._timer: threading.Timer | None = None
        if timeout is not None:
            self._timer = threading.Timer(timeout, self._expire)
            self._timer.name = "tshark-watchdog"
            self._timer.daemon = True
            self._timer.start()

    def _expire(self) -> None:
        """Timer thread: stop the process unless it already exited on its own."""
        if self._proc.poll() is not None:
            return
        self.fired = True
        logger.debug("tshark exceeded its %s s budget; stopping it",
                     _format_seconds(self.timeout))
        try:
            _terminate_then_kill(self._proc)
        except Exception:  # noqa: BLE001 - never die noisily on the timer thread
            logger.debug("Could not stop the timed-out tshark", exc_info=True)

    def cancel(self) -> None:
        """Disarm the timer and wait out a firing one, so no thread outlives the run."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer.join()


@dataclass
class _TsharkRun:
    """One spawned tshark: process, stderr summary and watchdog.

    The owner sets :attr:`completed` after reading stdout to EOF; :attr:`returncode` is set on reaping.
"""

    proc: subprocess.Popen
    stderr: _StderrSummary
    watchdog: _Watchdog
    capture: str | None
    completed: bool = False
    returncode: int | None = None

    def raise_if_timed_out(self) -> None:
        """Raise :class:`TsharkTimeoutError` when the watchdog stopped the run."""
        if self.watchdog.fired:
            raise _tshark_timeout_error(self.watchdog.timeout, self.capture)


@contextlib.contextmanager
def _tshark_process(cmd: Sequence[str], *, text: bool) -> Iterator[_TsharkRun]:
    """Spawn tshark for *cmd* under the shared time budget and always reap it.

    stderr is drained on a thread and a :class:`_Watchdog` enforces the
    :func:`tshark_timeout_for` budget. stdout is text when *text*, else bytes.
    Unless the caller marked the run completed, tshark is stopped; the process is
    waited for, the watchdog disarmed and the drain joined before the block exits.
"""
    argv = with_no_body_decompression(cmd)
    inputs = _capture_inputs(argv)
    timeout = tshark_timeout_for(inputs)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_hermetic_env(),
        **(_TSHARK_TEXT_IO if text else {}),
    )
    stderr = _StderrSummary()
    drain = _start_stderr_drain(proc, stderr.add)
    run = _TsharkRun(proc, stderr, _Watchdog(proc, timeout),
                     inputs[0] if inputs else None)
    try:
        yield run
    finally:
        try:
            if not run.completed:
                _stop_process(proc)
            run.returncode = proc.wait()
        finally:
            run.watchdog.cancel()
            if drain is not None:
                drain.join(timeout=_TSHARK_KILL_GRACE)


def _read_capped(stream, limit: int | None) -> bytearray:
    """Read binary *stream* to EOF keeping at most *limit* bytes; raises :class:`TsharkOutputLimitError` before buffering the excess."""
    buffer = bytearray()
    while True:
        chunk = stream.read(_TSHARK_READ_CHUNK)
        if not chunk:
            return buffer
        if limit is not None and len(buffer) + len(chunk) > limit:
            raise _tshark_output_limit_error(limit)
        buffer += chunk


def _decode_tshark_text(data: bytes | bytearray) -> str:
    """*data* decoded like a text-mode pipe: UTF-8 with replacement, universal newlines."""
    text = data.decode(_TSHARK_TEXT_IO["encoding"], _TSHARK_TEXT_IO["errors"])
    return text.replace("\r\n", "\n").replace("\r", "\n")


# Failure messages keep the last stderr lines plus every tshark: line that scrolled out.
_STDERR_TAIL_LINES = 20
_STDERR_TSHARK_LINES = 20
_TSHARK_MESSAGE_PREFIX = "tshark:"

# tshark's message for a capture whose last record is incomplete (exit 14 on 4.x); complete records before the cut were dissected normally.
_TRUNCATED_CAPTURE_MARKER = "cut short in the middle of a packet"


class _StderrSummary:
    """The part of tshark's stderr worth showing: the tail plus its ``tshark:`` lines.

    The real error is a ``tshark:`` line that a long listing can push out of a bare tail.
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

    For small outputs whose callers need the text whole (``-T ek`` streams through
    :func:`stream_packets`). stdout is read in bounded chunks, capped by
    :func:`tshark_max_output_bytes`, and the run by :func:`tshark_timeout_for`.
"""
    with _tshark_process(cmd, text=False) as run:
        output = _read_capped(run.proc.stdout, tshark_max_output_bytes())
        run.completed = True
    run.raise_if_timed_out()
    if run.returncode != 0:
        raise _tshark_failure(run.returncode, run.stderr)
    return _decode_tshark_text(output)


def stream_packets(cmd: Sequence[str]) -> Iterator[dict]:
    """Run *cmd* and yield one packet-source dict per decrypted packet.

    ``-T ek`` emits an ``{"index": ...}`` control line before each ``"layers"``
    object; only the latter is yielded, line by line. stderr is drained on a thread
    so a chatty tshark never stalls. When the consumer stops early (iterate under
    ``contextlib.closing`` so that also happens on error), tshark is terminated
    (killed after 5 s) and reaped.

    The :func:`tshark_timeout_for` budget includes consumer time between rows; rows
    already in the pipe are still yielded before the timeout is raised. A capture
    cut short in its last packet makes tshark exit non-zero after dissecting every
    complete packet; when packets were yielded that only warns.

    Raises:
        TsharkTimeoutError: Budget exceeded (also for a truncated capture); not
            when the consumer stopped early.
        RuntimeError: Non-zero exit, with ``tshark:`` lines and a stderr tail; not
            when the consumer stopped early or for a truncated capture with packets.
"""
    yielded = 0
    with _tshark_process(cmd, text=True) as run:
        assert run.proc.stdout is not None
        for line in run.proc.stdout:
            obj = _ek_source_object(line)
            if obj is not None:
                yielded += 1
                yield obj
        run.completed = True

    run.raise_if_timed_out()
    if run.returncode != 0:
        _raise_unless_truncated_capture(run.returncode, run.stderr, yielded)


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
    """The packet-source dict on one ``-T ek`` line; ``None`` for blank, non-JSON and ``{"index": ...}`` lines."""
    line = line.strip()
    if not line or line.startswith('{"index"'):
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

    A bad line is skipped, never a reason to stop reading (a stopped drain lets the
    pipe fill and blocks tshark). Only a pipe closed under it ends it before EOF.
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
    _terminate_then_kill(proc)


def _terminate_then_kill(proc) -> None:
    """Terminate *proc*; kill it if alive after :data:`_TSHARK_KILL_GRACE` s.

    Leaves the pipes alone (the reader may still drain them) and does not reap a killed process.
"""
    terminate = getattr(proc, "terminate", None)
    if terminate is None:
        return
    try:
        terminate()
        proc.wait(timeout=_TSHARK_KILL_GRACE)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass
