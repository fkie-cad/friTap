"""Does a TLS keylog actually cover the handshakes in a capture? (no TUI code)

A keylog whose client randoms never appear in the pcap converts to *0 flows*
with no hint why. This module answers the question up front and offers a rescue:

  * :func:`keylog_client_randoms` / :func:`keylog_secrets` read an NSS
    SSLKEYLOGFILE (CRLF tolerant, bounded read) into client_random -> labels /
    (label, secret) pairs.
  * :func:`read_capture_handshakes` makes ONE tshark pass over the pcap and
    returns every ClientHello (stream, client_random, SNI, negotiated version)
    plus the TLS streams that started before the capture (no ClientHello).
  * :func:`assess_coverage` (pure) compares the two; :func:`describe` turns the
    result into user-facing lines with a severity; :func:`check_keylog_coverage`
    wires the three together using the files' modification times.
  * :func:`repair_keylog` re-pairs the secrets of keylog sessions that are NOT
    in the capture to the capture's ClientHellos by trial decryption (the
    Schannel correlator), for keylogs whose secrets are right but whose client
    randoms are wrong or missing.

The label predicate :func:`is_nss_tls_label` is the single source of truth for
"is this an NSS TLS keylog label" (also used by :mod:`.keylog_suggest`).

Everything here is total for recoverable problems: unreadable files and tshark
failures degrade to empty results, never exceptions.
"""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from friTap.pipeline import TLS_KEYLOG_LABELS

logger = logging.getLogger(__name__)

# NSS labels the pipeline's set does not list; *_TRAFFIC_SECRET_N via the marker.
NSS_TLS_LABELS = TLS_KEYLOG_LABELS | {"EARLY_EXPORTER_SECRET"}
NSS_TRAFFIC_SECRET_MARKER = "_TRAFFIC_SECRET"  # {CLIENT,SERVER}_HANDSHAKE_TRAFFIC_SECRET, *_TRAFFIC_SECRET_N

DEFAULT_MAX_KEYLOG_BYTES = 4 * 1024 * 1024
_TLS12_MASTER_LABEL = "CLIENT_RANDOM"
_CLIENT_RANDOM_HEX = re.compile(r"^[0-9a-f]{64}$")
_SECRET_HEX = re.compile(r"^[0-9a-f]+$")

# A keylog flushed within this long after the capture is ordinary; beyond it the
# "sessions happened after the capture" explanation becomes plausible.
AFTER_CAPTURE_NOTE_THRESHOLD_S = 60.0

_HANDSHAKE_CLIENT_HELLO = "1"
_HANDSHAKE_SERVER_HELLO = "2"
_TLS13_VERSION = "0x0304"
_VERSION_NAMES = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

_CAPTURE_FIELDS = (
    "tcp.stream",
    "tls.handshake.type",
    "tls.handshake.random",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.version",
)


def is_nss_tls_label(label: str) -> bool:
    """True for NSS SSLKEYLOGFILE TLS labels (incl. every ``*_TRAFFIC_SECRET*``)."""
    return label in NSS_TLS_LABELS or NSS_TRAFFIC_SECRET_MARKER in label


# --------------------------------------------------------------------------
# Keylog reading
# --------------------------------------------------------------------------

def _keylog_triples(path: str, max_bytes: int) -> List[Tuple[str, str, str]]:
    """``(label, client_random, secret)`` for each valid NSS TLS line in *path*.

    Reads at most *max_bytes*; a line cut by the cap is dropped. CRLF, blank
    and ``#`` comment lines are tolerated. Never raises (unreadable -> ``[]``).
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except (OSError, TypeError, ValueError):
        logger.debug("Keylog read failed for %r", path, exc_info=True)
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if len(data) > max_bytes and lines:
        lines.pop()  # the last line may be truncated
    return [t for t in (_parse_keylog_line(line) for line in lines) if t is not None]


def _parse_keylog_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Parse one keylog line into ``(label, client_random, secret)`` or ``None``."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if len(parts) != 3 or not is_nss_tls_label(parts[0]):
        return None
    client_random, secret = parts[1].lower(), parts[2].lower()
    if not _CLIENT_RANDOM_HEX.match(client_random) or not _SECRET_HEX.match(secret):
        return None
    return parts[0], client_random, secret


def keylog_client_randoms(
    path: str, max_bytes: int = DEFAULT_MAX_KEYLOG_BYTES,
) -> Dict[str, Set[str]]:
    """Map each lowercase client_random in keylog *path* to its NSS labels."""
    out: Dict[str, Set[str]] = {}
    for label, client_random, _secret in _keylog_triples(path, max_bytes):
        out.setdefault(client_random, set()).add(label)
    return out


def keylog_secrets(
    path: str, max_bytes: int = DEFAULT_MAX_KEYLOG_BYTES,
) -> Dict[str, List[Tuple[str, str]]]:
    """Map each lowercase client_random to its ``(label, secret)`` pairs, de-duplicated."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    for label, client_random, secret in _keylog_triples(path, max_bytes):
        pairs = out.setdefault(client_random, [])
        if (label, secret) not in pairs:
            pairs.append((label, secret))
    return out


# --------------------------------------------------------------------------
# Capture reading (one tshark pass)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TlsHandshake:
    """One ClientHello seen in the capture."""

    stream: str
    client_random: str
    sni: str
    version: str  # e.g. "TLS 1.3"; "" when unknown


@dataclass(frozen=True)
class CaptureTls:
    """The TLS handshakes of a capture plus streams that began before it."""

    handshakes: Tuple[TlsHandshake, ...] = ()
    midstream_streams: Tuple[str, ...] = ()

    @property
    def client_randoms(self) -> Set[str]:
        """Every ClientHello client_random in the capture."""
        return {h.client_random for h in self.handshakes}


@dataclass
class _StreamFacts:
    """Per-stream accumulator filled from the tshark rows."""

    client_random: str = ""
    sni: str = ""
    offered_versions: List[str] = field(default_factory=list)
    client_hello_version: str = ""
    server_selected_version: str = ""
    server_hello_version: str = ""


def _values(cell: str) -> List[str]:
    """Split a tshark multi-occurrence field (``a,b,c``) into its non-empty values."""
    return [v.strip() for v in cell.split(",") if v.strip()]


def _first(cell: str) -> str:
    """First occurrence of a tshark field, or ``""``."""
    values = _values(cell)
    return values[0] if values else ""


def _normalized_random(cell: str) -> str:
    """First random of *cell* as lowercase hex without colons, or ``""``."""
    value = _first(cell).replace(":", "").lower()
    return value if _CLIENT_RANDOM_HEX.match(value) else ""


def _absorb_row(facts: _StreamFacts, row: List[str]) -> None:
    """Fold one tshark row (``_CAPTURE_FIELDS`` order) into *facts*."""
    _stream, types, randoms, sni, supported, hs_version = row
    handshake_types = _values(types)
    if _HANDSHAKE_CLIENT_HELLO in handshake_types and not facts.client_random:
        facts.client_random = _normalized_random(randoms)
        facts.sni = _first(sni)
        facts.offered_versions = _values(supported)
        facts.client_hello_version = _first(hs_version)
    elif _HANDSHAKE_SERVER_HELLO in handshake_types and not facts.server_hello_version:
        facts.server_selected_version = _first(supported)
        facts.server_hello_version = _first(hs_version)


def _negotiated_version(facts: _StreamFacts) -> str:
    """Human TLS version: ServerHello's choice, else the best the client offered."""
    if facts.server_hello_version:
        code = facts.server_selected_version or facts.server_hello_version
    elif _TLS13_VERSION in facts.offered_versions:
        code = _TLS13_VERSION
    else:
        code = facts.client_hello_version
    return _VERSION_NAMES.get(code.lower(), "")


def _stream_sort_key(stream: str) -> Tuple[int, str]:
    """Numeric-first sort key for tcp.stream ids."""
    return (int(stream), "") if stream.isdigit() else (1 << 62, stream)


def capture_tls_from_rows(rows: List[List[str]]) -> CaptureTls:
    """Build a :class:`CaptureTls` from ``_CAPTURE_FIELDS`` rows (pure)."""
    streams: Dict[str, _StreamFacts] = {}
    for row in rows:
        stream = row[0].strip()
        if stream:
            _absorb_row(streams.setdefault(stream, _StreamFacts()), row)
    handshakes: List[TlsHandshake] = []
    midstream: List[str] = []
    for stream in sorted(streams, key=_stream_sort_key):
        facts = streams[stream]
        if facts.client_random:
            handshakes.append(TlsHandshake(
                stream, facts.client_random, facts.sni, _negotiated_version(facts)))
        else:
            midstream.append(stream)
    return CaptureTls(tuple(handshakes), tuple(midstream))


def read_capture_handshakes(tshark_bin: str, pcap: str) -> CaptureTls:
    """Every TLS ClientHello in *pcap* plus the mid-stream TLS connections.

    One tshark pass over packets carrying a TLS record header (``tls.record``;
    a bare ``tls`` filter also matches 1-byte TCP keep-alives). Never raises: a
    tshark failure yields an empty :class:`CaptureTls`.
    """
    from friTap.offline.schannel.correlate import _run_fields, parse_tshark_fields

    try:
        output = _run_fields(tshark_bin, pcap, "tls.record", _CAPTURE_FIELDS)
        return capture_tls_from_rows(parse_tshark_fields(output, len(_CAPTURE_FIELDS)))
    except Exception:  # noqa: BLE001 - coverage is advisory; never break the caller
        logger.debug("Reading TLS handshakes failed for %r", pcap, exc_info=True)
        return CaptureTls()


# --------------------------------------------------------------------------
# Coverage assessment
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Coverage:
    """How well a keylog covers a capture's TLS handshakes."""

    covered: Tuple[TlsHandshake, ...] = ()
    uncovered: Tuple[TlsHandshake, ...] = ()
    midstream: int = 0
    keylog_sessions: int = 0
    keylog_sessions_in_capture: int = 0
    written_after_capture_s: Optional[float] = None

    @property
    def total(self) -> int:
        """Number of TLS handshakes in the capture."""
        return len(self.covered) + len(self.uncovered)


def _written_after_capture(
    keylog_mtime: Optional[float], capture_window: Optional[Tuple[float, float]],
) -> Optional[float]:
    """Seconds the keylog was last written AFTER the capture ended, else ``None``."""
    if keylog_mtime is None or capture_window is None:
        return None
    from friTap.offline.keylog_suggest import _gap_to_window

    if keylog_mtime <= capture_window[1]:
        return None
    return _gap_to_window(keylog_mtime, capture_window)


def assess_coverage(
    capture: CaptureTls,
    keylog_crs: "Dict[str, Set[str]] | Set[str]",
    *,
    keylog_mtime: Optional[float] = None,
    capture_window: Optional[Tuple[float, float]] = None,
) -> Coverage:
    """Compare the capture's ClientHellos with the keylog's client randoms (pure)."""
    keylog_set = {cr.lower() for cr in keylog_crs}
    covered = tuple(h for h in capture.handshakes if h.client_random in keylog_set)
    uncovered = tuple(h for h in capture.handshakes if h.client_random not in keylog_set)
    return Coverage(
        covered=covered,
        uncovered=uncovered,
        midstream=len(capture.midstream_streams),
        keylog_sessions=len(keylog_set),
        keylog_sessions_in_capture=len(keylog_set & capture.client_randoms),
        written_after_capture_s=_written_after_capture(keylog_mtime, capture_window),
    )


# --------------------------------------------------------------------------
# Human description
# --------------------------------------------------------------------------

def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    """``"1 session"`` / ``"2 sessions"``."""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _format_duration(seconds: float) -> str:
    """Coarse human duration: ``"40 s"``, ``"5 min"``, ``"2 h"``, ``"3 days"``."""
    if seconds < 60:
        return f"{int(seconds)} s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h"
    return _plural(int(seconds // 86400), "day")


def _host_summary(handshakes: Tuple[TlsHandshake, ...]) -> str:
    """``"login.live.com ×2 TLS 1.2, www.howsmyssl.com TLS 1.3"`` (first-seen order)."""
    counts = Counter((h.sni or f"stream {h.stream}", h.version) for h in handshakes)
    parts = []
    for (host, version), count in counts.items():
        text = host if count == 1 else f"{host} ×{count}"
        parts.append(f"{text} {version}" if version else text)
    return ", ".join(parts)


def _midstream_line(count: int) -> str:
    """Explain streams without a ClientHello."""
    started = "connection started" if count == 1 else "connections started"
    return f"{count} {started} before the capture and can't be decrypted."


def _sessions_line(coverage: Coverage) -> Optional[str]:
    """Explain the keylog side of a zero-coverage result."""
    sessions = coverage.keylog_sessions
    if sessions == 0:
        return "The keylog contains no TLS sessions."
    if coverage.keylog_sessions_in_capture:
        return None
    if sessions == 1:
        return "The keylog's only session does not appear in this capture."
    return f"None of the keylog's {sessions} sessions appear in this capture."


def _after_capture_line(coverage: Coverage) -> Optional[str]:
    """Explain a keylog written well after the capture stopped."""
    gap = coverage.written_after_capture_s
    if gap is None or gap < AFTER_CAPTURE_NOTE_THRESHOLD_S:
        return None
    return (
        f"The keylog was last written {_format_duration(gap)} after the capture "
        "ended — its sessions likely happened after the capture stopped."
    )


def _no_handshake_lines(coverage: Coverage) -> Tuple[str, List[str]]:
    """Severity + lines when the capture holds no ClientHello at all."""
    if coverage.midstream:
        return "warning", [
            "The capture contains no TLS handshakes to match the keylog against.",
            _midstream_line(coverage.midstream),
        ]
    return "info", ["The capture contains no TLS traffic — the TLS keylog is not needed."]


def describe(coverage: Coverage) -> Tuple[str, List[str]]:
    """``(severity, lines)`` explaining *coverage*; severity is ok/info/warning."""
    if coverage.total == 0:
        return _no_handshake_lines(coverage)
    matched, total = len(coverage.covered), coverage.total
    if matched == 0:
        severity = "warning"
        lines = [
            f"TLS keylog matches 0 of {_plural(total, 'TLS handshake')} in the capture "
            f"({_host_summary(coverage.uncovered)}).",
        ]
        lines += [line for line in (_sessions_line(coverage), _after_capture_line(coverage)) if line]
    elif coverage.uncovered:
        severity = "info"
        lines = [
            f"TLS keylog matches {matched} of {total} TLS handshakes in the capture; "
            f"not covered: {_host_summary(coverage.uncovered)}.",
        ]
    else:
        severity = "ok"
        lines = [f"TLS keylog covers {matched}/{total} TLS handshakes in the capture."]
    if coverage.midstream:
        lines.append(_midstream_line(coverage.midstream))
    return severity, lines


def _file_mtime(path: str) -> Optional[float]:
    """mtime of *path*, or ``None`` when it cannot be stat'ed."""
    try:
        return os.stat(path).st_mtime
    except (OSError, TypeError, ValueError):
        return None


def _pcap_window(pcap: str) -> Optional[Tuple[float, float]]:
    """The pcap's capture window (see ``keylog_suggest._capture_window``), or ``None``."""
    from friTap.offline.keylog_suggest import _capture_window

    try:
        return _capture_window(os.path.abspath(pcap))
    except (OSError, TypeError, ValueError):
        return None


def check_keylog_coverage(
    tshark_bin: str, pcap: str, keylog: str, capture: Optional[CaptureTls] = None,
) -> Coverage:
    """Coverage of *keylog* over *pcap*, reading the capture unless given."""
    if capture is None:
        capture = read_capture_handshakes(tshark_bin, pcap)
    return assess_coverage(
        capture,
        keylog_client_randoms(keylog),
        keylog_mtime=_file_mtime(keylog),
        capture_window=_pcap_window(pcap),
    )


# --------------------------------------------------------------------------
# Repair by trial decryption
# --------------------------------------------------------------------------

NO_REPAIR_HITS_MESSAGE = (
    "None of the keylog's secrets decrypt any session in this capture — "
    "the keys belong to different connections."
)


@dataclass(frozen=True)
class RepairResult:
    """Outcome of :func:`repair_keylog`."""

    repaired_path: Optional[str]
    matched_sessions: int
    tried_secrets: int
    message: str
    new_lines: Tuple[str, ...] = ()


ProgressCallback = Callable[[str], None]


def _orphan_secrets(
    secrets: Dict[str, List[Tuple[str, str]]], capture_crs: Set[str],
) -> Tuple[List[str], List[dict]]:
    """``(tls12 masters, tls13 records)`` of keylog sessions absent from the capture.

    TLS 1.3 records keep their label as a hint and are grouped by their original
    client_random, so a secret with no decryptable signal (EXPORTER_SECRET) rides
    along on the connection a sibling secret was placed on.
    """
    from friTap.offline.schannel.correlate import TLS12_MASTER_HEXLEN, TLS13_LABELS, TLS13_SECRET_HEXLENS

    masters: List[str] = []
    records: List[dict] = []
    for client_random, pairs in secrets.items():
        if client_random in capture_crs:
            continue
        for label, secret in pairs:
            if label == _TLS12_MASTER_LABEL and len(secret) == TLS12_MASTER_HEXLEN:
                masters.append(secret)
            elif label != _TLS12_MASTER_LABEL and len(secret) in TLS13_SECRET_HEXLENS:
                hint = label if label in TLS13_LABELS else None
                records.append({"secret": secret, "label": hint, "group": client_random})
    return list(dict.fromkeys(masters)), records


def _correlate(tshark_bin: str, pcap: str, masters: List[str], records: List[dict]) -> List[str]:
    """Trial-decrypt *masters* / *records* against *pcap*; NSS lines (never raises)."""
    from friTap.offline.schannel import correlate as sc

    try:
        lines = sc.correlate_tls12(tshark_bin, pcap, masters) if masters else []
        lines += sc.correlate_tls13(tshark_bin, pcap, records) if records else []
    except Exception:  # noqa: BLE001 - a failed rescue is a "no hits" result
        logger.debug("Keylog re-pair correlation failed for %r", pcap, exc_info=True)
        return []
    return sorted(dict.fromkeys(line.strip() for line in lines if line.strip()))


def _default_repaired_path(keylog: str) -> str:
    """``<dir>/<stem>.repaired.keylog`` next to *keylog*."""
    stem, _ext = os.path.splitext(os.path.basename(keylog))
    return os.path.join(os.path.dirname(keylog), f"{stem}.repaired.keylog")


def _write_repaired(keylog: str, new_lines: List[str], out_path: str) -> None:
    """Write the original keylog lines plus *new_lines* (LF endings) to *out_path*."""
    with open(keylog, "r", encoding="utf-8", errors="replace") as fh:
        original = [line.rstrip("\r\n") for line in fh]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(f"{line}\n" for line in original + new_lines))


def repair_keylog(
    tshark_bin: str,
    pcap: str,
    keylog: str,
    capture: Optional[CaptureTls] = None,
    out_path: Optional[str] = None,
    progress: Optional[ProgressCallback] = None,
) -> RepairResult:
    """Re-pair the secrets of keylog sessions missing from *pcap* by trial decryption.

    On any hit, ``<stem>.repaired.keylog`` (or *out_path*) is written with the
    original lines plus the re-paired ones. *progress*, when given, receives a
    short status string before the (potentially slow) tshark trials start.
    """
    if capture is None:
        capture = read_capture_handshakes(tshark_bin, pcap)
    known = keylog_secrets(keylog)
    masters, records = _orphan_secrets(known, capture.client_randoms)
    tried = len(masters) + len({r["secret"] for r in records})
    if tried == 0:
        return RepairResult(None, 0, 0, "The keylog has no secrets outside this capture to re-pair.")
    if progress is not None:
        progress(f"Trying {_plural(tried, 'secret')} against the capture…")
    new_lines = _new_keylog_lines(_correlate(tshark_bin, pcap, masters, records), known)
    if not new_lines:
        return RepairResult(None, 0, tried, NO_REPAIR_HITS_MESSAGE)
    matched = len({line.split()[1] for line in new_lines})
    target = out_path or _default_repaired_path(keylog)
    try:
        _write_repaired(keylog, new_lines, target)
    except OSError as exc:
        return RepairResult(None, matched, tried, f"Could not write the repaired keylog: {exc}", tuple(new_lines))
    message = f"Re-paired {_plural(matched, 'session')} by trial decryption; wrote {os.path.basename(target)}."
    return RepairResult(target, matched, tried, message, tuple(new_lines))


def _relabeled_path(keylog: str) -> str:
    """``<dir>/<stem>.relabeled.keylog`` next to *keylog*."""
    stem, _ext = os.path.splitext(os.path.basename(keylog))
    return os.path.join(os.path.dirname(keylog), f"{stem}.relabeled.keylog")


def _relabel_inputs(keylog: str, max_bytes: int) -> Tuple[List[str], List[dict]]:
    """All TLS secrets in *keylog* as ``(tls12 masters, tls13 records)``.

    Unlike :func:`keylog_secrets`, this keeps lines whose client_random is ``???``
    or otherwise not 64-hex — the live ncrypt/lsass hook writes those when it cannot
    correlate the ClientHello.random — so trial decryption can still place and label
    the secret. Each TLS 1.3 record carries its original label only as a *hint*
    (confirmed or overridden by decryption in :mod:`.correlate`) and its original
    client_random as a ride-along group when it is valid hex. De-duplicated.
    """
    from friTap.offline.schannel.correlate import (
        TLS12_MASTER_HEXLEN, TLS13_LABELS, TLS13_SECRET_HEXLENS,
    )
    masters: List[str] = []
    records: List[dict] = []
    seen_master: Set[str] = set()
    seen_record: Set[Tuple[Optional[str], str, Optional[str]]] = set()
    try:
        with open(keylog, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except (OSError, TypeError, ValueError):
        return [], []
    for line in data.decode("utf-8", errors="replace").splitlines():
        triple = _line_nss_triple(line)
        if triple is None:
            continue
        label, cr_raw, secret = triple
        if not _SECRET_HEX.match(secret):
            continue
        group = cr_raw if _CLIENT_RANDOM_HEX.match(cr_raw) else None
        if label == _TLS12_MASTER_LABEL:
            if len(secret) == TLS12_MASTER_HEXLEN and secret not in seen_master:
                seen_master.add(secret)
                masters.append(secret)
        elif len(secret) in TLS13_SECRET_HEXLENS:
            hint = label if label in TLS13_LABELS else None
            key = (hint, secret, group)
            if key not in seen_record:
                seen_record.add(key)
                records.append({"secret": secret, "label": hint, "group": group})
    return masters, records


def _line_nss_triple(line: str) -> Optional[Tuple[str, str, str]]:
    """``(label, client_random, secret)`` if *line* is an NSS TLS triple, else None."""
    parts = line.strip().split()
    if len(parts) == 3 and is_nss_tls_label(parts[0]):
        return parts[0], parts[1].lower(), parts[2].lower()
    return None


def _write_relabeled(keylog: str, corrected: List[str], out_path: str) -> None:
    """Write *corrected* lines plus every original line they don't supersede.

    An original NSS TLS line is dropped when its secret was authoritatively placed
    by trial decryption (so a swapped/``???`` line is replaced, not duplicated) or
    when its client_random is not valid hex (a ``???`` line trial decryption could
    not place — foreign noise). Every other line (a valid session outside this
    capture, a comment) is preserved. De-duplicated (case-insensitively on content),
    order preserved.
    """
    placed = {c.split()[-1].lower() for c in corrected if len(c.split()) == 3}
    with open(keylog, "r", encoding="utf-8", errors="replace") as fh:
        original = [ln.rstrip("\r\n") for ln in fh]
    kept: List[str] = []
    for ln in original:
        triple = _line_nss_triple(ln)
        if triple is not None:
            _label, cr, secret = triple
            if secret in placed:
                continue  # superseded by a corrected line
            if not _CLIENT_RANDOM_HEX.match(cr):
                continue  # unplaced ??? line: drop as foreign noise
        kept.append(ln)
    seen: Set[str] = set()
    deduped: List[str] = []
    for ln in kept + corrected:
        key = ln.strip().lower()
        if key in seen:
            continue
        if key:  # blank lines are kept as-is, never de-duplicated
            seen.add(key)
        deduped.append(ln)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(f"{ln}\n" for ln in deduped))


def relabel_keylog(
    tshark_bin: str,
    pcap: str,
    keylog: str,
    capture: Optional[CaptureTls] = None,  # accepted for call-site symmetry; unused
    out_path: Optional[str] = None,
    max_bytes: int = DEFAULT_MAX_KEYLOG_BYTES,
    progress: Optional[ProgressCallback] = None,
) -> RepairResult:
    """Rebuild *keylog* with authoritative TLS 1.3 labels + client_randoms.

    Every secret in the keylog — including ``???`` lines and sessions already in the
    capture — is trial-decrypted against *pcap* via
    :mod:`friTap.offline.schannel.correlate`, which assigns the true label and
    client_random by which record the secret actually decrypts. This corrects the
    live ncrypt hook's HANDSHAKE<->TRAFFIC_SECRET_0 label swap and its ``???``
    client_randoms, and drops foreign secrets that decrypt nothing in *pcap*. Writes
    ``<stem>.relabeled.keylog`` (or *out_path*) when the result differs from the
    input; a no-op otherwise. Requires tshark. Never raises for a recoverable
    problem (logs and returns a no-hit ``RepairResult``).

    Superset of :func:`repair_keylog`: it also re-pairs orphan sessions, but in
    addition relabels in-capture sessions and ingests ``???`` lines.
    """
    masters, records = _relabel_inputs(keylog, max_bytes)
    tried = len(masters) + len({r["secret"] for r in records})
    if tried == 0:
        return RepairResult(None, 0, 0, "The keylog has no TLS secrets to relabel.")
    if progress is not None:
        progress(f"Trial-decrypting {_plural(tried, 'secret')} to verify labels...")
    corrected = _correlate(tshark_bin, pcap, masters, records)
    if not corrected:
        return RepairResult(None, 0, tried, NO_REPAIR_HITS_MESSAGE)
    changed = _new_keylog_lines(corrected, keylog_secrets(keylog, max_bytes))
    if not changed:
        return RepairResult(
            None, 0, tried,
            "Every secret already carries its correct label; nothing to relabel.")
    # Count only sessions whose lines actually changed or were added — an
    # already-correct session re-emitted by correlation was not relabeled.
    matched = len({line.split()[1] for line in changed})
    target = out_path or _relabeled_path(keylog)
    try:
        _write_relabeled(keylog, corrected, target)
    except OSError as exc:
        return RepairResult(None, matched, tried,
                            f"Could not write the relabeled keylog: {exc}", tuple(corrected))
    message = (f"Relabeled {_plural(matched, 'session')} by trial decryption; "
               f"wrote {os.path.basename(target)}.")
    return RepairResult(target, matched, tried, message, tuple(corrected))


def _new_keylog_lines(lines: List[str], known: Dict[str, List[Tuple[str, str]]]) -> List[str]:
    """Correlated *lines* that are not already in the keylog."""
    existing = {f"{label} {cr} {secret}".lower() for cr, pairs in known.items() for label, secret in pairs}
    return [line for line in lines if line.lower() not in existing]


__all__ = [
    "AFTER_CAPTURE_NOTE_THRESHOLD_S",
    "DEFAULT_MAX_KEYLOG_BYTES",
    "NO_REPAIR_HITS_MESSAGE",
    "NSS_TLS_LABELS",
    "NSS_TRAFFIC_SECRET_MARKER",
    "CaptureTls",
    "Coverage",
    "RepairResult",
    "TlsHandshake",
    "assess_coverage",
    "capture_tls_from_rows",
    "check_keylog_coverage",
    "describe",
    "is_nss_tls_label",
    "keylog_client_randoms",
    "keylog_secrets",
    "relabel_keylog",
    "read_capture_handshakes",
    "repair_keylog",
]
