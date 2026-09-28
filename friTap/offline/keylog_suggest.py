"""Suggest a keylog for a pcap and sniff which picker protocol a keylog is for.

Pure helpers (no TUI code) used by the pcap-to-tap wizard:

  * :func:`suggest_keylog_for_pcap` looks for a sibling ``*key*.log`` /
    ``*key*.keylog`` file captured alongside the pcap — first by a matching
    timestamp in the filename, then by the file times closest to the capture.
  * With the capture's client randoms (``capture_crs``), candidates are first
    ranked by CONTENT — how many of those client randoms each keylog covers
    (:func:`rank_keylogs_by_coverage`); :func:`suggest_keylog_with_evidence`
    also reports that count for the hint.
  * :func:`sniff_keylog_protocol` reads the first lines of a keylog and returns
    the keylog-picker entry (``tls`` / ``custom`` / ``mtproto``) it belongs to.

Both are total: any I/O or parse failure yields ``None``, never an exception.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import AbstractSet, Callable, Dict, Iterable, List, Optional, Tuple

from friTap.offline.keylog_coverage import (
    is_nss_tls_label,
    keylog_client_randoms,
)
from friTap.offline.keylog_paths import canonical_keylog_path
from friTap.offline.keylog_picker import CUSTOM_PICKER_NAME, TLS_PICKER_NAME
from friTap.offline.schannel.unpaired import SIDECAR_KINDS

logger = logging.getLogger(__name__)

# Keylogs are often flushed after the capture stops (e.g. a memory scan of
# lsass at the end of a session), so allow a few minutes of slack.
DEFAULT_MAX_DELTA_S = 600
KEYLOG_EXTENSIONS = (".log", ".keylog")
MTPROTO_PICKER_NAME = "mtproto"

_COMPACT_TOKEN = re.compile(
    r"(?<!\d)(\d{4})(\d{2})(\d{2})[_\-T](\d{2})(\d{2})(\d{2})?(?!\d)"
)
_DASHED_TOKEN = re.compile(
    r"(?<!\d)(\d{4})-(\d{2})-(\d{2})[_T ](\d{2})[-:.](\d{2})(?:[-:.](\d{2}))?(?!\d)"
)
_EPOCH_TOKEN = re.compile(r"(?<!\d)(\d{10})(?!\d)")
_EPOCH_MIN = 1_000_000_000
_EPOCH_MAX = 2_000_000_000

_MAX_LINE_CHARS = 8192
# Per-candidate read cap when ranking keylogs by content.
MAX_RANK_KEYLOG_BYTES = 4 * 1024 * 1024


# --------------------------------------------------------------------------
# Filename timestamp tokens
# --------------------------------------------------------------------------

def _datetime_from_groups(groups: Tuple[Optional[str], ...]) -> Optional[datetime]:
    """Build a datetime from ``(Y, M, D, h, m, s?)`` regex groups, or ``None``."""
    try:
        year, month, day, hour, minute = (int(g) for g in groups[:5])
        second = int(groups[5]) if groups[5] else 0
        return datetime(year, month, day, hour, minute, second)
    except (TypeError, ValueError):
        return None


def _epoch_datetime(groups: Tuple[Optional[str], ...]) -> Optional[datetime]:
    """Naive LOCAL datetime for an epoch-seconds group, or ``None`` when out of range.

    Local (not UTC) so it compares with the naive local compact/dashed tokens.
    """
    value = int(groups[0])
    if not _EPOCH_MIN <= value <= _EPOCH_MAX:
        return None
    try:
        return datetime.fromtimestamp(value)
    except (OverflowError, OSError, ValueError):
        return None


def _timestamp_token(name: str) -> Optional[datetime]:
    """Parse the capture timestamp embedded in filename *name*, or ``None``.

    Recognizes ``YYYYMMDD[_-T]HHMM[SS]``, ``YYYY-MM-DD[_T ]HH[-:.]MM([-:.]SS)?``
    and a standalone 10-digit epoch (as naive local time). All matches of all
    patterns are tried in that order; the first valid datetime wins, so an
    invalid calendar date does not hide a later valid token.
    """
    parsers = (
        (_DASHED_TOKEN, _datetime_from_groups),
        (_COMPACT_TOKEN, _datetime_from_groups),
        (_EPOCH_TOKEN, _epoch_datetime),
    )
    for pattern, to_datetime in parsers:
        for match in pattern.finditer(name):
            parsed = to_datetime(match.groups())
            if parsed is not None:
                return parsed
    return None


# --------------------------------------------------------------------------
# Keylog suggestion
# --------------------------------------------------------------------------

def _looks_like_keylog_name(name: str) -> bool:
    """True for ``*key*.log`` / ``*key*.keylog`` filenames (case-insensitive)."""
    lowered = name.lower()
    return "key" in lowered and lowered.endswith(KEYLOG_EXTENSIONS)


def _normalized(path: str) -> str:
    """Canonical form of *path* for identity comparisons."""
    return canonical_keylog_path(path)


TimeWindow = Tuple[float, float]


def _capture_window(pcap_abs: str) -> TimeWindow:
    """``(created, last_modified)`` of the pcap; creation falls back to mtime.

    A capture is written over a span of time, so the keylog is matched against
    that whole span. ``st_birthtime`` exists on macOS/BSD/Windows; elsewhere the
    window collapses to the mtime.
    """
    st = os.stat(pcap_abs)
    created = getattr(st, "st_birthtime", st.st_mtime)
    return (min(created, st.st_mtime), st.st_mtime)


def _gap_to_window(moment: float, window: TimeWindow) -> float:
    """Seconds from *moment* to *window* (0 when inside it)."""
    return max(0.0, window[0] - moment, moment - window[1])


def _candidate_mtime(entry: "os.DirEntry[str]") -> Optional[float]:
    """mtime of *entry* when it is a regular file, else ``None`` (never raises)."""
    try:
        return entry.stat().st_mtime if entry.is_file() else None
    except OSError:
        return None


def _keylog_candidates(directory: str, excluded: set) -> Dict[str, float]:
    """Sorted ``{name: mtime}`` of keylog-looking regular files in *directory*.

    Names are filtered before any stat call; each candidate is stat'ed once and
    its mtime cached for the time-matching step. *excluded* paths are skipped.
    The keylog's LAST write is what counts: a long-lived keylog that is appended
    to across many sessions was created long before, so its creation time says
    nothing about this capture.
    """
    candidates: Dict[str, float] = {}
    with os.scandir(directory) as entries:
        for entry in entries:
            if not _looks_like_keylog_name(entry.name) or _normalized(entry.path) in excluded:
                continue
            mtime = _candidate_mtime(entry)
            if mtime is not None:
                candidates[entry.name] = mtime
    return {name: candidates[name] for name in sorted(candidates)}


def _closest(
    names: Iterable[str],
    distance_of: Callable[[str], Optional[float]],
    max_delta_s: float,
) -> Optional[str]:
    """Name with the smallest distance, within *max_delta_s*."""
    best: Optional[Tuple[float, str]] = None
    for name in names:
        delta = distance_of(name)
        if delta is None:
            continue
        if delta <= max_delta_s and (best is None or delta < best[0]):
            best = (delta, name)
    return best[1] if best else None


def _match_by_filename_token(pcap_name: str, names: List[str], max_delta_s: float) -> Optional[str]:
    """Candidate whose filename timestamp is closest to the pcap's (priority 1)."""
    pcap_token = _timestamp_token(pcap_name)
    if pcap_token is None:
        return None

    def token_distance(name: str) -> Optional[float]:
        token = _timestamp_token(name)
        return None if token is None else abs((token - pcap_token).total_seconds())

    return _closest(names, token_distance, max_delta_s)


def _match_by_file_time(
    pcap_abs: str, mtimes: Dict[str, float], max_delta_s: float,
) -> Optional[str]:
    """Candidate last written closest to the pcap's capture window (priority 2)."""
    window = _capture_window(pcap_abs)
    return _closest(mtimes, lambda name: _gap_to_window(mtimes[name], window), max_delta_s)


@dataclass(frozen=True)
class Suggestion:
    """A suggested keylog plus its content evidence.

    ``covered``/``total`` count the capture's client randoms the keylog covers;
    both are ``None`` when no ``capture_crs`` were supplied.
    """

    path: str
    covered: Optional[int] = None
    total: Optional[int] = None


def rank_keylogs_by_coverage(
    candidates: Iterable[str],
    capture_crs: AbstractSet[str],
    max_bytes: int = MAX_RANK_KEYLOG_BYTES,
) -> List[Tuple[str, int]]:
    """``(path, covered)`` for each candidate, most capture client randoms first.

    Ties keep the candidates' input order. Unreadable files count as 0.
    """
    wanted = {cr.lower() for cr in capture_crs}
    scored = [
        (path, len(wanted & keylog_client_randoms(path, max_bytes).keys()))
        for path in candidates
    ]
    return sorted(scored, key=lambda item: -item[1])


def _match_by_time(pcap_abs: str, mtimes: Dict[str, float], max_delta_s: float) -> Optional[str]:
    """Filename-token match first, else the closest file time (both within *max_delta_s*)."""
    chosen = _match_by_filename_token(os.path.basename(pcap_abs), list(mtimes), max_delta_s)
    if chosen is None:
        chosen = _match_by_file_time(pcap_abs, mtimes, max_delta_s)
    return chosen


def _match_by_content(
    pcap_abs: str, mtimes: Dict[str, float], capture_crs: AbstractSet[str], max_delta_s: float,
) -> Tuple[Optional[str], Dict[str, int]]:
    """Candidate covering the most capture client randoms (priority 0) + all scores.

    A tie between the best-covering candidates is broken by the time rules,
    else the first name. Zero coverage everywhere yields ``None``.
    """
    directory = os.path.dirname(pcap_abs)
    ranked = rank_keylogs_by_coverage(
        [os.path.join(directory, name) for name in mtimes], capture_crs)
    scores = {os.path.basename(path): covered for path, covered in ranked}
    best = ranked[0][1] if ranked else 0
    if best == 0:
        return None, scores
    tied = {name: mtimes[name] for name, covered in scores.items() if covered == best}
    return _match_by_time(pcap_abs, tied, max_delta_s) or next(iter(tied)), scores


def _suggest(
    pcap_path: str,
    exclude: Iterable[str],
    max_delta_s: float,
    capture_crs: Optional[AbstractSet[str]],
) -> Optional[Suggestion]:
    """Core of :func:`suggest_keylog_with_evidence` (may raise on I/O errors)."""
    pcap_abs = os.path.abspath(pcap_path)
    excluded = {_normalized(p) for p in exclude if p}
    excluded.add(_normalized(pcap_abs))
    mtimes = _keylog_candidates(os.path.dirname(pcap_abs), excluded)
    if not mtimes:
        return None
    chosen, scores = None, {}
    if capture_crs:
        chosen, scores = _match_by_content(pcap_abs, mtimes, capture_crs, max_delta_s)
    if chosen is None:
        chosen = _match_by_time(pcap_abs, mtimes, max_delta_s)
    if chosen is None:
        return None
    path = os.path.join(os.path.dirname(pcap_path), chosen)
    if capture_crs is None:
        return Suggestion(path)
    return Suggestion(path, scores.get(chosen, 0), len(capture_crs))


def suggest_keylog_with_evidence(
    pcap_path: str,
    exclude: Iterable[str] = (),
    max_delta_s: float = DEFAULT_MAX_DELTA_S,
    capture_crs: Optional[AbstractSet[str]] = None,
) -> Optional[Suggestion]:
    """Like :func:`suggest_keylog_for_pcap`, plus how many capture sessions it covers.

    With *capture_crs* (the capture's ClientHello client randoms), the
    candidate covering the most of them wins regardless of timestamps;
    without any coverage the timestamp rules apply unchanged.
    """
    try:
        return _suggest(pcap_path, exclude, max_delta_s, capture_crs)
    except (OSError, ValueError, TypeError):
        logger.debug("Keylog suggestion failed for %r", pcap_path, exc_info=True)
        return None


def suggest_keylog_for_pcap(
    pcap_path: str,
    exclude: Iterable[str] = (),
    max_delta_s: float = DEFAULT_MAX_DELTA_S,
    capture_crs: Optional[AbstractSet[str]] = None,
) -> Optional[str]:
    """Suggest a sibling keylog for *pcap_path*, or ``None``.

    Candidates are regular files next to the pcap whose lowercased name
    contains ``key`` and ends with ``.log``/``.keylog`` (minus *exclude* and the
    pcap itself). With *capture_crs*, the candidate covering the most of those
    client randoms wins (ties broken as below). Otherwise a filename-timestamp
    match within *max_delta_s* wins; else the candidate whose last write is
    closest to the pcap's capture window (creation .. last modification),
    within *max_delta_s*. The result is
    ``os.path.join(os.path.dirname(pcap_path), name)``.
    """
    suggestion = suggest_keylog_with_evidence(pcap_path, exclude, max_delta_s, capture_crs)
    return None if suggestion is None else suggestion.path


# --------------------------------------------------------------------------
# Keylog protocol sniffing
# --------------------------------------------------------------------------

def _is_mtproto_line(line: str) -> bool:
    """True when any canonical MTProto keylog parser accepts *line*.

    The MTProto keylog reuses one file for three labels — ``MTPROTO_AUTH_KEY``
    (cloud), ``MTPROTO_E2E_KEY`` (secret chat) and ``MTPROTO_OBF_KEY``
    (obfuscated-transport CTR state). A file may legitimately contain only the
    E2E or only the OBF label (e.g. the Telegram Secret-Chat keylog, or a
    memory-scan obf-key sidecar), so all three parsers are consulted — otherwise
    such a keylog sniffs as ``None`` and gets mis-filed under TLS.
    """
    try:
        from friTap.protocols.mtproto_keylog_spec import (
            parse_e2e_line,
            parse_line,
            parse_obf_line,
        )
    except ImportError:  # pragma: no cover - defensive
        return False
    return (
        parse_line(line) is not None
        or parse_e2e_line(line) is not None
        or parse_obf_line(line) is not None
    )


def _is_rc4_line(line: str) -> bool:
    """True when the canonical RC4 keylog parser accepts *line*."""
    try:
        from friTap.protocols.rc4_keylog_spec import parse_line
    except ImportError:  # pragma: no cover - defensive
        return False
    return parse_line(line) is not None


def _is_tls_label(label: str) -> bool:
    """True for NSS SSLKEYLOGFILE labels and Schannel sidecar kinds."""
    return is_nss_tls_label(label) or label.startswith(SIDECAR_KINDS)


def _protocol_for_line(line: str) -> Optional[str]:
    """Picker protocol a single (non-blank, non-comment) keylog *line* implies."""
    label = line.split(None, 1)[0]
    if _is_tls_label(label):
        return TLS_PICKER_NAME
    if _is_rc4_line(line):
        return CUSTOM_PICKER_NAME
    if _is_mtproto_line(line):
        return MTPROTO_PICKER_NAME
    return None


def _record_lines(path: str, max_lines: int) -> List[str]:
    """Up to *max_lines* non-blank, non-comment lines from *path* (bounded read:
    at most ``4 * max_lines`` physical lines of ``_MAX_LINE_CHARS`` each)."""
    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for _ in range(max_lines * 4):
            raw = fh.readline(_MAX_LINE_CHARS)
            if not raw:
                break
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
            if len(lines) >= max_lines:
                break
    return lines


def sniff_keylog_protocol(path: str, max_lines: int = 50) -> Optional[str]:
    """Return the picker protocol (``tls``/``custom``/``mtproto``) of keylog *path*.

    Inspects up to *max_lines* record lines; the first recognized line decides.
    Returns ``None`` for unknown content or any read error.
    """
    try:
        for line in _record_lines(path, max_lines):
            protocol = _protocol_for_line(line)
            if protocol is not None:
                return protocol
    except (OSError, ValueError, TypeError):
        logger.debug("Keylog sniff failed for %r", path, exc_info=True)
    return None


__all__ = [
    "DEFAULT_MAX_DELTA_S",
    "MAX_RANK_KEYLOG_BYTES",
    "Suggestion",
    "rank_keylogs_by_coverage",
    "suggest_keylog_for_pcap",
    "suggest_keylog_with_evidence",
    "sniff_keylog_protocol",
]
