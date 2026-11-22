"""Suggest a keylog for a pcap and sniff which picker protocol a keylog is for.

Pure helpers (no TUI code) for the pcap-to-tap wizard.
:func:`suggest_keylog_for_pcap` picks a sibling ``*key*.log``/``*key*.keylog``
file: by client-random coverage when ``capture_crs`` is given, else by filename
timestamp, else by file time. :func:`sniff_keylog_protocol` maps a keylog to its
picker entry (``tls``/``custom``/``mtproto``/``signal``). Both return ``None``
on any I/O or parse failure, never raise.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import AbstractSet, Callable, Dict, Iterable, List, Optional, Tuple

from friTap.offline.keylog_coverage import (
    is_nss_tls_label,
    keylog_client_randoms,
)
from friTap.offline.keylog_io import iter_bounded_lines
from friTap.offline.keylog_paths import canonical_keylog_path
from friTap.offline.keylog_picker import CUSTOM_PICKER_NAME, TLS_PICKER_NAME
from friTap.offline.schannel.unpaired import SIDECAR_KINDS
from friTap.protocols import mtproto_keylog_spec, rc4_keylog_spec

try:  # optional: absent from builds that ship without this protocol
    from friTap.protocols import signal_keylog_spec
except ImportError:  # pragma: no cover - depends on the build variant
    signal_keylog_spec = None

logger = logging.getLogger(__name__)

# Keylogs are often flushed after the capture stops (e.g. a memory scan of
# lsass at the end of a session), so allow a few minutes of slack.
DEFAULT_MAX_DELTA_S = 600
KEYLOG_EXTENSIONS = (".log", ".keylog")
MTPROTO_PICKER_NAME = "mtproto"
SIGNAL_PICKER_NAME = "signal"

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


def _looks_like_keylog_name(name: str) -> bool:
    """True for ``*key*.log`` / ``*key*.keylog`` filenames (case-insensitive)."""
    lowered = name.lower()
    return "key" in lowered and lowered.endswith(KEYLOG_EXTENSIONS)


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

    Names are filtered before any stat call and each candidate is stat'ed once.
    *excluded* paths are skipped. Only the last write (mtime) counts: an appended
    long-lived keylog's creation time says nothing about this capture.
    """
    candidates: Dict[str, float] = {}
    with os.scandir(directory) as entries:
        for entry in entries:
            if not _looks_like_keylog_name(entry.name) or canonical_keylog_path(entry.path) in excluded:
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
    excluded = {canonical_keylog_path(p) for p in exclude if p}
    excluded.add(canonical_keylog_path(pcap_abs))
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

    Candidates are regular files next to the pcap named ``*key*.log``/``*key*.keylog``
    (case-insensitive), minus *exclude* and the pcap. Priority: most *capture_crs*
    covered, then filename timestamp, then last write closest to the capture
    window; time matches must be within *max_delta_s*. Returns
    ``os.path.join(os.path.dirname(pcap_path), name)``.
    """
    suggestion = suggest_keylog_with_evidence(pcap_path, exclude, max_delta_s, capture_crs)
    return None if suggestion is None else suggestion.path


def _is_tls_label(label: str) -> bool:
    """True for NSS SSLKEYLOGFILE labels and Schannel sidecar kinds."""
    return is_nss_tls_label(label) or label.startswith(SIDECAR_KINDS)


def _is_tls_line(line: str) -> bool:
    """True when the first token of *line* is a TLS / Schannel label."""
    return _is_tls_label(line.split(None, 1)[0])


# Ordered (picker protocol, line matcher) table; the first match wins. Signal
# records are bare unlabelled hex, so they go last and never claim a labelled
# line. The MTProto matcher accepts AUTH, E2E and OBF lines alike, since a file
# may hold only E2E or only OBF keys and must not be mis-filed under TLS.
KEYLOG_LINE_MATCHERS: Tuple[Tuple[str, Callable[[str], bool]], ...] = (
    (TLS_PICKER_NAME, _is_tls_line),
    (CUSTOM_PICKER_NAME, rc4_keylog_spec.matches_line),
    (MTPROTO_PICKER_NAME, mtproto_keylog_spec.matches_line),
) + (
    ((SIGNAL_PICKER_NAME, signal_keylog_spec.matches_line),)
    if signal_keylog_spec is not None else ()
)


def _protocol_for_line(line: str) -> Optional[str]:
    """Picker protocol a single (non-blank, non-comment) keylog *line* implies."""
    for protocol, matches in KEYLOG_LINE_MATCHERS:
        if matches(line):
            return protocol
    return None


class _CharLimitedReader:
    """``readline`` over a text handle that stops after *limit* characters in total."""

    def __init__(self, fh, limit: int):
        self._fh = fh
        self._remaining = limit
        self.name = getattr(fh, "name", "")

    def readline(self, size: int = -1) -> str:
        """Like ``fh.readline(size)``, but ``""`` once the total limit is used up."""
        if self._remaining <= 0:
            return ""
        want = self._remaining if size < 0 else min(size, self._remaining)
        line = self._fh.readline(want)
        self._remaining -= len(line)
        return line


def _record_lines(path: str, max_lines: int) -> List[str]:
    """Up to *max_lines* non-blank, non-comment lines from *path*.

    Bounded: at most ``4 * max_lines`` physical lines of ``_MAX_LINE_CHARS`` each;
    over-long lines are skipped (:func:`iter_bounded_lines`).
    """
    max_physical = max_lines * 4
    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        # Cap the total read too: draining one newline-free giant "line" must not
        # walk the whole file just to sniff its first records.
        head = _CharLimitedReader(fh, max_physical * (_MAX_LINE_CHARS + 1))
        physical = iter_bounded_lines(head, _MAX_LINE_CHARS, source=path)
        for raw in islice(physical, max_physical):
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
            if len(lines) >= max_lines:
                break
        physical.close()  # report any skipped over-long lines now
    return lines


def sniff_keylog_protocol(path: str, max_lines: int = 50) -> Optional[str]:
    """Return the picker protocol (``tls``/``custom``/``mtproto``/``signal``) of *path*.

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
