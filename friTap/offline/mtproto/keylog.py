"""Read a friTap MTProto keylog into an auth_key_id -> key lookup.

Thin wrapper over :mod:`friTap.protocols.mtproto_keylog_spec` (the single source
of truth for the line format) so the offline reader never drifts from the live
writer. Tolerant by design: comments, blanks, and malformed lines are skipped.
"""

from __future__ import annotations

from typing import Dict, List

from ...protocols.mtproto_keylog_spec import (
    MtprotoAuthKey,
    MtprotoObfKey,
    parse_line,
    parse_obf_line,
)
from ..keylog_io import load_keylog_lines

# Re-exported: the endpoint helpers moved to the protocol-neutral net package.
from ..net.endpoints import normalize_endpoint, stream_endpoint  # noqa: F401


def load_mtproto_keylog(path: str) -> Dict[bytes, MtprotoAuthKey]:
    """Parse an MTProto keylog file into ``{auth_key_id(8 bytes): MtprotoAuthKey}``.

    Each line is parsed via :func:`mtproto_keylog_spec.parse_line`, which returns
    ``None`` for comments/blank/malformed lines (those are simply ignored). When
    duplicate auth_key_ids appear, the last entry wins.
    """
    return load_keylog_lines(path, parse_line, key=lambda entry: entry.auth_key_id)


def load_mtproto_obf_keylog(path: str) -> List[MtprotoObfKey]:
    """Parse an MTProto keylog file into a LIST of :class:`MtprotoObfKey` entries.

    A LIST, not a dict: obfuscation-transport keys carry no natural join key (the
    endpoint hint is only advisory and may be ``-``), so the offline path joins
    them to captured streams by trial de-obfuscation. Comments/blank/foreign lines
    are skipped via :func:`mtproto_keylog_spec.parse_obf_line`; order is preserved.
    """
    return load_keylog_lines(path, parse_obf_line)
