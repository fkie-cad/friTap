"""Read a friTap MTProto keylog into an auth_key_id -> key lookup.

Thin wrapper over :mod:`friTap.protocols.mtproto_keylog_spec` (the single source
of truth for the line format) so the offline reader never drifts from the live
writer. Tolerant by design: comments, blanks, and malformed lines are skipped.
"""

from __future__ import annotations

from typing import Dict

from ...protocols.mtproto_keylog_spec import MtprotoAuthKey, parse_line


def load_mtproto_keylog(path: str) -> Dict[bytes, MtprotoAuthKey]:
    """Parse an MTProto keylog file into ``{auth_key_id(8 bytes): MtprotoAuthKey}``.

    Each line is parsed via :func:`mtproto_keylog_spec.parse_line`, which returns
    ``None`` for comments/blank/malformed lines (those are simply ignored). When
    duplicate auth_key_ids appear, the last entry wins.
    """
    keymap: Dict[bytes, MtprotoAuthKey] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line)
            if entry is not None:
                keymap[entry.auth_key_id] = entry
    return keymap
