"""Read a friTap MTProto keylog into an auth_key_id -> key lookup.

Wraps :mod:`friTap.protocols.mtproto_keylog_spec` (single source of the line
format). Comments, blanks and malformed lines are skipped.
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

# Re-exported: tests import the endpoint helpers from this module.
from ..net.endpoints import normalize_endpoint, stream_endpoint  # noqa: F401


def load_mtproto_keylog(path: str) -> Dict[bytes, MtprotoAuthKey]:
    """Parse an MTProto keylog file into ``{auth_key_id(8 bytes): MtprotoAuthKey}``.

    Unparseable lines are skipped; on duplicate auth_key_ids the last entry wins.
    """
    return load_keylog_lines(path, parse_line, key=lambda entry: entry.auth_key_id)


def load_mtproto_obf_keylog(path: str) -> List[MtprotoObfKey]:
    """Parse an MTProto keylog file into an ordered list of :class:`MtprotoObfKey`.

    A list, not a dict: obfuscation keys have no join key (the endpoint hint is
    advisory and may be ``-``), so streams are matched by trial de-obfuscation.
    """
    return load_keylog_lines(path, parse_obf_line)
