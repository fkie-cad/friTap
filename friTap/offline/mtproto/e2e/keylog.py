"""Read a friTap MTProto keylog into a key_fingerprint -> secret-chat key lookup.

Thin wrapper over :mod:`friTap.protocols.mtproto_keylog_spec` (the single source
of truth for the line format) so the offline secret-chat reader never drifts from
the live writer. Tolerant by design: comments, blanks, cloud-chat lines, and
malformed lines are skipped.
"""

from __future__ import annotations

from typing import Dict

from ....protocols.mtproto_keylog_spec import MtprotoSecretChatKey, parse_e2e_line
from ...keylog_io import load_keylog_lines


def load_secret_chat_keylog(path: str) -> Dict[bytes, MtprotoSecretChatKey]:
    """Parse a keylog file into ``{key_fingerprint(8 bytes): MtprotoSecretChatKey}``.

    Each line is parsed via :func:`mtproto_keylog_spec.parse_e2e_line`, which
    returns ``None`` for comments/blank/cloud-chat/malformed lines (those are
    simply ignored). When duplicate fingerprints appear, the last entry wins.
    """
    return load_keylog_lines(path, parse_e2e_line, key=lambda entry: entry.key_fingerprint)
