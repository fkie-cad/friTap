"""Read a friTap MTProto keylog into a key_fingerprint -> secret-chat key lookup.

The line format lives in :mod:`friTap.protocols.mtproto_keylog_spec`, shared with
the live writer. Comments, blanks, cloud-chat lines, and malformed lines are skipped.
"""

from __future__ import annotations

from typing import Dict

from ....protocols.mtproto_keylog_spec import MtprotoSecretChatKey, parse_e2e_line
from ...keylog_io import load_keylog_lines


def load_secret_chat_keylog(path: str) -> Dict[bytes, MtprotoSecretChatKey]:
    """Parse a keylog file into ``{key_fingerprint(8 bytes): MtprotoSecretChatKey}``.

    Duplicate fingerprints: the last entry wins.
    """
    return load_keylog_lines(path, parse_e2e_line, key=lambda entry: entry.key_fingerprint)
