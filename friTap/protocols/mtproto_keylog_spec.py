"""Canonical friTap MTProto keylog format — the single source of truth.

Imported by BOTH the live writer (``MtprotoKeylogFormatter`` in
``friTap.protocols.mtproto_handler``) and the offline reader
(``friTap.offline.mtproto.keylog``) so the two never drift.

Line format (label-first, NSS-style; ``#`` comments ignored)::

    MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>

  * ``dc_id``            decimal datacenter id (informational hint).
  * ``auth_key_id_hex16`` 8 bytes / 16 hex chars — the JOIN key (every MTProto
                          record header carries this).
  * ``auth_key_hex512``   256 bytes / 512 hex chars.
  * ``key_type``          ``perm`` | ``temp`` (PFS: transport uses temp keys).

E2E secret chats reuse the same file with a distinct label::

    MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id>

  * ``key_fingerprint_hex16`` 8 bytes / 16 hex chars — the JOIN key (low 64 bits
                              of SHA1(shared_key); every E2E blob carries this).
  * ``shared_key_hex512``     256 bytes / 512 hex chars (the per-chat shared key).
  * ``chat_id``               decimal secret-chat id (informational hint;
                              optional — defaults to 0 when absent).

The format stays additive: :func:`parse_line` (the cloud-chat reader) ignores
E2E lines, and :func:`parse_e2e_line` (the secret-chat reader) ignores
``MTPROTO_AUTH_KEY`` lines, so both labels coexist in one file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

VERSION = 1
LABEL = "MTPROTO_AUTH_KEY"
E2E_LABEL = "MTPROTO_E2E_KEY"  # secret-chat (end-to-end) keys

KEY_TYPE_PERM = "perm"
KEY_TYPE_TEMP = "temp"
_VALID_KEY_TYPES = (KEY_TYPE_PERM, KEY_TYPE_TEMP)

AUTH_KEY_ID_HEXLEN = 16  # 8 bytes
AUTH_KEY_HEXLEN = 512  # 256 bytes

E2E_FINGERPRINT_HEXLEN = 16  # 8 bytes
E2E_SHARED_KEY_HEXLEN = 512  # 256 bytes

HEADER_COMMENT = (
    f"# friTap MTProto keylog v{VERSION} — format: "
    f"{LABEL} <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>"
)


@dataclass(frozen=True)
class MtprotoAuthKey:
    """One parsed keylog entry."""

    dc_id: int
    auth_key_id: bytes  # 8 bytes
    auth_key: bytes  # 256 bytes
    key_type: str = KEY_TYPE_PERM


def format_line(
    *,
    dc_id: int,
    auth_key_id: str,
    auth_key: str,
    key_type: str = KEY_TYPE_PERM,
) -> Optional[str]:
    """Render one keylog line from hex strings, or ``None`` if malformed.

    Returning ``None`` (rather than raising) lets the formatter drop a bad
    event without aborting the whole keylog, matching friTap's other formatters.
    """
    aid = (auth_key_id or "").strip().lower()
    ak = (auth_key or "").strip().lower()
    # Defense-in-depth: auth_key_id is by definition the low 64 bits of
    # SHA1(auth_key). The agent and the message router both populate it, but if a
    # line ever reaches here with an EMPTY id and a valid key, derive it rather
    # than silently dropping a usable key (the offline decryptor joins on this id).
    # A non-empty-but-malformed id is still rejected (it signals a real bug).
    if not aid and len(ak) == AUTH_KEY_HEXLEN:
        try:
            import hashlib
            aid = hashlib.sha1(bytes.fromhex(ak)).digest()[-8:].hex()
        except ValueError:
            pass
    if len(aid) != AUTH_KEY_ID_HEXLEN or len(ak) != AUTH_KEY_HEXLEN:
        return None
    try:
        int(aid, 16)
        int(ak, 16)
    except ValueError:
        return None
    kt = key_type if key_type in _VALID_KEY_TYPES else KEY_TYPE_PERM
    try:
        dc = int(dc_id)
    except (TypeError, ValueError):
        dc = 0
    return f"{LABEL} {dc} {aid} {ak} {kt}"


def parse_line(line: str) -> Optional[MtprotoAuthKey]:
    """Parse one keylog line into an :class:`MtprotoAuthKey`, or ``None``.

    Skips blank lines, ``#`` comments, the reserved E2E label, and any
    malformed/foreign line.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) < 4 or parts[0] != LABEL:
        return None
    _, dc_str, aid_hex, ak_hex = parts[0], parts[1], parts[2], parts[3]
    key_type = parts[4] if len(parts) >= 5 and parts[4] in _VALID_KEY_TYPES else KEY_TYPE_PERM
    if len(aid_hex) != AUTH_KEY_ID_HEXLEN or len(ak_hex) != AUTH_KEY_HEXLEN:
        return None
    try:
        dc_id = int(dc_str)
        auth_key_id = bytes.fromhex(aid_hex)
        auth_key = bytes.fromhex(ak_hex)
    except ValueError:
        return None
    return MtprotoAuthKey(dc_id=dc_id, auth_key_id=auth_key_id, auth_key=auth_key, key_type=key_type)


@dataclass(frozen=True)
class MtprotoSecretChatKey:
    """One parsed secret-chat (E2E) keylog entry."""

    key_fingerprint: bytes  # 8 bytes
    shared_key: bytes  # 256 bytes
    chat_id: int = 0


def format_e2e_line(
    *,
    key_fingerprint: str,
    shared_key: str,
    chat_id: int = 0,
) -> Optional[str]:
    """Render one secret-chat keylog line from hex strings, or ``None`` if malformed.

    Returning ``None`` (rather than raising) lets the formatter drop a bad
    event without aborting the whole keylog, matching :func:`format_line`.
    """
    fp = (key_fingerprint or "").strip().lower()
    key = (shared_key or "").strip().lower()
    if len(fp) != E2E_FINGERPRINT_HEXLEN or len(key) != E2E_SHARED_KEY_HEXLEN:
        return None
    try:
        int(fp, 16)
        int(key, 16)
    except ValueError:
        return None
    try:
        cid = int(chat_id)
    except (TypeError, ValueError):
        cid = 0
    return f"{E2E_LABEL} {fp} {key} {cid}"


def parse_e2e_line(line: str) -> Optional[MtprotoSecretChatKey]:
    """Parse one secret-chat keylog line into an :class:`MtprotoSecretChatKey`, or ``None``.

    Skips blank lines, ``#`` comments, the cloud-chat label, and any
    malformed/foreign line. The trailing ``chat_id`` is optional (defaults to 0).
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) < 3 or parts[0] != E2E_LABEL:
        return None
    fp_hex, key_hex = parts[1], parts[2]
    if len(fp_hex) != E2E_FINGERPRINT_HEXLEN or len(key_hex) != E2E_SHARED_KEY_HEXLEN:
        return None
    try:
        chat_id = int(parts[3]) if len(parts) >= 4 else 0
    except ValueError:
        chat_id = 0
    try:
        key_fingerprint = bytes.fromhex(fp_hex)
        shared_key = bytes.fromhex(key_hex)
    except ValueError:
        return None
    return MtprotoSecretChatKey(
        key_fingerprint=key_fingerprint, shared_key=shared_key, chat_id=chat_id
    )
