"""Canonical friTap MTProto keylog format.

Shared by the live writer (``MtprotoKeylogFormatter`` in
``friTap.protocols.mtproto_handler``) and the offline reader
(``friTap.offline.mtproto.keylog``) so the two cannot drift.

Line format (label-first, NSS-style; ``#`` comments ignored)::

    MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>

  * ``dc_id``            decimal datacenter id (hint only).
  * ``auth_key_id_hex16`` 8 bytes / 16 hex chars; the join key (every MTProto
                          record header carries it).
  * ``auth_key_hex512``   256 bytes / 512 hex chars.
  * ``key_type``          ``perm`` | ``temp`` (PFS: transport uses temp keys).

E2E secret chats reuse the same file with a distinct label::

    MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id> [<peer_user_id>]

  * ``key_fingerprint_hex16`` 8 bytes / 16 hex chars; the join key (low 64 bits
                              of SHA1(shared_key), carried by every E2E blob).
  * ``shared_key_hex512``     256 bytes / 512 hex chars (the per-chat shared key).
  * ``chat_id``               decimal secret-chat id (hint; optional, default 0).
  * ``peer_user_id``          decimal user id of the other participant, read from
                              the client's Java ``EncryptedChat`` (optional 4th
                              field, default 0; 3-field lines still parse).

Obfuscated-transport CTR state (recovered from memory for a connection already
open when capture started) uses a third label::

    MTPROTO_OBF_KEY <key_out_hex64> <iv_out_hex32> <key_in_hex64> <iv_in_hex32> <num_out> <num_in> <endpoint|->

  * ``key_out_hex64`` / ``key_in_hex64``  32 bytes / 64 hex; per-direction AES-256
                                          keys (out = client->server).
  * ``iv_out_hex32`` / ``iv_in_hex32``    16 bytes / 32 hex; the live CTR counter
                                          block at scan time (not the init IV).
  * ``num_out`` / ``num_in``              decimal byte-phase (0..15) into the
                                          current keystream block at scan time.
  * ``endpoint``                          optional ``ip:port`` hint; ``-`` when
                                          unknown or absent (offline joins by trial).

Each parser ignores the other labels, so all three coexist in one file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

VERSION = 1
LABEL = "MTPROTO_AUTH_KEY"
E2E_LABEL = "MTPROTO_E2E_KEY"  # secret-chat (end-to-end) keys
OBF_LABEL = "MTPROTO_OBF_KEY"  # obfuscated-transport CTR state (mid-stream recovery)

KEY_TYPE_PERM = "perm"
KEY_TYPE_TEMP = "temp"
_VALID_KEY_TYPES = (KEY_TYPE_PERM, KEY_TYPE_TEMP)

AUTH_KEY_ID_HEXLEN = 16  # 8 bytes
AUTH_KEY_HEXLEN = 512  # 256 bytes

E2E_FINGERPRINT_HEXLEN = 16  # 8 bytes
E2E_SHARED_KEY_HEXLEN = 512  # 256 bytes

OBF_KEY_HEXLEN = 64  # 32-byte AES-256 obfuscation key
OBF_IV_HEXLEN = 32  # 16-byte CTR counter block
OBF_NUM_MAX = 15  # byte-phase within a 16-byte AES-CTR keystream block
OBF_ENDPOINT_UNKNOWN = "-"

# Production DCs are 1..5; the headroom covers test/media/CDN ids. Anything
# outside (or non-numeric, or +/-Infinity from JSON) becomes 0 = unknown; the
# auth key is still kept.
DC_ID_MIN = 1
DC_ID_MAX = 1000
DC_ID_UNKNOWN = 0


def _coerce_int(value) -> Optional[int]:
    """``int(value)``, or ``None``. Catches ``OverflowError`` for JSON ``Infinity``."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _coerce_dc_id(dc_id) -> int:
    """Agent ``dc_id`` bounded to DC_ID_MIN..DC_ID_MAX, else DC_ID_UNKNOWN."""
    dc = _coerce_int(dc_id)
    if dc is None or not DC_ID_MIN <= dc <= DC_ID_MAX:
        return DC_ID_UNKNOWN
    return dc


HEADER_COMMENT = (
    f"# friTap MTProto keylog v{VERSION} — formats:\n"
    f"#   {LABEL} <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>\n"
    f"#   {E2E_LABEL} <key_fingerprint_hex16> <shared_key_hex512> <chat_id>\n"
    f"#   {OBF_LABEL} <key_out_hex64> <iv_out_hex32> <key_in_hex64> <iv_in_hex32> "
    f"<num_out> <num_in> <endpoint|->"
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
    """Render one keylog line from hex strings, or ``None`` if malformed (never raises, so one bad event cannot abort the keylog)."""
    aid = (auth_key_id or "").strip().lower()
    ak = (auth_key or "").strip().lower()
    # auth_key_id is the low 64 bits of SHA1(auth_key). Derive it when empty so a
    # usable key is not dropped (offline joins on this id). A non-empty malformed
    # id is still rejected.
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
    dc = _coerce_dc_id(dc_id)
    return f"{LABEL} {dc} {aid} {ak} {kt}"


def parse_line(line: str) -> Optional[MtprotoAuthKey]:
    """Parse one line into an :class:`MtprotoAuthKey`, or ``None`` (blanks, comments, other labels, malformed)."""
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
    peer_user_id: int = 0  # the other participant's user id (0 = unknown)


def format_e2e_line(
    *,
    key_fingerprint: str,
    shared_key: str,
    chat_id: int = 0,
    peer_user_id: int = 0,
) -> Optional[str]:
    """Render one secret-chat keylog line from hex strings, or ``None`` if malformed.

    The optional 4th ``peer_user_id`` is appended only when non-zero.
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
    try:
        peer = int(peer_user_id)
    except (TypeError, ValueError):
        peer = 0
    if peer:
        return f"{E2E_LABEL} {fp} {key} {cid} {peer}"
    return f"{E2E_LABEL} {fp} {key} {cid}"


def parse_e2e_line(line: str) -> Optional[MtprotoSecretChatKey]:
    """Parse one secret-chat line into an :class:`MtprotoSecretChatKey`, or ``None``; ``chat_id`` and ``peer_user_id`` default to 0."""
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
        peer_user_id = int(parts[4]) if len(parts) >= 5 else 0
    except ValueError:
        peer_user_id = 0
    try:
        key_fingerprint = bytes.fromhex(fp_hex)
        shared_key = bytes.fromhex(key_hex)
    except ValueError:
        return None
    return MtprotoSecretChatKey(
        key_fingerprint=key_fingerprint, shared_key=shared_key, chat_id=chat_id,
        peer_user_id=peer_user_id,
    )


@dataclass(frozen=True)
class MtprotoObfKey:
    """One parsed obfuscated-transport CTR-state keylog entry.

    ``iv_out``/``iv_in`` are the live CTR counter blocks (not the init IVs);
    ``num_out``/``num_in`` the byte-phase into the current keystream block. They
    seed de-obfuscation when the 64-byte init block was never captured (see
    :mod:`friTap.offline.mtproto.transport`).
    """

    key_out: bytes  # 32 bytes (client->server AES-256 key)
    iv_out: bytes  # 16 bytes (live client->server CTR counter)
    key_in: bytes  # 32 bytes (server->client AES-256 key)
    iv_in: bytes  # 16 bytes (live server->client CTR counter)
    num_out: int = 0  # byte-phase 0..15 (client->server)
    num_in: int = 0  # byte-phase 0..15 (server->client)
    endpoint: str = OBF_ENDPOINT_UNKNOWN  # "ip:port" hint or "-" when unknown


def format_obf_line(
    *,
    key_out: str,
    iv_out: str,
    key_in: str,
    iv_in: str,
    num_out: int = 0,
    num_in: int = 0,
    endpoint: str = OBF_ENDPOINT_UNKNOWN,
) -> Optional[str]:
    """Render one obfuscation-key keylog line from hex strings, or ``None`` if malformed."""
    ko = (key_out or "").strip().lower()
    io = (iv_out or "").strip().lower()
    ki = (key_in or "").strip().lower()
    ii = (iv_in or "").strip().lower()
    if (
        len(ko) != OBF_KEY_HEXLEN
        or len(ki) != OBF_KEY_HEXLEN
        or len(io) != OBF_IV_HEXLEN
        or len(ii) != OBF_IV_HEXLEN
    ):
        return None
    try:
        int(ko, 16)
        int(io, 16)
        int(ki, 16)
        int(ii, 16)
    except ValueError:
        return None
    # Clamp byte-phase into 0..15 rather than dropping an otherwise good key.
    no = _coerce_int(num_out) or 0
    ni = _coerce_int(num_in) or 0
    no = min(max(no, 0), OBF_NUM_MAX)
    ni = min(max(ni, 0), OBF_NUM_MAX)
    ep = (endpoint or "").strip()
    if not ep or any(c.isspace() for c in ep):
        ep = OBF_ENDPOINT_UNKNOWN
    return f"{OBF_LABEL} {ko} {io} {ki} {ii} {no} {ni} {ep}"


def parse_obf_line(line: str) -> Optional[MtprotoObfKey]:
    """Parse one obfuscation-key line into an :class:`MtprotoObfKey`, or ``None``; ``endpoint`` defaults to ``-``."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    # 7 tokens required (label, 4 key/iv fields, num_out, num_in); endpoint is the 8th.
    if len(parts) < 7 or parts[0] != OBF_LABEL:
        return None
    ko_hex, io_hex, ki_hex, ii_hex, no_str, ni_str = parts[1:7]
    if (
        len(ko_hex) != OBF_KEY_HEXLEN
        or len(ki_hex) != OBF_KEY_HEXLEN
        or len(io_hex) != OBF_IV_HEXLEN
        or len(ii_hex) != OBF_IV_HEXLEN
    ):
        return None
    try:
        key_out = bytes.fromhex(ko_hex)
        iv_out = bytes.fromhex(io_hex)
        key_in = bytes.fromhex(ki_hex)
        iv_in = bytes.fromhex(ii_hex)
    except ValueError:
        return None
    try:
        num_out = int(no_str)
        num_in = int(ni_str)
    except ValueError:
        return None
    endpoint = parts[7] if len(parts) >= 8 else OBF_ENDPOINT_UNKNOWN
    return MtprotoObfKey(
        key_out=key_out,
        iv_out=iv_out,
        key_in=key_in,
        iv_in=iv_in,
        num_out=num_out,
        num_in=num_in,
        endpoint=endpoint,
    )


def matches_line(line: str) -> bool:
    """True when any MTProto keylog parser (auth / E2E / obf) accepts *line*.

    A keylog file may carry only one label (e.g. an obf-key sidecar), so all are tried.
    """
    return (
        parse_line(line) is not None
        or parse_e2e_line(line) is not None
        or parse_obf_line(line) is not None
    )
