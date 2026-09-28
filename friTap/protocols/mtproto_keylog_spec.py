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

    MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id> [<peer_user_id>]

  * ``key_fingerprint_hex16`` 8 bytes / 16 hex chars — the JOIN key (low 64 bits
                              of SHA1(shared_key); every E2E blob carries this).
  * ``shared_key_hex512``     256 bytes / 512 hex chars (the per-chat shared key).
  * ``chat_id``               decimal secret-chat id (informational hint;
                              optional — defaults to 0 when absent).
  * ``peer_user_id``          decimal user id of the other participant, read from
                              the client's Java ``EncryptedChat`` (optional 4th
                              field; appended only when known — legacy 3-field
                              lines still parse, peer defaults to 0).

Obfuscated-transport CTR state (recovered from live memory for a connection that
was already open when the capture started) reuses the same file with a third
label::

    MTPROTO_OBF_KEY <key_out_hex64> <iv_out_hex32> <key_in_hex64> <iv_in_hex32> <num_out> <num_in> <endpoint|->

  * ``key_out_hex64`` / ``key_in_hex64``  32 bytes / 64 hex — the per-direction
                                          AES-256 obfuscation keys (out =
                                          client->server, in = server->client).
  * ``iv_out_hex32`` / ``iv_in_hex32``    16 bytes / 32 hex — the LIVE CTR counter
                                          block for each direction at scan time
                                          (NOT the original init IV).
  * ``num_out`` / ``num_in``              decimal byte-phase (0..15) into the
                                          current keystream block for each
                                          direction at scan time.
  * ``endpoint``                          optional ``ip:port`` hint tying the key
                                          to one connection; ``-`` when unknown
                                          (defaults to ``-`` when absent — the
                                          offline path joins by trial anyway).

The format stays additive: :func:`parse_line` (the cloud-chat reader) ignores
E2E and obfuscation lines, :func:`parse_e2e_line` (the secret-chat reader) ignores
the other labels, and :func:`parse_obf_line` ignores everything but its own label,
so all three labels coexist in one file.
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
    peer_user_id: int = 0  # the other participant's user id (0 = unknown)


def format_e2e_line(
    *,
    key_fingerprint: str,
    shared_key: str,
    chat_id: int = 0,
    peer_user_id: int = 0,
) -> Optional[str]:
    """Render one secret-chat keylog line from hex strings, or ``None`` if malformed.

    Returning ``None`` (rather than raising) lets the formatter drop a bad
    event without aborting the whole keylog, matching :func:`format_line`. The
    optional 4th ``peer_user_id`` field is appended only when known (non-zero),
    so lines without a resolved peer stay in the original 3-field layout.
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
    """Parse one secret-chat keylog line into an :class:`MtprotoSecretChatKey`, or ``None``.

    Skips blank lines, ``#`` comments, the cloud-chat label, and any
    malformed/foreign line. The trailing ``chat_id`` (3rd) and ``peer_user_id``
    (4th) are both optional and default to 0, so legacy 3-field lines still parse.
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

    ``iv_out``/``iv_in`` are the LIVE 16-byte CTR counter blocks captured while the
    connection was alive (not the original init IVs); ``num_out``/``num_in`` are the
    byte-phase into the current keystream block. The offline path uses these to
    seed the de-obfuscation cipher for a connection whose 64-byte init block was
    never captured (see :mod:`friTap.offline.mtproto.transport`).
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
    """Render one obfuscation-key keylog line from hex strings, or ``None`` if malformed.

    Returning ``None`` (rather than raising) lets the formatter drop a bad event
    without aborting the whole keylog, matching :func:`format_line`.
    """
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
    # Byte-phase is informational-but-load-bearing; coerce like ``dc_id`` and clamp
    # into the valid 0..15 block range rather than dropping an otherwise-good key.
    try:
        no = int(num_out)
    except (TypeError, ValueError):
        no = 0
    try:
        ni = int(num_in)
    except (TypeError, ValueError):
        ni = 0
    no = min(max(no, 0), OBF_NUM_MAX)
    ni = min(max(ni, 0), OBF_NUM_MAX)
    ep = (endpoint or "").strip()
    if not ep or any(c.isspace() for c in ep):
        ep = OBF_ENDPOINT_UNKNOWN
    return f"{OBF_LABEL} {ko} {io} {ki} {ii} {no} {ni} {ep}"


def parse_obf_line(line: str) -> Optional[MtprotoObfKey]:
    """Parse one obfuscation-key keylog line into an :class:`MtprotoObfKey`, or ``None``.

    Skips blank lines, ``#`` comments, the cloud-chat and E2E labels, and any
    malformed/foreign line. The trailing ``endpoint`` is optional (defaults to
    ``-``), mirroring the way :func:`parse_e2e_line` defaults ``chat_id``.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    # label + key_out + iv_out + key_in + iv_in + num_out + num_in == 7 tokens;
    # endpoint (token 8) is optional.
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
