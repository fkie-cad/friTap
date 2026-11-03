#!/usr/bin/env python3

"""Key-material policy shared by every JSON output.

``-j file.json``, ``-j file.jsonl`` and the ``-j -`` stdout stream are routinely
handed to scripts, ticket systems and AI agents, so raw secrets must never land
there by accident. A keylog record carries its secret (``key_data`` /
``payload``) only when the user opted in: with ``-k`` (keylog output was
requested anyway) or with ``--json-keys``. Otherwise the record is kept, so
consumers still learn that a key was seen, but it is reduced to its label (and
the public client_random of NSS lines) and marked ``"redacted": true``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from .keylog_format import is_nss_keylog_line

if TYPE_CHECKING:
    from ..config import OutputConfig

# Record fields that can hold a secret: the pre-formatted keylog line and the
# structured payload (e.g. an SSH KEX shared secret).
KEY_MATERIAL_FIELDS = ("key_data", "payload")

# Label kept for a record whose key_data carries no recognisable label (a bare
# secret, or the label-less Signal keylog format).
UNKNOWN_LABEL = "unknown"

# Exact keylog labels friTap emits. Kept in sync (see the unit tests) with
# pipeline.TLS_KEYLOG_LABELS, the RC4/MTProto keylog specs and the SSH handler.
KNOWN_KEYLOG_LABELS = frozenset({
    # NSS / TLS (SSLKEYLOGFILE)
    "CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET",
    "RESUMPTION_MASTER_SECRET", "CLIENT_EARLY_TRAFFIC_SECRET",
    # SSH (Wireshark ``<cookie> SHARED_SECRET <K>``), RC4, MTProto
    "SHARED_SECRET", "RC4_KEY",
    "MTPROTO_AUTH_KEY", "MTPROTO_E2E_KEY", "MTPROTO_OBF_KEY",
})

# Label families: SSH per-direction keys (SSH_ENC_KEY_C2S, SSH_IV_S2C...),
# IPsec/strongSwan key names (SK_ai, SK_er, encr_i, integ_r...) and the
# upper-case custom-plugin labels (AES_KEY, WG_SENDING_KEY, SRTP_MASTER_KEY...).
# A custom label needs an underscore, so a bare hex/base64 token never matches.
_KNOWN_KEYLOG_LABEL_PATTERNS = (
    re.compile(r"SSH_[A-Z0-9_]{1,60}"),
    re.compile(r"SK_(?:ai|ar|ei|er|pi|pr|d)|(?:encr|integ)_[ir]"),
    re.compile(r"[A-Z][A-Z0-9]{0,31}(?:_[A-Z0-9]{1,31}){1,7}"),
)
_SSH_SHARED_SECRET_FORMAT = re.compile(r"[0-9a-fA-F]+ SHARED_SECRET [0-9a-fA-F]+")


def is_known_keylog_label(token: str) -> bool:
    """True when *token* is a keylog label friTap emits (never a secret)."""
    return len(token) <= 64 and (
        token in KNOWN_KEYLOG_LABELS
        or any(p.fullmatch(token) for p in _KNOWN_KEYLOG_LABEL_PATTERNS))


def keylog_label_of(key_data: str) -> Optional[str]:
    """The label of a keylog line, or ``None`` when it carries none.

    A single token is always a bare secret, never a label; the SSH
    ``<cookie> SHARED_SECRET <K>`` line carries its label second.
    """
    tokens = key_data.split()
    if len(tokens) < 2:
        return None
    if _SSH_SHARED_SECRET_FORMAT.fullmatch(" ".join(tokens)):
        return "SHARED_SECRET"
    return tokens[0] if is_known_keylog_label(tokens[0]) else None


def json_key_material_enabled(output_config: "OutputConfig") -> bool:
    """True when raw key material is wanted for the JSON outputs.

    ``-k`` (keys are recorded anyway) or ``--json-keys`` together with a ``-j``
    output. The one predicate behind both the JSON handlers' redaction policy
    and the agent's ``keylog_enabled`` switch, so the two cannot drift.
    """
    return bool(output_config.keylog
                or (output_config.json_keys and output_config.wants_json))


def redact_key_record(record: dict) -> dict:
    """Strip secret fields from a keylog record, keeping only non-secret hints.

    The public client_random is kept only for a genuine NSS keylog line
    (``<LABEL> <client_random> <secret>``), never for an arbitrary 3-token line.

    The label is kept only when it is a known keylog label
    (:func:`keylog_label_of`); otherwise it becomes ``"unknown"`` — the first
    token of a bare secret must never be copied out as its "label".
    """
    key_data = str(record.get("key_data") or "")
    tokens = key_data.split()
    for key in KEY_MATERIAL_FIELDS:
        record.pop(key, None)
    label = keylog_label_of(key_data)
    if tokens:
        record["label"] = label or UNKNOWN_LABEL
    if len(tokens) == 3 and label == tokens[0] and is_nss_keylog_line(key_data):
        record["client_random"] = tokens[1]
    record["redacted"] = True
    return record


def apply_key_material_policy(record: dict, include_key_material: bool) -> dict:
    """*record* unchanged when key material is allowed, else its redacted form."""
    return record if include_key_material else redact_key_record(record)
