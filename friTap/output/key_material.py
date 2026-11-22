#!/usr/bin/env python3

"""Key-material policy shared by every JSON output.

JSON outputs go to scripts, ticket systems and AI agents, so raw secrets must not
land there by accident. A keylog record keeps its secret (``key_data``/``payload``)
only with ``-k`` or ``--json-keys``; otherwise it is reduced to its label (plus the
public client_random of NSS lines) and marked ``"redacted": true``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from ..tls_keylog_labels import TLS_KEYLOG_LABELS
from .keylog_format import is_nss_keylog_line

if TYPE_CHECKING:
    from ..config import OutputConfig

# Record fields that can hold a secret (the keylog line, the structured payload e.g. an SSH KEX secret).
KEY_MATERIAL_FIELDS = ("key_data", "payload")

# Label for a record whose key_data has no recognisable label (bare secret, label-less Signal format).
UNKNOWN_LABEL = "unknown"

# Exact keylog labels friTap emits: the shared TLS set plus SSH (Wireshark ``<cookie> SHARED_SECRET <K>``), RC4, MTProto.
KNOWN_KEYLOG_LABELS = TLS_KEYLOG_LABELS | frozenset({
    "SHARED_SECRET", "RC4_KEY",
    "MTPROTO_AUTH_KEY", "MTPROTO_E2E_KEY", "MTPROTO_OBF_KEY",
})

# Label families: SSH per-direction keys, IPsec/strongSwan names (SK_ai, encr_i...) and upper-case
# custom-plugin labels (AES_KEY, WG_SENDING_KEY...). A custom label needs an underscore, so a bare hex/base64 token never matches.
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
    """The label of a keylog line, or ``None``; a single token is a bare secret, and the SSH ``<cookie> SHARED_SECRET <K>`` label is second."""
    tokens = key_data.split()
    if len(tokens) < 2:
        return None
    if _SSH_SHARED_SECRET_FORMAT.fullmatch(" ".join(tokens)):
        return "SHARED_SECRET"
    return tokens[0] if is_known_keylog_label(tokens[0]) else None


def json_key_material_enabled(output_config: "OutputConfig") -> bool:
    """True when raw key material is wanted in the JSON outputs: ``-k``, or ``--json-keys`` with ``-j``.

    One predicate for the redaction policy and the agent's ``keylog_enabled`` switch, so they cannot drift.
    """
    return bool(output_config.keylog
                or (output_config.json_keys and output_config.wants_json))


def redact_key_record(record: dict) -> dict:
    """Strip secret fields from a keylog record, keeping non-secret hints.

    The public client_random is kept only for a genuine NSS line (``<LABEL> <client_random> <secret>``).
    The label is kept only if known (:func:`keylog_label_of`), else ``"unknown"``: a bare
    secret's first token must never be copied out as a label.
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
