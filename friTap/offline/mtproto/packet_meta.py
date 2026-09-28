"""Per-packet forensic metadata for offline Telegram records.

Each decrypted MTProto cloud record (and each Secret-Chat message riding one)
becomes its own flow. This module builds the JSON-native *envelope* dict that
travels on that flow's layer, and the :class:`RecordLedger` that hands every
flow exactly the record it was emitted from.

Why a ledger instead of a content hash: several DIFFERENT packets of one
capture can carry byte-identical TL bodies (e.g. two ``msgs_ack`` for the same
ids), so a key derived from the chunk bytes alone is ambiguous. The ledger keeps
a first-in-first-out queue per key; since flows are created in emission order,
popping in flow order restores the one-to-one mapping.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, Optional, Tuple

from .crossref import msg_id_hex

# msg_id % 4 -> meaning, per the MTProto spec ("Message Identifier (msg_id)"):
# client ids are divisible by 4; server ids are 1 mod 4 for a response to a
# client message and 3 mod 4 otherwise (updates/notifications).
_MSG_ID_KINDS = {
    0: "client",
    1: "server_response",
    3: "server_notification",
}

_MSG_ID_FRACTION = float(1 << 32)

#: ``(exclusive min, inclusive max)`` unix seconds a msg_id clock may plausibly
#: carry (2001-09-09 .. 2100-01-01); anything outside is treated as "unknown".
PLAUSIBLE_MSG_EPOCH_RANGE = (1_000_000_000, 4_102_444_800)


def msg_id_kind(msg_id: int) -> str:
    """Classify *msg_id* by its low two bits (``"invalid"`` for 2 mod 4)."""
    if not msg_id:
        return "unknown"
    return _MSG_ID_KINDS.get(msg_id % 4, "invalid")


def msg_id_seconds(msg_id: int) -> int:
    """Whole unix seconds encoded in *msg_id* (its high 32 bits)."""
    return msg_id >> 32


def is_plausible_msg_time(seconds: float) -> bool:
    """True if *seconds* lies within :data:`PLAUSIBLE_MSG_EPOCH_RANGE`."""
    low, high = PLAUSIBLE_MSG_EPOCH_RANGE
    return low < seconds <= high


def msg_id_time(msg_id: int) -> float:
    """Unix time encoded in *msg_id*: seconds in the high 32 bits, fraction below."""
    return msg_id_seconds(msg_id) + (msg_id & 0xFFFFFFFF) / _MSG_ID_FRACTION


def _msg_id_hex(msg_id: int) -> str:
    """:func:`~.crossref.msg_id_hex`, but ``""`` for an absent (zero) msg_id."""
    return msg_id_hex(msg_id) if msg_id else ""


def _dc_endpoint(msg) -> str:
    """``ip:port`` of the Telegram DC side of *msg* (dst on write, src on read)."""
    if getattr(msg, "direction", "") == "read":
        return f"{msg.src_addr}:{msg.src_port}"
    return f"{msg.dst_addr}:{msg.dst_port}"


def build_cloud_envelope(msg) -> dict:
    """JSON-native envelope of one decrypted cloud record (a ``DecryptedMessage``)."""
    msg_id = getattr(msg, "msg_id", 0) or 0
    seq_no = getattr(msg, "seq_no", 0) or 0
    envelope = {
        "auth_key_id": getattr(msg, "auth_key_id_hex", "") or "",
        "salt": bytes(getattr(msg, "salt", b"") or b"").hex(),
        "session_id": bytes(getattr(msg, "session_id", b"") or b"").hex(),
        "msg_id": _msg_id_hex(msg_id),
        "msg_time": msg_id_time(msg_id) if msg_id else 0.0,
        "msg_id_kind": msg_id_kind(msg_id),
        "seq_no": seq_no,
        "content_related": bool(seq_no & 1),
        "msg_len": getattr(msg, "msg_len", 0) or 0,
        "padding_len": getattr(msg, "padding_len", 0) or 0,
        "frame_len": getattr(msg, "frame_len", 0) or 0,
        "transport": getattr(msg, "transport", "") or "",
        "obfuscated": bool(getattr(msg, "obfuscated", False)),
        "dc_addr": _dc_endpoint(msg),
    }
    dc_id = getattr(msg, "dc_id", 0) or 0
    if dc_id:
        envelope["dc_id"] = dc_id
    return envelope


def build_e2e_envelope(sc, carrier) -> dict:
    """JSON-native envelope of one Secret-Chat message and its carrying cloud record."""
    carrier_msg_id = getattr(carrier, "msg_id", 0) or 0
    envelope = {
        "key_fingerprint": getattr(sc, "key_fingerprint_hex", "") or "",
        "msg_key": getattr(sc, "msg_key_hex", "") or "",
        "carrier_msg_id": _msg_id_hex(carrier_msg_id),
        "carrier_auth_key_id": getattr(carrier, "auth_key_id_hex", "") or "",
    }
    chat_id = getattr(sc, "chat_id", 0) or 0
    if chat_id:
        envelope["chat_id"] = chat_id
    return envelope


LedgerKey = Tuple[str, str]


class RecordLedger:
    """FIFO queues of emitted-record dicts, keyed by (transport, chunk_key)."""

    def __init__(self) -> None:
        self._queues: Dict[LedgerKey, Deque[dict]] = {}

    def add(self, transport: str, chunk_key: str, record: dict) -> None:
        """Queue *record* behind any earlier record with the same key."""
        self._queues.setdefault((transport, chunk_key), deque()).append(record)

    def take(self, transport: str, chunk_key: str) -> Optional[dict]:
        """Pop the oldest record for the key, or ``None`` when none is left."""
        queue = self._queues.get((transport, chunk_key))
        if not queue:
            return None
        return queue.popleft()

    def __len__(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def __bool__(self) -> bool:
        return any(self._queues.values())
