"""Per-conversion Telegram (MTProto cloud + Secret-Chat E2E) pipeline state.

Registered as the ``telegram`` protocol-state namespace of
:class:`~friTap.offline.pipeline_api.WriterState` by this package's
``__init__``; the emitters / attach pass reach it through
:func:`~friTap.offline.pipeline_api.protocol_state_of`. The historical
``WriterState`` attribute names (``state.mtproto_meta`` etc.) stay readable and
writable on the writer state itself via :data:`TELEGRAM_LEGACY_ATTRS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Name of the namespace on the writer state.
TELEGRAM_STATE = "telegram"


@dataclass
class TelegramPipelineState:
    """Telegram side-channel and record bookkeeping of ONE conversion."""

    # Parsed-message side channel. Cloud transport (mtproto) is keyed by
    # normalize_4tuple like Signal; Secret-Chat E2E (telegram_e2e) is keyed by its
    # ``telegram_e2e:<fp>`` session id since several chats share one 4-tuple.
    # Both are consumed by _attach_telegram_meta.
    mtproto_meta: dict = field(default_factory=dict)
    telegram_e2e_meta: dict = field(default_factory=dict)
    # Identities of Telegram records already emitted during this conversion
    # (cloud: (auth_key_id_hex, msg_id, direction); E2E: (fp, msg_key_hex)),
    # so a second decoder pass over the same traffic never duplicates flows.
    telegram_emitted: set = field(default_factory=set)
    # Lazily created by _telegram_ledger / _telegram_refs (None = no Telegram
    # record emitted yet) and the record counter behind _next_record_seq.
    telegram_ledger: object = None
    telegram_refs: object = None
    telegram_record_seq: int = 0


# Historical WriterState attribute names routed to this namespace.
TELEGRAM_LEGACY_ATTRS = (
    "mtproto_meta",
    "telegram_e2e_meta",
    "telegram_emitted",
    "telegram_ledger",
    "telegram_refs",
    "telegram_record_seq",
)


def register_telegram_pipeline_state() -> None:
    """Register :class:`TelegramPipelineState` on the writer state (idempotent)."""
    from friTap.offline.pipeline_api import register_protocol_state

    register_protocol_state(TELEGRAM_STATE, TelegramPipelineState, TELEGRAM_LEGACY_ATTRS)
