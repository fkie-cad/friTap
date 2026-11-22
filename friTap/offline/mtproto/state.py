"""Per-conversion Telegram (MTProto cloud + Secret-Chat E2E) pipeline state.

Registered as the ``telegram`` namespace of ``WriterState``; reach it via
:func:`~friTap.offline.pipeline_api.protocol_state_of`. The names in
:data:`TELEGRAM_LEGACY_ATTRS` are also routed on the writer state itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TELEGRAM_STATE = "telegram"


@dataclass
class TelegramPipelineState:
    """Telegram side-channel and record bookkeeping of ONE conversion."""

    # Side channel for _attach_telegram_meta. Cloud: keyed by normalize_4tuple;
    # E2E: keyed by ``telegram_e2e:<fp>`` since chats can share one 4-tuple.
    mtproto_meta: dict = field(default_factory=dict)
    telegram_e2e_meta: dict = field(default_factory=dict)
    # Emitted record identities (cloud: (auth_key_id_hex, msg_id, direction);
    # E2E: (fp, msg_key_hex)) so a second decoder pass never duplicates flows.
    telegram_emitted: set = field(default_factory=set)
    # Lazily created by _telegram_ledger / _telegram_refs; counter for _next_record_seq.
    telegram_ledger: object = None
    telegram_refs: object = None
    telegram_record_seq: int = 0


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
