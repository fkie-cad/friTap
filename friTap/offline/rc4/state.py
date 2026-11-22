"""Per-conversion RC4 pipeline state.

Registered as the ``rc4`` namespace of ``WriterState``; reach it via
:func:`~friTap.offline.pipeline_api.protocol_state_of`. ``rc4_provenance`` on the
writer state is routed here via :data:`RC4_LEGACY_ATTRS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

RC4_STATE = "rc4"


@dataclass
class Rc4PipelineState:
    """RC4 bookkeeping of ONE conversion."""

    # RC4 provenance records derived from the single-pass TLS plaintext, keyed
    # by canonical_4tuple (consumed by the nested RC4-in-TLS attach pass).
    rc4_provenance: dict = field(default_factory=dict)


RC4_LEGACY_ATTRS = ("rc4_provenance",)


def register_rc4_pipeline_state() -> None:
    """Register :class:`Rc4PipelineState` on the writer state (idempotent)."""
    from friTap.offline.pipeline_api import register_protocol_state

    register_protocol_state(RC4_STATE, Rc4PipelineState, RC4_LEGACY_ATTRS)
