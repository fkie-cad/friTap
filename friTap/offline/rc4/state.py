"""Per-conversion RC4 pipeline state.

Registered as the ``rc4`` protocol-state namespace of
:class:`~friTap.offline.pipeline_api.WriterState` by this package's
``__init__``; the emitter / attach pass reach it through
:func:`~friTap.offline.pipeline_api.protocol_state_of`. The historical
``state.rc4_provenance`` attribute stays readable and writable on the writer
state itself via :data:`RC4_LEGACY_ATTRS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Name of the namespace on the writer state.
RC4_STATE = "rc4"


@dataclass
class Rc4PipelineState:
    """RC4 bookkeeping of ONE conversion."""

    # RC4 provenance records derived from the single-pass TLS plaintext, keyed
    # by canonical_4tuple (consumed by the nested RC4-in-TLS attach pass).
    rc4_provenance: dict = field(default_factory=dict)


# Historical WriterState attribute names routed to this namespace.
RC4_LEGACY_ATTRS = ("rc4_provenance",)


def register_rc4_pipeline_state() -> None:
    """Register :class:`Rc4PipelineState` on the writer state (idempotent)."""
    from friTap.offline.pipeline_api import register_protocol_state

    register_protocol_state(RC4_STATE, Rc4PipelineState, RC4_LEGACY_ATTRS)
