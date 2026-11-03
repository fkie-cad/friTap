"""Exceptions raised by isolated stateful decoders (import-light).

Parsers import these without pulling in the worker machinery, so they can
handle isolated-decoder outcomes even when isolation is off.
"""

from __future__ import annotations


class DecoderContextLost(Exception):
    """The worker-side decoder state is gone (worker crashed, restarted, hit
    the context cap or was closed). The state cannot be rebuilt: callers
    must stop relying on it (disable / poison) instead of retrying."""


class DecoderContextError(Exception):
    """A context call failed inside the worker for a reason without a more
    specific exception type (the message is filtered worker text)."""


class HeaderListTooLarge(Exception):
    """An isolated QPACK decode produced a header list above the caps; the
    worker withheld it (the parent rejects it exactly like an oversized
    in-process result)."""
