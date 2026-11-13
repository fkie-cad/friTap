"""The single normalizer for TLS ``client_random`` values reported by the agent.

The agent trees disagree on case (``--modern`` datalog values are upper-case,
caller stacks lower-case) and some hooks send placeholders such as ``"???"``.
Every host path that keys or joins on a client_random goes through
:func:`normalize_client_random`, so ``cr:`` keys match across message types and
a placeholder never collapses unrelated connections onto one key.
"""

from __future__ import annotations

import re

#: 32 random bytes as lower-case hex: the only accepted client_random form.
_CLIENT_RANDOM_PATTERN = re.compile(r"[0-9a-f]{64}")


def normalize_client_random(value) -> str:
    """*value* as lower-case 64-char hex, or ``""`` when it is not a client_random."""
    if not isinstance(value, str):
        return ""
    candidate = value.strip().lower()
    return candidate if _CLIENT_RANDOM_PATTERN.fullmatch(candidate) else ""
