"""
"Did you mean" suggestions for misspelled names (tools, parameters, operators).

A dependency-free helper shared by the agent API (``friTap.agent_api``) and
the display-filter parser, so every layer words its hints the same way.
Each caller keeps its own similarity ``cutoff``.
"""

from __future__ import annotations

import difflib
from typing import Sequence

DEFAULT_CUTOFF = 0.5
DEFAULT_LIMIT = 3


def close_matches(word: str, candidates: Sequence[str], *, limit: int = DEFAULT_LIMIT,
                  cutoff: float = DEFAULT_CUTOFF) -> list[str]:
    """Up to ``limit`` candidates similar to ``word`` (difflib ratio >= ``cutoff``), best first."""
    return difflib.get_close_matches(word, list(candidates), n=limit, cutoff=cutoff)


def did_you_mean(word: str, candidates: Sequence[str], *, limit: int = DEFAULT_LIMIT,
                 cutoff: float = DEFAULT_CUTOFF, show_all: bool = False) -> str | None:
    """``"did you mean: a, b"`` for close candidates, else ``"valid: ..."`` (with
    ``show_all``) or ``None``."""
    close = close_matches(word, candidates, limit=limit, cutoff=cutoff)
    if close:
        return "did you mean: " + ", ".join(close)
    if show_all and candidates:
        return "valid: " + ", ".join(candidates)
    return None


__all__ = ["DEFAULT_CUTOFF", "DEFAULT_LIMIT", "close_matches", "did_you_mean"]
