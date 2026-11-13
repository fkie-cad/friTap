"""Tiny filesystem helpers shared by the capture writers and the offline tools."""

from __future__ import annotations

import os
from typing import Optional


def remove_quietly(path: str) -> None:
    """Delete *path* if it exists; ignore every error."""
    try:
        os.remove(path)
    except OSError:
        pass


def is_non_empty_file(path: Optional[str]) -> bool:
    """True when *path* names an existing regular file with content."""
    try:
        return bool(path) and os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False
