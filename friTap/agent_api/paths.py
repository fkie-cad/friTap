"""
Sandboxed path resolution for agent API tools.

Paths given by an agent are untrusted: they are resolved (symlinks included)
and must stay inside the context's sandbox root.
"""

from __future__ import annotations

import os
from pathlib import Path

from friTap.agent_api.errors import ToolError


def resolve_under_root(
    path_str: str,
    root: Path | str,
    *,
    suffix: str | None = None,
    must_exist: bool = True,
) -> Path:
    """Resolve ``path_str`` (relative to ``root``) to a real path inside ``root``.

    Raises:
        ToolError: ``bad_param`` (empty path / wrong suffix), ``forbidden``
            (resolves outside ``root``, e.g. via ``..`` or a symlink) or
            ``not_found`` (``must_exist`` and the file is missing).
    """
    if not path_str:
        raise ToolError("path must not be empty", "bad_param")
    real_root = Path(os.path.realpath(root))
    resolved = Path(os.path.realpath(real_root / os.path.expanduser(path_str)))
    if not resolved.is_relative_to(real_root):
        raise ToolError(
            f"path {path_str!r} is outside the sandbox root", "forbidden",
            hint=f"use a path under {real_root}",
        )
    _check_suffix(resolved, suffix)
    if must_exist and not resolved.exists():
        raise ToolError(f"file not found: {path_str}", "not_found")
    return resolved


def _check_suffix(path: Path, suffix: str | None) -> None:
    if suffix and path.suffix.lower() != suffix.lower():
        raise ToolError(
            f"expected a {suffix} file, got {path.name!r}", "bad_param",
            hint=f"pass a path ending in {suffix}",
        )


__all__ = ["resolve_under_root"]
