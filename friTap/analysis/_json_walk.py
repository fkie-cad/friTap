"""
Bounded, iterative JSON traversal shared by analyzers.

Replaces recursive walkers so attacker-controlled JSON can neither exhaust the
Python stack nor burn unbounded CPU: traversal stops descending past
``MAX_JSON_DEPTH`` and stops entirely after ``MAX_JSON_NODES`` visited nodes.

Events are yielded in the same pre-order a naive recursive walk would use:
a ``"container"`` event when a dict/list is entered, and a ``"field"`` event
for each dict entry whose value is a scalar (list scalars are not reported).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 50_000

CONTAINER = "container"
FIELD = "field"


@dataclass(frozen=True)
class JsonNode:
    """One traversal event: an entered container or a scalar dict field."""
    kind: str
    value: Any
    path: str
    key: str = ""


def _child_path(parent: str, key: str) -> str:
    return f"{parent}.{key}" if parent else key


def _children(obj: Any, path: str) -> Iterator[tuple[str | None, Any, str]]:
    """Yield ``(key, value, path)`` for a dict's entries or a list's items."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_str = key if isinstance(key, str) else str(key)
            yield key_str, value, _child_path(path, key_str)
    else:
        for index, item in enumerate(obj):
            yield None, item, f"{path}[{index}]"


def iter_json(
    root: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> Iterator[JsonNode]:
    """Iteratively walk *root*, yielding :class:`JsonNode` events (bounded)."""
    if not isinstance(root, (dict, list)):
        return
    yield JsonNode(CONTAINER, root, "")
    stack: list[tuple[Iterator, int]] = [(_children(root, ""), 1)]
    visited = 1
    while stack:
        children, depth = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            continue
        visited += 1
        if visited > max_nodes:
            return
        key, value, path = child
        if isinstance(value, (dict, list)):
            if depth >= max_depth:
                continue
            yield JsonNode(CONTAINER, value, path, key or "")
            stack.append((_children(value, path), depth + 1))
        elif key is not None:
            yield JsonNode(FIELD, value, path, key)


__all__ = ["MAX_JSON_DEPTH", "MAX_JSON_NODES", "CONTAINER", "FIELD", "JsonNode", "iter_json"]
