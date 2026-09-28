"""AST node types for filter expressions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field as _dc_field
from typing import Any, Union


@dataclass(frozen=True)
class ComparisonNode:
    """Binary comparison: field op value."""
    field: str
    operator: str  # ==, !=, >, >=, <, <=, contains, matches
    value: str
    compiled_regex: re.Pattern | None = None
    # Pre-computed at parse time for hot-path performance:
    value_type: str = "str"       # from field registry
    value_lower: str = ""         # lowercased value for string comparisons
    value_numeric: float | None = None  # pre-parsed numeric value
    value_bytes: bytes = b""      # value_lower UTF-8 encoded (bytes fields)
    # Lowercase values equal to the operand for ==/!= (FieldDef
    # ``operand_equivalents``); None means plain case-insensitive equality.
    value_set: frozenset[str] | None = None
    # Resolved FieldDef (static or dynamic); excluded from equality/repr.
    field_def: Any = _dc_field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class ExistenceNode:
    """Truthy/existence check on a field."""
    field: str
    # Resolved FieldDef (static or dynamic); excluded from equality/repr.
    field_def: Any = _dc_field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class AndNode:
    """Logical AND of two sub-expressions."""
    left: ASTNode
    right: ASTNode


@dataclass(frozen=True)
class OrNode:
    """Logical OR of two sub-expressions."""
    left: ASTNode
    right: ASTNode


@dataclass(frozen=True)
class NotNode:
    """Logical NOT of a sub-expression."""
    operand: ASTNode


ASTNode = Union[ComparisonNode, ExistenceNode, AndNode, OrNode, NotNode]
