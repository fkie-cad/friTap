"""Filter engine: parses once, evaluates many times against Flow or DataCanonical."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .ast_nodes import (
    ASTNode, ComparisonNode, ExistenceNode,
    AndNode, OrNode, NotNode,
)
from .errors import FilterSyntaxError
from .fields import FIELD_REGISTRY, CANONICAL_FIELDS, is_canonical_only, is_field_prefix
from .parser import parse_filter, collect_fields

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.schemas.canonical import DataCanonical


class FilterEngine:
    """Compiled filter that evaluates against Flow or DataCanonical objects.

    Usage:
        engine = FilterEngine("http.response.code >= 400 and ip.dst == 10.0.0.1")
        if engine.matches(flow):
            ...
    """

    def __init__(self, expression: str) -> None:
        self._expression = expression
        self._ast = parse_filter(expression)
        self._fields = collect_fields(self._ast)
        self._canonical_only = is_canonical_only(self._fields)

    @property
    def expression(self) -> str:
        return self._expression

    @property
    def fields(self) -> set[str]:
        return self._fields

    def matches(self, flow: "Flow") -> bool:
        """Return True if the flow matches this filter."""
        return _evaluate(self._ast, flow, use_canonical=False)

    def matches_canonical(self, event: "DataCanonical") -> bool:
        """Return True if the canonical event matches (network fields only)."""
        return _evaluate(self._ast, event, use_canonical=True)

    @classmethod
    def try_create(cls, expression: str) -> "FilterEngine | str":
        """Return a FilterEngine if valid, or an error message string.

        Avoids double-parsing when callers validate then construct.
        """
        try:
            return cls(expression)
        except FilterSyntaxError as e:
            return str(e)

    @classmethod
    def try_create_lenient(cls, expression: str) -> "FilterEngine | str | None":
        """Like try_create, but returns None for incomplete-but-plausible input.

        Returns:
            FilterEngine if valid, str error if definitely wrong,
            None if the expression looks incomplete (field prefix, trailing dot, etc.)
        """
        try:
            return cls(expression)
        except FilterSyntaxError as e:
            msg = str(e)
            # Check for unknown field that is a prefix of a known field
            if "Unknown field" in msg:
                import re as _re
                m = _re.search(r"Unknown field '([^']+)'", msg)
                if m and is_field_prefix(m.group(1)):
                    return None
            # Trailing dot or partial IP — incomplete input
            stripped = expression.rstrip()
            if stripped.endswith((".","and","or","not","==","!=",">=","<=",">","<")):
                return None
            return msg

    @staticmethod
    def validate(expression: str) -> str | None:
        """Return None if expression is valid, or an error message string."""
        try:
            parse_filter(expression)
            return None
        except FilterSyntaxError as e:
            return str(e)

    @staticmethod
    def requires_flow_collector(expression: str) -> bool:
        """Return True if the expression uses fields beyond DataCanonical scope."""
        try:
            ast = parse_filter(expression)
            fields = collect_fields(ast)
            return not is_canonical_only(fields)
        except FilterSyntaxError:
            return False


# -- Evaluation ---------------------------------------------------------------

def _evaluate(node: ASTNode, obj: Any, use_canonical: bool) -> bool:
    """Recursively evaluate an AST node against an object."""
    if isinstance(node, ComparisonNode):
        return _eval_comparison(node, obj, use_canonical)
    if isinstance(node, ExistenceNode):
        return _eval_existence(node, obj, use_canonical)
    if isinstance(node, AndNode):
        return _evaluate(node.left, obj, use_canonical) and _evaluate(node.right, obj, use_canonical)
    if isinstance(node, OrNode):
        return _evaluate(node.left, obj, use_canonical) or _evaluate(node.right, obj, use_canonical)
    if isinstance(node, NotNode):
        return not _evaluate(node.operand, obj, use_canonical)
    return False


def _get_value(field_name: str, obj: Any, use_canonical: bool) -> Any:
    """Extract a field value from obj using the appropriate accessor."""
    field_def = FIELD_REGISTRY.get(field_name)
    if field_def is None:
        return None
    if use_canonical:
        accessor = field_def.canonical_accessor
        if accessor is None:
            return None
        return accessor(obj)
    return field_def.accessor(obj)


def _eval_existence(node: ExistenceNode, obj: Any, use_canonical: bool) -> bool:
    """Truthy test: field exists and is non-empty/non-zero."""
    val = _get_value(node.field, obj, use_canonical)
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return len(val) > 0
    if isinstance(val, (int, float)):
        return val != 0
    return bool(val)


import operator as _op

_OP_DISPATCH = {
    "==": _op.eq,
    "!=": _op.ne,
    ">": _op.gt,
    ">=": _op.ge,
    "<": _op.lt,
    "<=": _op.le,
}


def _eval_comparison(node: ComparisonNode, obj: Any, use_canonical: bool) -> bool:
    """Evaluate a comparison operation."""
    field_val = _get_value(node.field, obj, use_canonical)
    if field_val is None:
        return False

    op = node.operator

    if op == "matches":
        if node.compiled_regex is None:
            return False
        return node.compiled_regex.search(str(field_val)) is not None

    if op == "contains":
        return node.value_lower in str(field_val).lower()

    # Use pre-computed value_type from the AST node (avoids registry lookup)
    vtype = node.value_type

    if vtype in ("int", "float"):
        return _compare_numeric(field_val, node.value_numeric, op)
    if vtype == "bool":
        target = node.value_lower in ("true", "1", "yes")
        cmp_fn = _OP_DISPATCH.get(op)
        return cmp_fn(bool(field_val), target) if cmp_fn else False
    return _compare_string(field_val, node.value_lower, op)


def _compare_numeric(field_val: Any, compare_val: float | None, op: str) -> bool:
    """Compare numeric values using pre-parsed compare_val."""
    if compare_val is None:
        return False
    try:
        fv = float(field_val)
    except (ValueError, TypeError):
        return False
    cmp_fn = _OP_DISPATCH.get(op)
    return cmp_fn(fv, compare_val) if cmp_fn else False


def _compare_string(field_val: Any, cv: str, op: str) -> bool:
    """Compare string values (case-insensitive). cv is already lowered."""
    fv = str(field_val).lower()
    cmp_fn = _OP_DISPATCH.get(op)
    if cmp_fn is None:
        return False
    if op in ("==", "!="):
        return cmp_fn(fv, cv)
    # For ordering, try numeric first, fall back to lexicographic
    try:
        return cmp_fn(float(fv), float(cv))
    except ValueError:
        return cmp_fn(fv, cv)
