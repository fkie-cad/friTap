"""Filter engine: parses once, evaluates many times against Flow or DataCanonical."""

from __future__ import annotations

import operator as _op
import re
from typing import TYPE_CHECKING, Any

from .ast_nodes import (
    AndNode,
    ASTNode,
    ComparisonNode,
    ExistenceNode,
    NotNode,
    OrNode,
)
from .errors import FilterSyntaxError, UnknownFieldError
from .fields import (
    is_canonical_only,
    is_field_prefix,
    non_canonical_fields,
)
from .parser import collect_fields, parse_filter

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
        self._ast = _reorder_by_cost(parse_filter(expression))
        self._fields = collect_fields(self._ast)
        self._canonical_only = is_canonical_only(self._fields)
        self._needs_context = _uses_context(self._ast)

    @property
    def expression(self) -> str:
        return self._expression

    @property
    def fields(self) -> set[str]:
        return self._fields

    @property
    def needs_context(self) -> bool:
        """True if any referenced field (e.g. ``frame``) needs the eval context.

        Callers can skip building the (expensive) content context otherwise.
        """
        return self._needs_context

    def matches(self, flow: "Flow", ctx: Any = None) -> bool:
        """Return True if the flow matches this filter.

        *ctx* is an optional evaluation context for context-needing fields
        (``frame``): a duck-typed object with ``text_for(obj) -> bytes | None``
        returning the flow's content as LOWERCASED bytes.
        """
        return _evaluate(self._ast, flow, False, ctx)

    def matches_canonical(self, event: "DataCanonical") -> bool:
        """Return True if the canonical event matches (network fields only)."""
        return _evaluate(self._ast, event, True, None)

    @classmethod
    def try_create_detailed(cls, expression: str) -> "FilterEngine | FilterSyntaxError":
        """Return a FilterEngine if valid, or the FilterSyntaxError on failure.

        Lets UIs read the structured hints of an ``UnknownFieldError``
        (``did_you_mean`` / ``actions``) instead of a flat string.
        """
        try:
            return cls(expression)
        except FilterSyntaxError as e:
            return e

    @classmethod
    def try_create(cls, expression: str) -> "FilterEngine | str":
        """Return a FilterEngine if valid, or an error message string.

        Avoids double-parsing when callers validate then construct.
        """
        result = cls.try_create_detailed(expression)
        return str(result) if isinstance(result, FilterSyntaxError) else result

    @classmethod
    def try_create_lenient(cls, expression: str) -> "FilterEngine | str | None":
        """Like try_create, but returns None for incomplete-but-plausible input.

        Returns:
            FilterEngine if valid, str error if definitely wrong,
            None if the expression looks incomplete (field prefix, trailing dot, etc.)
        """
        result = cls.try_create_detailed(expression)
        if not isinstance(result, FilterSyntaxError):
            return result
        return None if cls.is_incomplete(expression, result) else str(result)

    @staticmethod
    def is_incomplete(expression: str, error: FilterSyntaxError) -> bool:
        """True if *error* on *expression* looks like the user is still typing.

        That is an unknown field that is a (case-insensitive) prefix of a known
        field or protocol name, or a trailing dot / connective / operator.
        """
        if isinstance(error, UnknownFieldError) and is_field_prefix(error.name):
            return True
        stripped = expression.rstrip()
        return (stripped.endswith(_INCOMPLETE_SUFFIXES)
                or _DANGLING_CONNECTIVE.search(stripped) is not None)

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
        return bool(FilterEngine.non_canonical_fields(expression))

    @staticmethod
    def non_canonical_fields(expression: str) -> list[str]:
        """Fields of *expression* that cannot be evaluated on a data event.

        Headless capture filters single ``DataCanonical`` events, where these
        fields are always absent. Returns ``[]`` for an invalid expression.
        """
        try:
            return non_canonical_fields(collect_fields(parse_filter(expression)))
        except FilterSyntaxError:
            return []

    @property
    def canonical_only(self) -> bool:
        """True if every referenced field works on DataCanonical events."""
        return self._canonical_only


# Endings of an expression that is still being typed (trailing dot or
# partial IP, dangling operator).
_INCOMPLETE_SUFFIXES: tuple[str, ...] = (
    ".", "==", "!=", ">=", "<=", ">", "<",
)

# A dangling connective as a whole word: "http and" is incomplete, but an
# unknown word that merely ends in the letters ("bogusmotor", "brand") is not.
_DANGLING_CONNECTIVE = re.compile(r"(?:^|[\s()])(?:and|or|not)$", re.IGNORECASE)


# -- Cost ordering ------------------------------------------------------------

def _uses_context(node: ASTNode) -> bool:
    """True if any field under *node* needs the evaluation context."""
    if isinstance(node, (ComparisonNode, ExistenceNode)):
        fdef = node.field_def
        return bool(fdef and fdef.needs_context)
    if isinstance(node, (AndNode, OrNode)):
        return _uses_context(node.left) or _uses_context(node.right)
    if isinstance(node, NotNode):
        return _uses_context(node.operand)
    return False


def _reorder_by_cost(node: ASTNode) -> ASTNode:
    """Evaluate cheap children of ``and``/``or`` before context-needing ones.

    Evaluation is side-effect free, so swapping operands preserves semantics;
    only a context-needing left operand with a cheap right one is swapped
    (stable otherwise). Short-circuiting then skips the expensive side.
    """
    if isinstance(node, (AndNode, OrNode)):
        left = _reorder_by_cost(node.left)
        right = _reorder_by_cost(node.right)
        if _uses_context(left) and not _uses_context(right):
            left, right = right, left
        return type(node)(left, right)
    if isinstance(node, NotNode):
        return NotNode(_reorder_by_cost(node.operand))
    return node


# -- Evaluation ---------------------------------------------------------------

def _evaluate(node: ASTNode, obj: Any, use_canonical: bool, ctx: Any = None) -> bool:
    """Recursively evaluate an AST node against an object."""
    if isinstance(node, ComparisonNode):
        return _eval_comparison(node, obj, use_canonical, ctx)
    if isinstance(node, ExistenceNode):
        return _eval_existence(node, obj, use_canonical, ctx)
    if isinstance(node, AndNode):
        return (_evaluate(node.left, obj, use_canonical, ctx)
                and _evaluate(node.right, obj, use_canonical, ctx))
    if isinstance(node, OrNode):
        return (_evaluate(node.left, obj, use_canonical, ctx)
                or _evaluate(node.right, obj, use_canonical, ctx))
    if isinstance(node, NotNode):
        return not _evaluate(node.operand, obj, use_canonical, ctx)
    return False


def _get_value(
    node: ComparisonNode | ExistenceNode, obj: Any, use_canonical: bool, ctx: Any = None
) -> Any:
    """Extract a field value from obj using the appropriate accessor."""
    field_def = node.field_def
    if field_def is None:
        return None
    if use_canonical:
        accessor = field_def.canonical_accessor
        if accessor is None:
            return None
        return accessor(obj)
    if field_def.needs_context:
        return field_def.accessor(obj, ctx)
    return field_def.accessor(obj)


_MULTI_TYPES = (tuple, list, set, frozenset)


def _is_truthy(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (str, bytes, bytearray)):
        return len(val) > 0
    if isinstance(val, (int, float)):
        return val != 0
    return bool(val)


def _eval_existence(
    node: ExistenceNode, obj: Any, use_canonical: bool, ctx: Any = None
) -> bool:
    """Truthy test: field exists and is non-empty/non-zero.

    A multi-valued field exists when at least one value is truthy, the same
    rule as for scalars: ``mtproto.obfuscated`` holding ``(False,)`` does not
    match, nor does a count holding only ``0``.
    """
    val = _get_value(node, obj, use_canonical, ctx)
    if isinstance(val, _MULTI_TYPES):
        return any(_is_truthy(v) for v in val)
    return _is_truthy(val)


_OP_DISPATCH = {
    "==": _op.eq,
    "!=": _op.ne,
    ">": _op.gt,
    ">=": _op.ge,
    "<": _op.lt,
    "<=": _op.le,
}


def _eval_comparison(
    node: ComparisonNode, obj: Any, use_canonical: bool, ctx: Any = None
) -> bool:
    """Evaluate a comparison (Wireshark multi-occurrence rule for tuples).

    Multi-valued fields: every operator is true if ANY value matches, except
    ``!=``, which is true if NO value equals the operand. No values -> False.
    """
    field_val = _get_value(node, obj, use_canonical, ctx)
    if field_val is None:
        return False
    if not isinstance(field_val, _MULTI_TYPES):
        return _compare_scalar(node, field_val, node.operator)

    values = [v for v in field_val if v is not None]
    if not values:
        return False
    if node.operator == "!=":
        return not any(_compare_scalar(node, v, "==") for v in values)
    return any(_compare_scalar(node, v, node.operator) for v in values)


def _compare_scalar(node: ComparisonNode, field_val: Any, op: str) -> bool:
    """Compare one field value against the node's operand using *op*."""
    if isinstance(field_val, (bytes, bytearray)):
        return _compare_bytes(node, field_val, op)

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
    if node.value_set is not None and op in ("==", "!="):
        is_equal = str(field_val).lower() in node.value_set
        return is_equal if op == "==" else not is_equal
    return _compare_string(field_val, node.value_lower, op)


def _compare_bytes(node: ComparisonNode, field_val: bytes, op: str) -> bool:
    """Compare content bytes. *field_val* is assumed already lowercased.

    ``contains`` is a case-insensitive bytes search (works on binary data);
    ``matches`` runs the (IGNORECASE) regex over the UTF-8 decoded text, with
    undecodable bytes kept as surrogate escapes so binary data never raises
    and non-ASCII patterns (``"über"``) match their UTF-8 encoding.
    """
    if op == "contains":
        return node.value_bytes in field_val
    if op == "matches":
        if node.compiled_regex is None:
            return False
        text = bytes(field_val).decode("utf-8", errors="surrogateescape")
        return node.compiled_regex.search(text) is not None
    if op == "==":
        return bytes(field_val) == node.value_bytes
    if op == "!=":
        return bytes(field_val) != node.value_bytes
    return False


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
