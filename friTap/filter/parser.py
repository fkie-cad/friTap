"""Recursive-descent parser for filter expressions.

Grammar:
    expression  := or_expr
    or_expr     := and_expr ( "or" and_expr )*
    and_expr    := not_expr ( "and" not_expr )*
    not_expr    := "not" not_expr | "!" not_expr | primary
    primary     := comparison | existence | "(" expression ")"
    comparison  := field_name operator value
    existence   := field_name
    operator    := "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "matches"
"""

from __future__ import annotations

import re

from .ast_nodes import (
    AndNode,
    ASTNode,
    ComparisonNode,
    ExistenceNode,
    NotNode,
    OrNode,
)
from .errors import FIELD_REPLACEMENT, FilterSyntaxError, Suggestion, UnknownFieldError
from .fields import FieldDef, did_you_mean, get_field
from .lexer import OPERATOR_TOKENS, Token, TokenType, tokenize


class _Parser:
    """Recursive-descent parser for filter expressions."""

    def __init__(self, tokens: list[Token], text: str = "") -> None:
        self._tokens = tokens
        self._text = text
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._peek()
        if tok.type != ttype:
            raise FilterSyntaxError(
                f"Expected {ttype.name}, got {tok.type.name} ({tok.value!r})",
                tok.position,
            )
        return self._advance()

    # -- Grammar rules --------------------------------------------------------

    def parse(self) -> ASTNode:
        node = self._or_expr()
        if self._peek().type != TokenType.EOF:
            tok = self._peek()
            raise FilterSyntaxError(
                f"Unexpected token {tok.value!r}", tok.position
            )
        return node

    def _or_expr(self) -> ASTNode:
        left = self._and_expr()
        while self._peek().type == TokenType.OR:
            self._advance()
            right = self._and_expr()
            left = OrNode(left, right)
        return left

    def _and_expr(self) -> ASTNode:
        left = self._not_expr()
        while self._peek().type == TokenType.AND:
            self._advance()
            right = self._not_expr()
            left = AndNode(left, right)
        return left

    def _not_expr(self) -> ASTNode:
        tok = self._peek()
        if tok.type == TokenType.NOT:
            self._advance()
            operand = self._not_expr()
            return NotNode(operand)
        if tok.type == TokenType.BANG:
            self._advance()
            operand = self._not_expr()
            return NotNode(operand)
        return self._primary()

    def _primary(self) -> ASTNode:
        tok = self._peek()

        # Parenthesized group
        if tok.type == TokenType.LPAREN:
            self._advance()
            node = self._or_expr()
            self._expect(TokenType.RPAREN)
            return node

        # Must be a field name
        if tok.type != TokenType.FIELD:
            raise FilterSyntaxError(
                f"Expected field name, got {tok.type.name} ({tok.value!r})",
                tok.position,
            )

        field_tok = self._advance()

        # Validate field name (case-insensitive; resolves dynamic fields)
        field_def = get_field(field_tok.value)
        if field_def is None:
            raise self._unknown_field(field_tok)

        # Check if next token is an operator → comparison
        next_tok = self._peek()
        if next_tok.type in OPERATOR_TOKENS:
            op_tok = self._advance()
            value_tok = self._read_value()
            return self._make_comparison(field_def, op_tok, value_tok)

        # Otherwise, existence check
        return self._make_existence(field_def)

    def _unknown_field(self, tok: Token) -> UnknownFieldError:
        """Build an UnknownFieldError with did-you-mean names and fixes."""
        names = did_you_mean(tok.value)
        followed_by_operator = self._peek().type in OPERATOR_TOKENS
        actions = unknown_field_actions(
            self._text, tok.position, tok.value, names, followed_by_operator)
        return UnknownFieldError(
            tok.value, tok.position, did_you_mean=names, actions=actions,
            followed_by_operator=followed_by_operator,
        )

    def _read_value(self) -> Token:
        """Read a value token (string, number, or bare word used as value)."""
        tok = self._peek()
        if tok.type in (TokenType.STRING, TokenType.NUMBER, TokenType.FIELD):
            return self._advance()
        raise FilterSyntaxError(
            f"Expected value, got {tok.type.name} ({tok.value!r})",
            tok.position,
        )

    # -- Node construction with dual-field expansion --------------------------

    def _make_comparison(
        self, field_def: FieldDef, op_tok: Token, value_tok: Token
    ) -> ASTNode:
        """Build a ComparisonNode, expanding dual fields to OR."""
        op = _OP_MAP.get(op_tok.type, op_tok.value)

        compiled = None
        if op == "matches":
            # Content (bytes) is searched lowercased, so its regex ignores case.
            flags = re.IGNORECASE if field_def.value_type == "bytes" else 0
            try:
                compiled = re.compile(value_tok.value, flags)
            except re.error as e:
                raise FilterSyntaxError(
                    f"Invalid regex {value_tok.value!r}: {e}",
                    value_tok.position,
                ) from e

        # Pre-compute constants for hot-path evaluation
        vtype = field_def.value_type
        val_lower = value_tok.value.lower()
        val_numeric = _parse_numeric(value_tok.value) if vtype in ("int", "float") else None

        def _node(fdef: FieldDef) -> ComparisonNode:
            return ComparisonNode(
                fdef.name, op, value_tok.value, compiled,
                value_type=fdef.value_type,
                value_lower=val_lower,
                value_numeric=val_numeric,
                value_bytes=val_lower.encode("utf-8"),
                value_set=_operand_equivalents(fdef, op, value_tok.value),
                field_def=fdef,
            )

        partner = _dual_partner(field_def)
        if partner is not None:
            # Wireshark's rule for a two-occurrence field: ``!=`` means NO
            # occurrence equals the operand (``ip.addr != X`` excludes flows
            # touching X at either end), every other operator ANY occurrence.
            combine = AndNode if op == "!=" else OrNode
            return combine(_node(field_def), _node(partner))

        return _node(field_def)

    def _make_existence(self, field_def: FieldDef) -> ASTNode:
        """Build an ExistenceNode, expanding dual fields to OR."""
        partner = _dual_partner(field_def)
        if partner is not None:
            left = ExistenceNode(field_def.name, field_def=field_def)
            right = ExistenceNode(partner.name, field_def=partner)
            return OrNode(left, right)

        return ExistenceNode(field_def.name, field_def=field_def)


def _parse_numeric(text: str) -> float | None:
    """Parse a numeric operand: decimal/float, else a prefixed int (``0x1f``)."""
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return float(int(text, 0))
    except ValueError:
        return None


def _operand_equivalents(field_def: FieldDef, op: str, value: str) -> frozenset[str] | None:
    """Precompute the ==/!= equivalence set for fields that define one."""
    if op not in ("==", "!=") or field_def.operand_equivalents is None:
        return None
    return field_def.operand_equivalents(value) or None


def _dual_partner(field_def: FieldDef) -> FieldDef | None:
    if field_def.is_dual and field_def.dual_partner:
        return get_field(field_def.dual_partner)
    return None


def _quote(value: str) -> str:
    """Quote *value* as a filter string literal (escapes \\ and \")."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# Generic searches offered when a bare word is not a known field:
# (field, Suggestion.kind), in display order.
SUGGESTION_FIELDS: tuple[tuple[str, str], ...] = (
    ("protocol", "protocol_search"),
    ("method", "method_search"),
    ("frame", "frame_search"),
)


def _split_around(text: str, position: int, token: str) -> tuple[str, str]:
    """Return the text before and after *token* at *position* ("" if absent)."""
    if position < 0 or text[position:position + len(token)] != token:
        return "", ""
    return text[:position], text[position + len(token):]


def unknown_field_actions(
    text: str, position: int, token: str, names: list[str], followed_by_operator: bool,
) -> tuple[Suggestion, ...]:
    """Ready-to-apply fixes for the unknown *token* at *position* in *text*.

    A bare word gets the generic searches plus the first did-you-mean name:
    ``"ip.src == 1.2.3.4 and foo"`` -> ``'ip.src == 1.2.3.4 and protocol
    contains "foo"'``, ... A word used as a field (followed by an operator)
    only gets did-you-mean replacements, since ``protocol contains "foo" == 3``
    is not valid: ``"htp.host == x"`` -> ``"http.host == x"``. Without a
    locatable token the fix alone is returned.
    """
    prefix, suffix = _split_around(text, position, token)

    def replace(label: str, kind: str) -> Suggestion:
        return Suggestion(f"{prefix}{label}{suffix}", kind, label)

    if followed_by_operator:
        return tuple(replace(name, FIELD_REPLACEMENT)
                     for name in names[:len(SUGGESTION_FIELDS)])
    searches = [replace(f"{field} contains {_quote(token)}", kind)
                for field, kind in SUGGESTION_FIELDS]
    did_you_mean_fix = [replace(names[0], FIELD_REPLACEMENT)] if names else []
    return tuple(searches + did_you_mean_fix)


_OP_MAP = {
    TokenType.OP_EQ: "==",
    TokenType.OP_NE: "!=",
    TokenType.OP_GT: ">",
    TokenType.OP_GE: ">=",
    TokenType.OP_LT: "<",
    TokenType.OP_LE: "<=",
    TokenType.CONTAINS: "contains",
    TokenType.MATCHES: "matches",
}


def parse_filter(text: str) -> ASTNode:
    """Parse a filter expression string into an AST.

    Raises FilterSyntaxError on invalid syntax or unknown fields.
    """
    text = text.strip()
    if not text:
        raise FilterSyntaxError("Empty filter expression")
    tokens = tokenize(text)
    parser = _Parser(tokens, text)
    return parser.parse()


def collect_fields(node: ASTNode) -> set[str]:
    """Collect all field names referenced in an AST."""
    fields: set[str] = set()
    _collect(node, fields)
    return fields


def _collect(node: ASTNode, fields: set[str]) -> None:
    if isinstance(node, ComparisonNode):
        fields.add(node.field)
    elif isinstance(node, ExistenceNode):
        fields.add(node.field)
    elif isinstance(node, (AndNode, OrNode)):
        _collect(node.left, fields)
        _collect(node.right, fields)
    elif isinstance(node, NotNode):
        _collect(node.operand, fields)
