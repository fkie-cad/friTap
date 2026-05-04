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
    ASTNode, ComparisonNode, ExistenceNode,
    AndNode, OrNode, NotNode,
)
from .errors import FilterSyntaxError
from .fields import FIELD_REGISTRY, get_field
from .lexer import Token, TokenType, OPERATOR_TOKENS, tokenize


class _Parser:
    """Recursive-descent parser for filter expressions."""

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
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
        field_name = field_tok.value

        # Validate field name
        field_def = get_field(field_name)
        if field_def is None:
            raise FilterSyntaxError(
                f"Unknown field {field_name!r}",
                field_tok.position,
            )

        # Check if next token is an operator → comparison
        next_tok = self._peek()
        if next_tok.type in OPERATOR_TOKENS:
            op_tok = self._advance()
            value_tok = self._read_value()
            return self._make_comparison(field_name, op_tok, value_tok)

        # Otherwise, existence check
        return self._make_existence(field_name)

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
        self, field_name: str, op_tok: Token, value_tok: Token
    ) -> ASTNode:
        """Build a ComparisonNode, expanding dual fields to OR."""
        field_def = FIELD_REGISTRY[field_name]
        op = _OP_MAP.get(op_tok.type, op_tok.value)

        compiled = None
        if op == "matches":
            try:
                compiled = re.compile(value_tok.value)
            except re.error as e:
                raise FilterSyntaxError(
                    f"Invalid regex {value_tok.value!r}: {e}",
                    value_tok.position,
                ) from e

        # Pre-compute constants for hot-path evaluation
        vtype = field_def.value_type
        val_lower = value_tok.value.lower()
        val_numeric = None
        if vtype in ("int", "float"):
            try:
                val_numeric = float(value_tok.value)
            except ValueError:
                pass

        def _node(fname: str) -> ComparisonNode:
            fdef = FIELD_REGISTRY[fname]
            return ComparisonNode(
                fname, op, value_tok.value, compiled,
                value_type=fdef.value_type,
                value_lower=val_lower,
                value_numeric=val_numeric,
            )

        if field_def.is_dual and field_def.dual_partner:
            return OrNode(_node(field_name), _node(field_def.dual_partner))

        return _node(field_name)

    def _make_existence(self, field_name: str) -> ASTNode:
        """Build an ExistenceNode, expanding dual fields to OR."""
        field_def = FIELD_REGISTRY[field_name]

        if field_def.is_dual and field_def.dual_partner:
            left = ExistenceNode(field_name)
            right = ExistenceNode(field_def.dual_partner)
            return OrNode(left, right)

        return ExistenceNode(field_name)


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
    parser = _Parser(tokens)
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
