"""Tokenizer for filter expressions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .errors import FilterSyntaxError


class TokenType(Enum):
    FIELD = auto()      # dotted identifier: ip.src, http.request.method
    STRING = auto()     # quoted string: "value", 'value'
    NUMBER = auto()     # numeric literal: 443, 3.14
    OP_EQ = auto()      # ==
    OP_NE = auto()      # !=
    OP_GT = auto()      # >
    OP_GE = auto()      # >=
    OP_LT = auto()      # <
    OP_LE = auto()      # <=
    CONTAINS = auto()   # contains
    MATCHES = auto()    # matches
    AND = auto()        # and
    OR = auto()         # or
    NOT = auto()        # not
    BANG = auto()        # !
    LPAREN = auto()     # (
    RPAREN = auto()     # )
    EOF = auto()


OPERATOR_TOKENS = frozenset({
    TokenType.OP_EQ, TokenType.OP_NE,
    TokenType.OP_GT, TokenType.OP_GE,
    TokenType.OP_LT, TokenType.OP_LE,
    TokenType.CONTAINS, TokenType.MATCHES,
})

_KEYWORDS = {
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "contains": TokenType.CONTAINS,
    "matches": TokenType.MATCHES,
}


@dataclass(frozen=True)
class Token:
    type: TokenType
    value: str
    position: int


def tokenize(text: str) -> list[Token]:
    """Tokenize a filter expression string into a list of Tokens."""
    tokens: list[Token] = []
    i = 0
    length = len(text)

    while i < length:
        ch = text[i]

        # Skip whitespace
        if ch in " \t\r\n":
            i += 1
            continue

        # Parentheses
        if ch == "(":
            tokens.append(Token(TokenType.LPAREN, "(", i))
            i += 1
            continue
        if ch == ")":
            tokens.append(Token(TokenType.RPAREN, ")", i))
            i += 1
            continue

        # Two-char operators
        if i + 1 < length:
            two = text[i:i + 2]
            if two == "==":
                tokens.append(Token(TokenType.OP_EQ, "==", i))
                i += 2
                continue
            if two == "!=":
                tokens.append(Token(TokenType.OP_NE, "!=", i))
                i += 2
                continue
            if two == ">=":
                tokens.append(Token(TokenType.OP_GE, ">=", i))
                i += 2
                continue
            if two == "<=":
                tokens.append(Token(TokenType.OP_LE, "<=", i))
                i += 2
                continue

        # Single-char operators
        if ch == ">":
            tokens.append(Token(TokenType.OP_GT, ">", i))
            i += 1
            continue
        if ch == "<":
            tokens.append(Token(TokenType.OP_LT, "<", i))
            i += 1
            continue
        if ch == "!":
            tokens.append(Token(TokenType.BANG, "!", i))
            i += 1
            continue

        # Quoted string
        if ch in ('"', "'"):
            start = i
            quote = ch
            i += 1
            parts: list[str] = []
            while i < length:
                c = text[i]
                if c == "\\" and i + 1 < length:
                    # Escape sequence
                    nc = text[i + 1]
                    if nc == quote:
                        parts.append(quote)
                    elif nc == "\\":
                        parts.append("\\")
                    elif nc == "n":
                        parts.append("\n")
                    elif nc == "t":
                        parts.append("\t")
                    else:
                        parts.append(nc)
                    i += 2
                elif c == quote:
                    i += 1
                    break
                else:
                    parts.append(c)
                    i += 1
            else:
                raise FilterSyntaxError(f"Unterminated string starting with {quote}", start)
            tokens.append(Token(TokenType.STRING, "".join(parts), start))
            continue

        # Number or dotted numeric value (e.g. IP address: 10.0.0.1)
        if ch.isdigit() or (ch == "-" and i + 1 < length and text[i + 1].isdigit()):
            start = i
            if ch == "-":
                i += 1
            dot_count = 0
            while i < length and (text[i].isdigit() or text[i] == "."):
                if text[i] == ".":
                    dot_count += 1
                    i += 1
                    # If next char is NOT a digit, we have a trailing dot —
                    # consume remaining digit/dot chars for partial IPs like "10.0."
                    if i >= length or not text[i].isdigit():
                        while i < length and (text[i].isdigit() or text[i] == "."):
                            if text[i] == ".":
                                dot_count += 1
                            i += 1
                        break
                else:
                    i += 1
            word = text[start:i]
            if word.endswith(".") or dot_count >= 2:
                # Trailing dot or multiple dots → IP address / partial, treat as bare word
                tokens.append(Token(TokenType.FIELD, word, start))
            else:
                tokens.append(Token(TokenType.NUMBER, word, start))
            continue

        # Bare word (field name or keyword or bare value)
        if ch.isalpha() or ch == "_":
            start = i
            while i < length and (text[i].isalnum() or text[i] in "._-"):
                i += 1
            word = text[start:i]
            lower = word.lower()
            if lower in _KEYWORDS:
                tokens.append(Token(_KEYWORDS[lower], lower, start))
            else:
                # Could be a field name (has dots) or bare value
                tokens.append(Token(TokenType.FIELD, word, start))
            continue

        raise FilterSyntaxError(f"Unexpected character {ch!r}", i)

    tokens.append(Token(TokenType.EOF, "", length))
    return tokens
