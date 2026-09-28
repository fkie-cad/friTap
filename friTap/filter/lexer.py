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


# Characters allowed after the first one of a bare word. "/" lets unquoted
# protocol labels such as HTTP/2 or HTTP/1.1 be written as values.
_BARE_WORD_CHARS = "._-/"


def _starts_bare_word(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _scan_bare_word(text: str, i: int) -> int:
    """Return the index just past the bare word continuing at *i*."""
    while i < len(text) and (text[i].isalnum() or text[i] in _BARE_WORD_CHARS):
        i += 1
    return i


_QUOTES = ('"', "'")

# Escapes decoded inside a (non-raw) quoted string. Anything else keeps its
# backslash verbatim, so regex escapes such as \s \d \w \b \. \( \x41
# reach ``matches`` unchanged. Decision (Wireshark is the reference): only the
# escapes friTap already decoded (\\ \n \t and the quotes \" \') plus \r
# are translated. \b is NOT backspace here (it stays a regex word boundary)
# and \x / octal / \u are not decoded -- use a raw string r"..." whenever a
# pattern must reach the regex engine completely untouched.
_STRING_ESCAPES = {
    "\\": "\\",
    '"': '"',
    "'": "'",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _scan_string(text: str, i: int, raw: bool) -> tuple[Token, int]:
    """Scan a quoted string starting at *i* (at the ``r`` prefix if *raw*).

    Returns the STRING token and the index just past the closing quote. In a
    raw string every backslash is literal; a backslash still protects the
    next character, so ``r"a\\"b"`` keeps ``\\"`` and does not end there.
    """
    start = i
    if raw:
        i += 1
    quote = text[i]
    i += 1
    parts: list[str] = []
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nc = text[i + 1]
            parts.append(c + nc if raw else _STRING_ESCAPES.get(nc, c + nc))
            i += 2
        elif c == quote:
            return Token(TokenType.STRING, "".join(parts), start), i + 1
        else:
            parts.append(c)
            i += 1
    kind = "raw string" if raw else "string"
    prefix = text[start] if raw else ""
    raise FilterSyntaxError(f"Unterminated {kind} starting with {prefix}{quote}", start)


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

        # Raw string: r"..." / R'...' -- only when the r is IMMEDIATELY
        # followed by a quote, so bare words like rc4 or rc4.key_len stay fields.
        if ch in "rR" and i + 1 < length and text[i + 1] in _QUOTES:
            token, i = _scan_string(text, i, raw=True)
            tokens.append(token)
            continue

        # Quoted string
        if ch in _QUOTES:
            token, i = _scan_string(text, i, raw=False)
            tokens.append(token)
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
            if i < length and _starts_bare_word(text[i]):
                # A digit run followed by letters is a bare word, e.g. the
                # hex id 0a1b2c or 0x1f — not a number plus a stray token.
                i = _scan_bare_word(text, i)
                tokens.append(Token(TokenType.FIELD, text[start:i], start))
                continue
            word = text[start:i]
            if word.endswith(".") or dot_count >= 2:
                # Trailing dot or multiple dots → IP address / partial, treat as bare word
                tokens.append(Token(TokenType.FIELD, word, start))
            else:
                tokens.append(Token(TokenType.NUMBER, word, start))
            continue

        # Bare word (field name or keyword or bare value)
        if _starts_bare_word(ch):
            start = i
            i = _scan_bare_word(text, i)
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
