"""Display-filter lexer: string escapes and raw strings.

Unknown escapes keep their backslash so regex escapes (``\\s``, ``\\d``,
``\\.`` ...) reach ``matches`` intact; ``r"..."`` raw strings keep every
backslash. Pure Python — no device/Frida.
"""

from __future__ import annotations

import pytest

from friTap.filter import FilterEngine, FilterSyntaxError
from friTap.filter.lexer import TokenType, tokenize
from tests.unit._display_filter_helpers import FakeCtx as _FakeCtx
from tests.unit._display_filter_helpers import http_flow


def _string_value(literal: str) -> str:
    """Tokenize *literal* (a single string literal) and return its value."""
    tokens = tokenize(literal)
    assert [t.type for t in tokens] == [TokenType.STRING, TokenType.EOF]
    return tokens[0].value


# ---------------------------------------------------------------------------
# Unknown escapes keep the backslash
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal, expected", [
    (r'"hi\s+together"', r"hi\s+together"),
    (r'"\d+"', r"\d+"),
    (r'"a\.b"', r"a\.b"),
    (r'"\(x\)"', r"\(x\)"),
    (r'"\w\b\B\S\D\W"', r"\w\b\B\S\D\W"),
    (r'"\[a\]"', r"\[a\]"),
    (r'"\x41"', r"\x41"),
    (r"'\s'", r"\s"),
])
def test_unknown_escape_keeps_backslash(literal, expected):
    assert _string_value(literal) == expected


# ---------------------------------------------------------------------------
# Known escapes are unchanged
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal, expected", [
    (r'"a\"b"', 'a"b'),
    (r"'a\'b'", "a'b"),
    (r'"a\'b"', "a'b"),
    (r"'a\"b'", 'a"b'),
    (r'"a\\b"', "a\\b"),
    (r'"a\\\\b"', "a\\\\b"),
    (r'"a\nb"', "a\nb"),
    (r'"a\tb"', "a\tb"),
    (r'"a\rb"', "a\rb"),
    ('"plain"', "plain"),
])
def test_known_escapes_are_decoded(literal, expected):
    assert _string_value(literal) == expected


def test_escaped_backslash_before_s_is_literal_backslash_s():
    # "\\s" -> backslash + s: the documented way to spell a literal backslash.
    assert _string_value(r'"\\s"') == r"\s"


# ---------------------------------------------------------------------------
# Raw strings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal, expected", [
    (r'r"a\b\"c"', r"a\b\"c"),
    (r"r'x\y'", r"x\y"),
    (r'R"x\y"', r"x\y"),
    (r"R'\d+\.\d+'", r"\d+\.\d+"),
    (r'r"a\\b"', r"a\\b"),
    (r'r"a\nb"', r"a\nb"),
    ('r""', ""),
])
def test_raw_string_keeps_backslashes(literal, expected):
    assert _string_value(literal) == expected


def test_raw_string_position_is_the_prefix():
    tokens = tokenize(r'frame matches r"\d"')
    assert tokens[2].type == TokenType.STRING
    assert tokens[2].position == 14


@pytest.mark.parametrize("expr", ['r"abc', r'r"abc\"', "R'abc", 'r"abc\\'])
def test_unterminated_raw_string_raises_with_position(expr):
    text = f"frame matches {expr}"
    with pytest.raises(FilterSyntaxError) as info:
        tokenize(text)
    assert "Unterminated raw string" in str(info.value)
    assert info.value.position == 14


def test_unterminated_plain_string_message_unchanged():
    with pytest.raises(FilterSyntaxError) as info:
        tokenize('frame contains "abc')
    assert "Unterminated string starting with \"" in str(info.value)
    assert info.value.position == 15


@pytest.mark.parametrize("expr, fields", [
    ("rc4", ["rc4"]),
    ("rc4.key_len == 16", ["rc4.key_len"]),
    ("r", ["r"]),
    ("R", ["R"]),
    ("r == x", ["r", "x"]),
    ("rr", ["rr"]),
])
def test_bare_words_starting_with_r_stay_fields(expr, fields):
    tokens = tokenize(expr)
    assert [t.value for t in tokens if t.type == TokenType.FIELD] == fields
    assert TokenType.STRING not in {t.type for t in tokens}


def test_rc4_key_len_comparison_tokens():
    tokens = tokenize("rc4.key_len == 16")
    assert [(t.type, t.value) for t in tokens] == [
        (TokenType.FIELD, "rc4.key_len"), (TokenType.OP_EQ, "=="),
        (TokenType.NUMBER, "16"), (TokenType.EOF, ""),
    ]


# ---------------------------------------------------------------------------
# End-to-end through FilterEngine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr", [
    r'frame matches "hi\s+together"',
    r'frame matches r"hi\s+together"',
    r"frame matches 'HI\s+TOGETHER'",
    r'frame matches "\bhi\b"',
    r'frame matches "id=\d+"',
    r'frame matches "\(ok\)"',
])
def test_frame_matches_with_regex_escapes(expr):
    ctx = _FakeCtx(b"say hi together (ok) id=42")
    assert FilterEngine(expr).matches(object(), ctx)


def test_frame_matches_regex_escape_rejects_non_matching_content():
    ctx = _FakeCtx(b"hitogether")
    assert not FilterEngine(r'frame matches "hi\s+together"').matches(object(), ctx)


def test_compiled_regex_receives_preserved_backslashes():
    engine = FilterEngine(r'frame matches "hi\s+together"')
    assert engine.matches(object(), _FakeCtx(b"hi \t together"))
    assert not engine.matches(object(), _FakeCtx(b"his+together"))


def test_http_host_matches_escaped_dots():
    engine = FilterEngine(r'http.host matches "^api\.example\.com$"')
    assert engine.matches(http_flow(host="api.example.com", with_response=False))
    assert not engine.matches(http_flow(host="apixexample.com", with_response=False))


def test_contains_with_unknown_escape_is_literal_backslash():
    ctx = _FakeCtx(b"path c:\\temp and hi together")
    assert FilterEngine(r'frame contains ":\temp"').matches(object(), ctx) is False
    assert FilterEngine(r'frame contains "c:\\temp"').matches(object(), ctx)
    assert FilterEngine(r'frame contains r"c:\temp"').matches(object(), ctx)
    assert not FilterEngine(r'frame contains "hi\stogether"').matches(object(), ctx)
