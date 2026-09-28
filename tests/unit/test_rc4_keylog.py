#!/usr/bin/env python3

"""Tests for the RC4 keylog format (friTap.protocols.rc4_keylog_spec).

Covers ``format_line`` / ``parse_line`` round-trips, the exact line layout, and
the ``Rc4KeylogFormatter`` rendering that a downstream offline RC4 decrypt
workstream consumes.
"""

from types import SimpleNamespace

import pytest

from friTap.protocols import rc4_keylog_spec as spec
from friTap.protocols.rc4_handler import Rc4KeylogFormatter

# The fixture key from the RC4 research (research/memory_scan_lsass).
FIXTURE_KEY = b"fritap-rc4-demo-key"
FIXTURE_KEY_HEX = FIXTURE_KEY.hex()


# ---------------------------------------------------------------------------
# format_line
# ---------------------------------------------------------------------------

def test_format_line_exact_layout():
    line = spec.format_line(
        key=FIXTURE_KEY_HEX, key_len=len(FIXTURE_KEY),
        source="RC4_set_key", direction="unknown", assoc="4711",
    )
    assert line == f"RC4_KEY {FIXTURE_KEY_HEX} 19 RC4_set_key unknown 4711"


def test_format_line_defaults():
    line = spec.format_line(key="4b6579")  # "Key"
    assert line == "RC4_KEY 4b6579 3 unknown unknown -"


def test_format_line_rejects_odd_hex():
    assert spec.format_line(key="abc") is None


def test_format_line_rejects_non_hex():
    assert spec.format_line(key="zzzz") is None


def test_format_line_rejects_key_len_mismatch():
    assert spec.format_line(key=FIXTURE_KEY_HEX, key_len=99) is None


def test_format_line_normalizes_bad_direction_and_spaces():
    line = spec.format_line(
        key="4b6579", source="my hook", direction="sideways", assoc="a b",
    )
    # bad direction -> "unknown"; spaces in tokens -> underscores.
    assert line == "RC4_KEY 4b6579 3 my_hook unknown a_b"


@pytest.mark.parametrize("bad_key", ["0x1234", "1_23_4", "12g4"])
def test_parse_line_rejects_malformed_hex_without_crashing(bad_key):
    # int(_,16) would accept "0x…"/"1_2…"; parse_line must reject via bytes.fromhex
    # semantics rather than raising and aborting the whole keylog conversion.
    klen = len(bad_key) // 2
    assert spec.parse_line(f"RC4_KEY {bad_key} {klen} src out -") is None


# ---------------------------------------------------------------------------
# parse_line + round-trip
# ---------------------------------------------------------------------------

def test_parse_line_roundtrip():
    line = spec.format_line(
        key=FIXTURE_KEY_HEX, key_len=len(FIXTURE_KEY),
        source="BCryptGenerateSymmetricKey", direction="out", assoc="1234",
    )
    parsed = spec.parse_line(line)
    assert parsed is not None
    assert parsed.key == FIXTURE_KEY
    assert parsed.key_len == len(FIXTURE_KEY)
    assert parsed.source == "BCryptGenerateSymmetricKey"
    assert parsed.direction == "out"
    assert parsed.assoc == "1234"


def test_parse_line_skips_comments_and_blanks():
    assert spec.parse_line("# a comment") is None
    assert spec.parse_line("   ") is None
    assert spec.parse_line("") is None


def test_parse_line_rejects_wrong_label():
    assert spec.parse_line("NOT_RC4 4b6579 3 s unknown -") is None


def test_parse_line_rejects_wrong_field_count():
    assert spec.parse_line("RC4_KEY 4b6579 3 s unknown") is None  # 5 tokens


def test_parse_line_rejects_len_mismatch():
    assert spec.parse_line("RC4_KEY 4b6579 9 s unknown -") is None


def test_header_comment_is_parse_skippable():
    for line in spec.HEADER_COMMENT.splitlines():
        assert spec.parse_line(line) is None


# ---------------------------------------------------------------------------
# Rc4KeylogFormatter — renders the spec line from an agent payload
# ---------------------------------------------------------------------------

def test_formatter_output_matches_spec():
    fmt = Rc4KeylogFormatter()
    event = SimpleNamespace(payload={
        "key": FIXTURE_KEY_HEX,
        "key_len": len(FIXTURE_KEY),
        "source": "RC4_set_key",
        "direction": "unknown",
        "assoc": "4711",
    })
    expected = spec.format_line(
        key=FIXTURE_KEY_HEX, key_len=len(FIXTURE_KEY),
        source="RC4_set_key", direction="unknown", assoc="4711",
    )
    assert fmt.format(event) == [expected]


def test_formatter_drops_malformed_key():
    fmt = Rc4KeylogFormatter()
    event = SimpleNamespace(payload={"key": "not-hex"})
    assert fmt.format(event) == []


def test_formatter_dedup_key_distinguishes_direction():
    fmt = Rc4KeylogFormatter()
    e_out = SimpleNamespace(payload={"key": FIXTURE_KEY_HEX, "direction": "out", "assoc": "1"})
    e_in = SimpleNamespace(payload={"key": FIXTURE_KEY_HEX, "direction": "in", "assoc": "1"})
    assert fmt.dedup_key(e_out) != fmt.dedup_key(e_in)
