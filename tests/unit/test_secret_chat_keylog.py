"""Tests for the secret-chat (E2E) keylog format, parser, and offline reader.

All hermetic — no device, no crypto backend needed (these test the text format
and file reading, not decryption).
"""

from __future__ import annotations

from friTap.offline.mtproto.e2e.keylog import load_secret_chat_keylog
from friTap.protocols import mtproto_keylog_spec as spec

_FP = "a1b2c3d4e5f60718"
_KEY = "ab" * 256  # 512 hex chars


# --------------------------------------------------------------------------- #
# spec: format_e2e_line / parse_e2e_line round-trip
# --------------------------------------------------------------------------- #


def test_format_parse_e2e_roundtrip():
    line = spec.format_e2e_line(key_fingerprint=_FP, shared_key=_KEY, chat_id=42)
    assert line == f"{spec.E2E_LABEL} {_FP} {_KEY} 42"
    parsed = spec.parse_e2e_line(line)
    assert parsed is not None
    assert parsed.key_fingerprint == bytes.fromhex(_FP)
    assert parsed.shared_key == bytes.fromhex(_KEY)
    assert parsed.chat_id == 42


def test_format_e2e_line_rejects_bad_lengths():
    assert spec.format_e2e_line(key_fingerprint="ab", shared_key=_KEY) is None
    assert spec.format_e2e_line(key_fingerprint=_FP, shared_key="cd") is None
    assert spec.format_e2e_line(key_fingerprint=_FP, shared_key="zz" * 256) is None


def test_format_e2e_line_defaults_chat_id():
    line = spec.format_e2e_line(key_fingerprint=_FP, shared_key=_KEY, chat_id="bogus")
    assert line == f"{spec.E2E_LABEL} {_FP} {_KEY} 0"


def test_parse_e2e_line_tolerates_missing_chat_id():
    parsed = spec.parse_e2e_line(f"{spec.E2E_LABEL} {_FP} {_KEY}")
    assert parsed is not None
    assert parsed.chat_id == 0


def test_parse_e2e_line_skips_noise():
    assert spec.parse_e2e_line("") is None
    assert spec.parse_e2e_line("   ") is None
    assert spec.parse_e2e_line("# a comment") is None
    assert spec.parse_e2e_line("CLIENT_RANDOM abc def") is None  # foreign label
    # cloud-chat line is ignored by the E2E parser
    assert spec.parse_e2e_line(f"{spec.LABEL} 2 {_FP} {_KEY} temp") is None
    # malformed hex length
    assert spec.parse_e2e_line(f"{spec.E2E_LABEL} ab {_KEY} 1") is None


# --------------------------------------------------------------------------- #
# cross-parser isolation: parse_line ignores E2E lines
# --------------------------------------------------------------------------- #


def test_parse_line_ignores_e2e_lines():
    assert spec.parse_line(f"{spec.E2E_LABEL} {_FP} {_KEY} 7") is None


# --------------------------------------------------------------------------- #
# offline reader
# --------------------------------------------------------------------------- #


def test_load_secret_chat_keylog(tmp_path):
    path = tmp_path / "keys.log"
    fp2 = "0011223344556677"
    path.write_text(
        "\n".join(
            [
                spec.HEADER_COMMENT,
                "",
                "# a comment",
                f"{spec.E2E_LABEL} {_FP} {_KEY} 1",
                f"{spec.LABEL} 2 {_FP} {_KEY} temp",  # cloud-chat: skipped
                f"{spec.E2E_LABEL} {fp2} {_KEY}",  # no chat_id -> 0
                "garbage line here",
            ]
        ),
        encoding="utf-8",
    )
    keymap = load_secret_chat_keylog(str(path))
    assert set(keymap) == {bytes.fromhex(_FP), bytes.fromhex(fp2)}
    assert keymap[bytes.fromhex(_FP)].chat_id == 1
    assert keymap[bytes.fromhex(fp2)].chat_id == 0
    assert keymap[bytes.fromhex(_FP)].shared_key == bytes.fromhex(_KEY)


def test_load_secret_chat_keylog_last_wins(tmp_path):
    path = tmp_path / "dup.log"
    other_key = "cd" * 256
    path.write_text(
        "\n".join(
            [
                f"{spec.E2E_LABEL} {_FP} {_KEY} 1",
                f"{spec.E2E_LABEL} {_FP} {other_key} 2",
            ]
        ),
        encoding="utf-8",
    )
    keymap = load_secret_chat_keylog(str(path))
    assert keymap[bytes.fromhex(_FP)].shared_key == bytes.fromhex(other_key)
    assert keymap[bytes.fromhex(_FP)].chat_id == 2
