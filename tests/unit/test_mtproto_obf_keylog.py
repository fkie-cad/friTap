"""Tests for the MTPROTO_OBF_KEY keylog line format and its offline loader.

Hermetic — pure text format + file parsing, no crypto backend or device needed.
"""

from __future__ import annotations

import pytest

from friTap.protocols import mtproto_keylog_spec as spec

_KEY_OUT = "11" * 32  # 64 hex
_IV_OUT = "22" * 16  # 32 hex
_KEY_IN = "33" * 32
_IV_IN = "44" * 16


def test_format_parse_obf_roundtrip():
    line = spec.format_obf_line(
        key_out=_KEY_OUT, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN,
        num_out=3, num_in=7, endpoint="149.154.167.51:443",
    )
    assert line == (
        f"{spec.OBF_LABEL} {_KEY_OUT} {_IV_OUT} {_KEY_IN} {_IV_IN} 3 7 "
        "149.154.167.51:443"
    )
    parsed = spec.parse_obf_line(line)
    assert parsed is not None
    assert parsed.key_out == bytes.fromhex(_KEY_OUT)
    assert parsed.iv_out == bytes.fromhex(_IV_OUT)
    assert parsed.key_in == bytes.fromhex(_KEY_IN)
    assert parsed.iv_in == bytes.fromhex(_IV_IN)
    assert parsed.num_out == 3
    assert parsed.num_in == 7
    assert parsed.endpoint == "149.154.167.51:443"


def test_format_obf_rejects_bad_lengths():
    assert spec.format_obf_line(
        key_out="ab", iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN
    ) is None
    assert spec.format_obf_line(
        key_out=_KEY_OUT, iv_out="ab", key_in=_KEY_IN, iv_in=_IV_IN
    ) is None


def test_format_obf_rejects_non_hex():
    assert spec.format_obf_line(
        key_out="zz" * 32, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN
    ) is None


def test_format_obf_clamps_byte_phase():
    # num is a byte-phase into a 16-byte block; out-of-range coerces into 0..15
    # rather than dropping an otherwise-usable key (mirrors dc_id leniency).
    line = spec.format_obf_line(
        key_out=_KEY_OUT, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN,
        num_out=99, num_in=-4,
    )
    parsed = spec.parse_obf_line(line)
    assert parsed is not None
    assert parsed.num_out == spec.OBF_NUM_MAX
    assert parsed.num_in == 0


def test_parse_obf_defaults_missing_endpoint():
    # A 7-token line (no endpoint) defaults endpoint to "-", like parse_e2e_line
    # defaults chat_id.
    line = f"{spec.OBF_LABEL} {_KEY_OUT} {_IV_OUT} {_KEY_IN} {_IV_IN} 0 0"
    parsed = spec.parse_obf_line(line)
    assert parsed is not None
    assert parsed.endpoint == spec.OBF_ENDPOINT_UNKNOWN


def test_format_obf_blank_endpoint_becomes_dash():
    line = spec.format_obf_line(
        key_out=_KEY_OUT, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN,
        endpoint="   ",
    )
    assert line.split()[-1] == spec.OBF_ENDPOINT_UNKNOWN


@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "# a comment",
    f"{spec.OBF_LABEL} tooShort",
    f"{spec.OBF_LABEL} {_KEY_OUT} {_IV_OUT} {_KEY_IN} {_IV_IN} x 0 -",  # bad num
])
def test_parse_obf_rejects_junk(bad):
    assert spec.parse_obf_line(bad) is None


def test_label_coexistence_across_parsers():
    # Each parser ignores the other two labels: the three coexist in one file.
    aid = "a1b2c3d4e5f60718"
    ak = "ab" * 256
    auth_line = spec.format_line(dc_id=2, auth_key_id=aid, auth_key=ak)
    e2e_line = spec.format_e2e_line(key_fingerprint=aid, shared_key=ak, chat_id=9)
    obf_line = spec.format_obf_line(
        key_out=_KEY_OUT, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN
    )
    # parse_obf_line only accepts the obf line.
    assert spec.parse_obf_line(auth_line) is None
    assert spec.parse_obf_line(e2e_line) is None
    assert spec.parse_obf_line(obf_line) is not None
    # The cloud/E2E parsers ignore the obf line.
    assert spec.parse_line(obf_line) is None
    assert spec.parse_e2e_line(obf_line) is None


def test_load_mtproto_obf_keylog_returns_list(tmp_path):
    from friTap.offline.mtproto.keylog import (
        load_mtproto_keylog,
        load_mtproto_obf_keylog,
    )

    aid = "a1b2c3d4e5f60718"
    ak = "ab" * 256
    obf1 = spec.format_obf_line(
        key_out=_KEY_OUT, iv_out=_IV_OUT, key_in=_KEY_IN, iv_in=_IV_IN, num_out=1
    )
    obf2 = spec.format_obf_line(
        key_out=_KEY_IN, iv_out=_IV_IN, key_in=_KEY_OUT, iv_in=_IV_OUT, num_out=2
    )
    path = tmp_path / "mixed.mtproto.keylog"
    path.write_text(
        spec.HEADER_COMMENT + "\n"
        + spec.format_line(dc_id=1, auth_key_id=aid, auth_key=ak) + "\n"
        + obf1 + "\n"
        + "# a stray comment\n"
        + obf2 + "\n"
    )
    obf_keys = load_mtproto_obf_keylog(str(path))
    assert isinstance(obf_keys, list)
    assert [k.num_out for k in obf_keys] == [1, 2]  # order preserved, LIST not dict
    # The auth-key loader still reads its own label from the same file, unchanged.
    assert bytes.fromhex(aid) in load_mtproto_keylog(str(path))
