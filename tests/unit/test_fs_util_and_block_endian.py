"""Shared helpers: remove_quietly, is_non_empty_file and build_block's endian."""

import struct

from friTap._fs_util import is_non_empty_file, remove_quietly
from friTap.output.pcapng_blocks import BT_EPB, build_block


def test_remove_quietly_deletes_and_ignores_missing(tmp_path):
    target = tmp_path / "x"
    target.write_text("data")
    remove_quietly(str(target))
    assert not target.exists()
    remove_quietly(str(target))  # no error the second time


def test_is_non_empty_file(tmp_path):
    full, empty = tmp_path / "full", tmp_path / "empty"
    full.write_text("data")
    empty.write_text("")
    assert is_non_empty_file(str(full))
    assert not is_non_empty_file(str(empty))
    assert not is_non_empty_file(str(tmp_path))  # a directory
    assert not is_non_empty_file(str(tmp_path / "missing"))
    assert not is_non_empty_file(None) and not is_non_empty_file("")


def test_build_block_defaults_to_little_endian():
    block = build_block(BT_EPB, b"abc")
    assert block == struct.pack("<II", BT_EPB, 16) + b"abc\x00" + struct.pack("<I", 16)


def test_build_block_big_endian():
    block = build_block(BT_EPB, b"abcd", ">")
    assert block == struct.pack(">II", BT_EPB, 16) + b"abcd" + struct.pack(">I", 16)
