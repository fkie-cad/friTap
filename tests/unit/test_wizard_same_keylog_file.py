"""Re-adding the same keylog by a different path must not trigger a merge."""

import os

from friTap.tui.wizard import _same_keylog_file


def test_identical_strings_are_same():
    assert _same_keylog_file("ckeys.log", "ckeys.log")


def test_relative_and_absolute_path_are_same(tmp_path, monkeypatch):
    target = tmp_path / "ckeys.log"
    target.write_text("CLIENT_RANDOM x y\n")
    monkeypatch.chdir(tmp_path)
    assert _same_keylog_file("ckeys.log", str(target))


def test_symlink_resolves_to_same_file(tmp_path):
    target = tmp_path / "a.log"
    target.write_text("x\n")
    link = tmp_path / "b.log"
    os.symlink(target, link)
    assert _same_keylog_file(str(target), str(link))


def test_different_files_are_not_same(tmp_path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("x\n")
    b.write_text("x\n")
    assert not _same_keylog_file(str(a), str(b))
