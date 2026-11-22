"""Tests for friTap.cache_files (shared cache dir + atomic write)."""

import os
import stat
import sys

import pytest

from friTap import cache_files


def test_cache_dir_uses_platformdirs():
    platformdirs = pytest.importorskip("platformdirs")
    assert cache_files.fritap_cache_dir() == platformdirs.user_cache_dir("friTap")


def test_cache_dir_falls_back_without_platformdirs(monkeypatch):
    monkeypatch.setitem(sys.modules, "platformdirs", None)
    expected = os.path.join(os.path.expanduser("~"), ".cache", "friTap")
    assert cache_files.fritap_cache_dir() == expected


@pytest.mark.parametrize("fsync", [True, False])
def test_write_atomic_creates_dirs_and_writes(tmp_path, fsync):
    target = tmp_path / "a" / "b" / "cache.json"
    cache_files.write_atomic(target, b"payload", fsync=fsync)
    assert target.read_bytes() == b"payload"
    assert os.listdir(target.parent) == ["cache.json"]


def test_write_atomic_replaces_existing(tmp_path):
    target = tmp_path / "cache.json"
    target.write_bytes(b"old")
    cache_files.write_atomic(str(target), b"new")
    assert target.read_bytes() == b"new"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_write_atomic_file_is_private(tmp_path):
    target = tmp_path / "cache.json"
    cache_files.write_atomic(target, b"x")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_write_atomic_failure_keeps_old_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "cache.json"
    target.write_bytes(b"old")

    def failing_replace(_src, _dst):
        raise OSError("replace failed")

    monkeypatch.setattr(cache_files.os, "replace", failing_replace)
    with pytest.raises(OSError):
        cache_files.write_atomic(target, b"new")
    assert target.read_bytes() == b"old"
    assert os.listdir(tmp_path) == ["cache.json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_write_atomic_applies_mode(tmp_path):
    target = tmp_path / "cache.json"
    cache_files.write_atomic(target, b"x", **cache_files.CACHE_WRITE_OPTIONS)
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_cache_file_lock_is_exclusive(tmp_path):
    pytest.importorskip("fcntl")
    target = tmp_path / "cache.json"
    with cache_files.cache_file_lock(target) as held:
        assert held
        with cache_files.cache_file_lock(target, timeout=0.1) as second:
            assert not second  # flock is per open file description
    with cache_files.cache_file_lock(target) as again:
        assert again


def test_cache_file_lock_degrades_without_fcntl(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "fcntl", None)
    with cache_files.cache_file_lock(tmp_path / "cache.json") as held:
        assert held is False


def test_cache_file_lock_unwritable_dir_runs_unlocked(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with cache_files.cache_file_lock(blocker / "cache.json") as held:
        assert held is False


def _fake_sudo(monkeypatch, home, chowns):
    pwd = pytest.importorskip("pwd")
    monkeypatch.setattr(cache_files.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("P", (), {"pw_dir": str(home)})())
    monkeypatch.setattr(cache_files.os, "fchown", lambda fd, u, g: chowns.append(("file", u, g)))
    monkeypatch.setattr(cache_files.os, "lchown", lambda p, u, g: chowns.append((p, u, g)))


def test_sudo_write_inside_home_hands_file_and_new_dirs_back(tmp_path, monkeypatch):
    chowns = []
    home = tmp_path / "home"
    home.mkdir()
    _fake_sudo(monkeypatch, home, chowns)
    target = home / ".cache" / "friTap" / "c.json"
    cache_files.write_atomic(target, b"x", **cache_files.CACHE_WRITE_OPTIONS)
    dirs = [c[0] for c in chowns if c[0] != "file"]
    assert [os.path.relpath(d, home) for d in dirs] == [".cache", os.path.join(".cache", "friTap")]
    assert ("file", 501, 20) in chowns


def test_sudo_write_outside_home_or_without_opt_in_does_not_chown(tmp_path, monkeypatch):
    chowns = []
    home = tmp_path / "home"
    home.mkdir()
    _fake_sudo(monkeypatch, home, chowns)
    cache_files.write_atomic(tmp_path / "elsewhere" / "c.json", b"x", **cache_files.CACHE_WRITE_OPTIONS)
    cache_files.write_atomic(home / "export" / "out.har", b"x")  # export path: no opt-in
    assert chowns == []
