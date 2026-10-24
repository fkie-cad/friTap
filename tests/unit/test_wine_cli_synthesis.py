"""Tests for the CLI-layer Wine synthesis (`_maybe_prepend_wine`): turning a bare
Windows target on Linux into a `wine <exe>` spawn command, gated by --wine."""

import logging
import types

import pytest

from friTap.friTap import _maybe_prepend_wine

LOG = logging.getLogger("test.wine.synth")


def _parsed(exec_argv, *, spawn=True, wine="auto"):
    return types.SimpleNamespace(
        exec=" ".join(exec_argv), exec_argv=list(exec_argv), spawn=spawn, wine=wine,
    )


def _force_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")


def test_pe_file_gets_wine_prepended(tmp_path, monkeypatch):
    _force_linux(monkeypatch)
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 64)  # PE magic
    p = _parsed([str(exe)])
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv[0].endswith("wine") or p.exec_argv[0] == "wine"
    assert p.exec_argv[1] == str(exe)


def test_elf_named_exe_not_treated_as_wine(tmp_path, monkeypatch):
    _force_linux(monkeypatch)
    f = tmp_path / "tool.exe"
    f.write_bytes(b"\x7fELF" + b"\x00" * 64)  # real ELF despite .exe name
    p = _parsed([str(f)])
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv == [str(f)]  # unchanged


def test_nonexistent_dotexe_falls_back_to_name(monkeypatch):
    _force_linux(monkeypatch)
    p = _parsed(["C:/Games/game.exe"])
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv[0].split("/")[-1].startswith("wine")
    assert p.exec_argv[1] == "C:/Games/game.exe"


def test_already_wine_not_doubled(monkeypatch):
    _force_linux(monkeypatch)
    p = _parsed(["wine", "/p/app.exe"])
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv == ["wine", "/p/app.exe"]


def test_wine_off_disables_synthesis(tmp_path, monkeypatch):
    _force_linux(monkeypatch)
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 64)
    p = _parsed([str(exe)], wine="off")
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv == [str(exe)]  # off -> untouched


def test_wine_on_forces_even_without_exe(tmp_path, monkeypatch):
    _force_linux(monkeypatch)
    f = tmp_path / "game"  # no .exe, not PE
    f.write_bytes(b"random")
    p = _parsed([str(f)], wine="on")
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv[1] == str(f)
    assert p.exec_argv[0].split("/")[-1].startswith("wine")


def test_attach_mode_not_synthesized(tmp_path, monkeypatch):
    _force_linux(monkeypatch)
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    p = _parsed([str(exe)], spawn=False)
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv == [str(exe)]  # attach -> untouched


def test_non_linux_not_synthesized(tmp_path, monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    p = _parsed([str(exe)])
    _maybe_prepend_wine(p, LOG)
    assert p.exec_argv == [str(exe)]