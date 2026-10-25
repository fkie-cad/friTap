"""Tests for the CLI-layer Wine synthesis (`_maybe_prepend_wine`): turning a bare
Windows target on Linux into a `wine <exe>` spawn command, gated by --wine."""

import argparse
import logging
import types

from friTap.friTap import _WINE_MODES, _maybe_prepend_wine, _normalize_bare_wine_flag

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

# --- bare `--wine` normalization ------------------------------------------------

def test_bare_wine_before_target_becomes_auto():
    assert _normalize_bare_wine_flag(["-s", "--wine", "app.exe"]) == \
        ["-s", "--wine", "auto", "app.exe"]


def test_bare_wine_before_flag_left_for_argparse_const():
    argv = ["--wine", "-s", "app.exe"]
    assert _normalize_bare_wine_flag(argv) == argv


def test_bare_wine_at_end_left_for_argparse_const():
    argv = ["-s", "app.exe", "--wine"]
    assert _normalize_bare_wine_flag(argv) == argv


def test_explicit_wine_modes_untouched():
    for mode in _WINE_MODES:
        argv = ["--wine", mode, "app.exe"]
        assert _normalize_bare_wine_flag(argv) == argv


def test_wine_equals_form_untouched():
    argv = ["--wine=off", "app.exe"]
    assert _normalize_bare_wine_flag(argv) == argv


def test_wine_after_double_dash_belongs_to_target():
    argv = ["-s", "--", "tool", "--wine", "x"]
    assert _normalize_bare_wine_flag(argv) == argv


def _wine_parser():
    # Mirrors the --wine/target definitions in friTap.friTap.cli().
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--spawn", action="store_true")
    parser.add_argument("-k", "--keylog")
    parser.add_argument("--wine", choices=_WINE_MODES, nargs="?", const="auto", default="auto")
    parser.add_argument("exec", nargs="+")
    return parser


def test_parser_bare_wine_with_target_and_dash_args():
    argv = ["-s", "-k", "k.log", "--wine", "--", "curl.exe", "-sk", "https://x"]
    parsed = _wine_parser().parse_args(_normalize_bare_wine_flag(argv))
    assert parsed.wine == "auto"
    assert parsed.exec == ["curl.exe", "-sk", "https://x"]


def test_parser_bare_wine_directly_before_target():
    parsed = _wine_parser().parse_args(_normalize_bare_wine_flag(["-s", "--wine", "app.exe"]))
    assert parsed.wine == "auto"
    assert parsed.exec == ["app.exe"]
