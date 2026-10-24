"""Unit tests for the importable Wine GDB key-extraction launcher
(``agent_gdb/wine/wine_key_extract.py``). These cover only the gdb-free parts:
loader/script resolution, argument validation and the gdb invocation plumbing
(FRITAP_ARGS / FRITAP_PATTERNS). The in-gdb script is exercised separately."""

import json
import os

import pytest

from agent_gdb.wine import wine_key_extract as wke


def test_resolve_gdb_script_path_points_at_real_file():
    path = wke.resolve_gdb_script_path()
    assert path.endswith(os.path.join("gdb_script", "gdb_wine_extract.py"))
    assert os.path.isfile(path)


def test_is_elf(tmp_path):
    elf = tmp_path / "fake.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
    not_elf = tmp_path / "wrapper.sh"
    not_elf.write_text("#!/bin/sh\nexec wine64 \"$@\"\n")
    assert wke._is_elf(str(elf)) is True
    assert wke._is_elf(str(not_elf)) is False
    assert wke._is_elf(str(tmp_path / "missing")) is False


def test_resolve_wine_loader_returns_explicit_elf(tmp_path):
    elf = tmp_path / "wine64"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
    assert wke.resolve_wine_loader(str(elf)) == str(elf)


def test_resolve_wine_loader_mines_wrapper_script(tmp_path, monkeypatch):
    # A Debian/Ubuntu-style shell wrapper that names the real loaders.
    loader64 = tmp_path / "wine64"
    loader64.write_bytes(b"\x7fELF" + b"\x00" * 16)
    wrapper = tmp_path / "wine"
    wrapper.write_text(
        "#!/bin/sh -e\n"
        f"wine32=/nonexistent/wine\n"
        f"wine64={loader64}\n"
        'exec "$wine64" "$@"\n'
    )
    # which() returns the wrapper; realpath keeps it; it is not ELF, so the
    # resolver must fall through to the mined wine64= path.
    monkeypatch.setattr(wke.shutil, "which", lambda _c: str(wrapper))
    assert wke.resolve_wine_loader(str(wrapper)) == str(loader64)


def test_run_requires_exactly_one_of_attach_or_spawn():
    with pytest.raises(ValueError):
        wke.run_wine_key_extraction()
    with pytest.raises(ValueError):
        wke.run_wine_key_extraction(attach="1", spawn="a.exe")


class _FakeProc:
    def __init__(self):
        self.returncode = 0

    def wait(self):
        return 0


def test_run_builds_fritap_args_and_patterns(tmp_path, monkeypatch):
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return _FakeProc()

    monkeypatch.setattr(wke.subprocess, "Popen", fake_popen)
    monkeypatch.delenv("WINELOADER", raising=False)
    # Keep resolve_wine_loader deterministic (no real wine needed).
    monkeypatch.setattr(wke, "resolve_wine_loader", lambda b, **k: "/usr/lib/wine/wine64")

    patterns = tmp_path / "patterns.json"
    patterns.write_text(json.dumps({"deadbeef": {"name": "x", "handler": "FindHookablesBP", "offset": 0}}))

    rc = wke.run_wine_key_extraction(
        spawn="app.exe",
        keylog=str(tmp_path / "keys.log"),
        patterns=str(patterns),
        program_args=["--foo", "bar"],
        wine_bin="wine",
    )
    assert rc == 0
    assert captured["cmd"][0] == "gdb"
    assert captured["cmd"][-1].endswith("gdb_wine_extract.py")

    args = json.loads(captured["env"]["FRITAP_ARGS"])
    assert args["spawn"] == "app.exe"
    assert args["program_args"] == ["--foo", "bar"]
    assert args["wine-bin"] == "/usr/lib/wine/wine64"
    assert args["attach"] is None
    # --patterns FILE must be wired through to the env var the gdb script reads.
    assert json.loads(captured["env"]["FRITAP_PATTERNS"]) == {
        "deadbeef": {"name": "x", "handler": "FindHookablesBP", "offset": 0}
    }
    # Spawn mode also exports WINELOADER for the wow64 loader to re-exec.
    assert captured["env"]["WINELOADER"] == "/usr/lib/wine/wine64"
