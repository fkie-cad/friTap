"""Unit tests for the importable Wine GDB key-extraction launcher
(``agent_gdb/wine/wine_key_extract.py``). These cover only the gdb-free parts:
loader/script resolution, argument validation and the gdb invocation plumbing
(FRITAP_ARGS / FRITAP_PATTERNS). The in-gdb script is exercised separately."""

import json
import os
import types

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


class _LaunchProc:
    """A Wine launcher ``Popen`` that has already exited."""

    pid = 999999

    def poll(self):
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


def _capture_launch(monkeypatch, **launch_kwargs):
    """Run launch_and_attach with Popen and the /proc finder stubbed; returns the
    Popen call's (argv, kwargs). No process is found, so nothing is attached."""
    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"], captured["kwargs"] = argv, kwargs
        return _LaunchProc()

    monkeypatch.setattr(wke.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(wke, "_find_wine_app_pid", lambda *a, **k: None)
    rc = wke.launch_and_attach(wine_cmd="wine", program="app.exe",
                               startup_timeout=0, **launch_kwargs)
    assert rc == 1
    return captured["argv"], captured["kwargs"]


def test_launch_without_run_as_is_unchanged(monkeypatch):
    argv, kwargs = _capture_launch(monkeypatch)
    assert argv == ["wine", "app.exe"]
    assert kwargs == {"start_new_session": True}


def test_launch_with_run_as_drops_privileges(monkeypatch):
    monkeypatch.setenv("WINEPREFIX", "/home/alice/.wine")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(wke.os, "getgrouplist", lambda user, gid: [gid, 27])
    run_as = wke.WineRunAs(uid=1000, gid=1000, user="alice", home="/home/alice")
    _, kwargs = _capture_launch(monkeypatch, run_as=run_as)
    assert kwargs["user"] == 1000 and kwargs["group"] == 1000
    assert kwargs["extra_groups"] == [1000, 27]
    env = kwargs["env"]
    assert (env["HOME"], env["USER"], env["LOGNAME"]) == ("/home/alice", "alice", "alice")
    assert env["WINEPREFIX"] == "/home/alice/.wine" and env["DISPLAY"] == ":0"


# --- least-privilege gdb under sudo ---------------------------------------------

_ALICE = wke.WineRunAs(uid=1000, gid=1000, user="alice", home="/home/alice")


def _capture_gdb_popen(monkeypatch, **run_kwargs):
    """Run run_wine_key_extraction in attach mode with Popen stubbed; returns
    the gdb Popen kwargs."""
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured.update(kwargs)
        return _FakeProc()

    monkeypatch.setattr(wke.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(wke.os, "getgrouplist", lambda user, gid: [gid, 27])
    assert wke.run_wine_key_extraction(attach="42", **run_kwargs) == 0
    return captured


def test_run_without_run_as_keeps_gdb_kwargs(monkeypatch):
    monkeypatch.delenv("FRITAP_WINE_READY_FILE", raising=False)
    kwargs = _capture_gdb_popen(monkeypatch)
    assert not {"user", "group", "extra_groups"} & set(kwargs)
    assert kwargs["start_new_session"] is True
    assert "FRITAP_WINE_READY_FILE" not in kwargs["env"]


def test_run_with_run_as_drops_gdb_privileges(monkeypatch):
    kwargs = _capture_gdb_popen(monkeypatch, run_as=_ALICE, ready_file="/tmp/ready_dir/ready")
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (1000, 1000, [1000, 27])
    env = kwargs["env"]
    assert env["HOME"] == "/home/alice" and env["USER"] == "alice"
    assert json.loads(env["FRITAP_ARGS"])["attach"] == "42"
    assert env["FRITAP_WINE_READY_FILE"] == "/tmp/ready_dir/ready"
    assert len(kwargs["pass_fds"]) == 3
    assert "FRITAP_WINE_READY_FILE" not in os.environ


def _launch_with_found_pid(monkeypatch, **launch_kwargs):
    """launch_and_attach with a found (fake) pid; records the extractor call,
    the ready dir it saw and any chown of it."""
    record = {"chown": []}

    def fake_extract(**kwargs):
        record["extract"] = kwargs
        record["ready_dir"] = os.path.dirname(kwargs["ready_file"])
        record["dir_existed"] = os.path.isdir(record["ready_dir"])
        return 0

    monkeypatch.setattr(wke.subprocess, "Popen", lambda argv, **kw: _LaunchProc())
    monkeypatch.setattr(wke, "_find_wine_app_pid", lambda *a, **k: "4242")
    monkeypatch.setattr(wke, "run_wine_key_extraction", fake_extract)
    monkeypatch.setattr(wke.os, "chown", lambda p, u, g: record["chown"].append((p, u, g)))
    monkeypatch.setattr(wke.os, "kill", lambda *a: None)
    assert wke.launch_and_attach(wine_cmd="wine", program="app.exe", **launch_kwargs) == 0
    return record


def test_launch_with_gdb_run_as_hands_ready_dir_to_user(monkeypatch):
    record = _launch_with_found_pid(monkeypatch, gdb_run_as=_ALICE)
    assert record["extract"]["run_as"] is _ALICE
    assert record["chown"] == [(record["ready_dir"], 1000, 1000)]
    assert record["dir_existed"] and not os.path.exists(record["ready_dir"])
    assert "FRITAP_WINE_READY_FILE" not in os.environ


def test_launch_without_gdb_run_as_does_not_chown(monkeypatch):
    record = _launch_with_found_pid(monkeypatch)
    assert record["extract"]["run_as"] is None
    assert record["chown"] == []
    assert not os.path.exists(record["ready_dir"])


@pytest.mark.parametrize("content, expected", [(None, 0), ("1\n", 1), ("0\n", 0), ("junk", 1)])
def test_ptrace_scope(tmp_path, monkeypatch, content, expected):
    path = tmp_path / "ptrace_scope"
    if content is not None:
        path.write_text(content)
    monkeypatch.setattr(wke, "YAMA_PTRACE_SCOPE", str(path))
    assert wke.ptrace_scope() == expected


def _blocker_env(monkeypatch, *, scope=0, probe=True, status=None):
    """Stub the blocker's inputs; returns the list of probe/fchown calls."""
    calls = {"probe": [], "fchown": []}

    def fake_probe(run_as, *args):
        calls["probe"].append(args)
        return probe(args) if callable(probe) else probe

    monkeypatch.setattr(wke, "ptrace_scope", lambda: scope)
    monkeypatch.setattr(wke, "_can_access_as", fake_probe)
    monkeypatch.setattr(wke, "_proc_ids", lambda pid: status)
    monkeypatch.setattr(wke.os, "fchown", lambda fd, u, g: calls["fchown"].append((u, g)))
    return calls


def test_blocker_reports_restrictive_ptrace_scope(monkeypatch, tmp_path):
    calls = _blocker_env(monkeypatch, scope=1)
    keylog = tmp_path / "keys.log"
    reason = wke.unprivileged_gdb_blocker(_ALICE, str(keylog))
    assert "ptrace_scope=1" in reason
    assert calls["probe"] == [] and not keylog.exists()


def test_blocker_reports_target_id_mismatch(monkeypatch, tmp_path):
    calls = _blocker_env(monkeypatch, status=([1000, 0, 1000, 1000], [1000] * 4))
    keylog = tmp_path / "keys.log"
    reason = wke.unprivileged_gdb_blocker(_ALICE, str(keylog), target_pid=4242)
    assert "4242" in reason
    assert calls["probe"] == [] and not keylog.exists()


def test_blocker_reports_unreadable_script(monkeypatch, tmp_path):
    _blocker_env(monkeypatch, probe=False)
    keylog = tmp_path / "keys.log"
    reason = wke.unprivileged_gdb_blocker(_ALICE, str(keylog))
    assert wke.resolve_gdb_script_path() in reason
    assert not keylog.exists()


def test_blocker_creates_missing_keylog_for_user(monkeypatch, tmp_path):
    calls = _blocker_env(monkeypatch, status=([1000] * 4, [1000] * 4))
    keylog = tmp_path / "keys.log"
    assert wke.unprivileged_gdb_blocker(_ALICE, str(keylog), target_pid=4242) is None
    assert keylog.exists()
    assert calls["fchown"] == [(1000, 1000)]


def test_blocker_checks_new_keylog_is_reachable_by_user(monkeypatch, tmp_path):
    calls = _blocker_env(monkeypatch)
    keylog = tmp_path / "keys.log"
    assert wke.unprivileged_gdb_blocker(_ALICE, str(keylog)) is None
    assert keylog.exists()
    assert calls["probe"][-1] == ("-w", str(keylog))


def test_blocker_removes_new_keylog_unreachable_by_user(monkeypatch, tmp_path):
    calls = _blocker_env(monkeypatch, probe=lambda args: args[0] != "-w")
    keylog = tmp_path / "keys.log"
    reason = wke.unprivileged_gdb_blocker(_ALICE, str(keylog))
    assert reason == f"keylog {keylog} is not reachable by alice"
    assert calls["fchown"] == [(1000, 1000)]
    assert not keylog.exists()


def test_blocker_reports_unwritable_existing_keylog(monkeypatch, tmp_path):
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    calls = _blocker_env(monkeypatch, probe=lambda args: args[0] != "-w")
    reason = wke.unprivileged_gdb_blocker(_ALICE, str(keylog))
    assert str(keylog) in reason
    assert calls["fchown"] == []


def test_blocker_accepts_writable_existing_keylog(monkeypatch, tmp_path):
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    calls = _blocker_env(monkeypatch)
    assert wke.unprivileged_gdb_blocker(_ALICE, str(keylog)) is None
    assert ("-w", str(keylog)) in calls["probe"]
    assert calls["fchown"] == []


def test_proc_ids_parses_status(monkeypatch, tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tapp.exe\nUid:\t1000\t1000\t1000\t1000\nGid:\t20\t20\t20\t20\n")
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real_open(
        status if p == "/proc/7/status" else p, *a, **k))
    assert wke._proc_ids(7) == ([1000] * 4, [20] * 4)


def test_can_access_as_probes_as_user(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(cmd=cmd, **kwargs)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(wke.subprocess, "run", fake_run)
    monkeypatch.setattr(wke.os, "getgrouplist", lambda user, gid: [gid])
    assert wke._can_access_as(_ALICE, "-r", "/x") is True
    assert seen["cmd"] == ["test", "-r", "/x"] and seen["user"] == 1000


def test_can_access_as_treats_oserror_as_denied(monkeypatch):
    def boom(*a, **k):
        raise PermissionError("setgroups")

    monkeypatch.setattr(wke.subprocess, "run", boom)
    monkeypatch.setattr(wke.os, "getgrouplist", lambda user, gid: [gid])
    assert wke._can_access_as(_ALICE, "-r", "/x") is False


# --- /proc cmdline scan ------------------------------------------------------------


def _fake_proc_tree(monkeypatch, tmp_path, cmdlines):
    """Point the /proc glob/open at *tmp_path*, one ``<pid>/cmdline`` per entry
    (None = unreadable)."""
    for pid, raw in cmdlines.items():
        (tmp_path / pid).mkdir()
        if raw is not None:
            (tmp_path / pid / "cmdline").write_bytes(raw)
    monkeypatch.setattr(wke.glob, "glob", lambda pattern: sorted(
        f"/proc/{p}" for p in cmdlines))
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real_open(
        str(p).replace("/proc/", f"{tmp_path}/", 1) if str(p).startswith("/proc/") else p,
        *a, **k))


def test_iter_proc_cmdlines_joins_args_and_skips_excluded(monkeypatch, tmp_path):
    _fake_proc_tree(monkeypatch, tmp_path, {
        "10": b"wine\0app.exe\0", "11": b"sudo\0fritap\0", "12": None,
    })
    assert list(wke.iter_proc_cmdlines(exclude={"11"})) == [("10", "wine app.exe ")]


def test_find_wine_app_pid_matches_exe_case_insensitively(monkeypatch, tmp_path):
    _fake_proc_tree(monkeypatch, tmp_path, {"20": b"wine\0C:\\x\\APP.exe\0", "21": b"app.exe\0"})
    (tmp_path / "20" / "maps").write_text("7f00 r-xp C:/x/APP.exe\n")
    (tmp_path / "21" / "maps").write_text("")
    assert wke._find_wine_app_pid("app.exe", {"21"}, deadline=float("inf")) == "20"


# --- sudo / prefix policy ------------------------------------------------------------


def _fake_pwd(monkeypatch, entries):
    import pwd

    def getpwuid(uid):
        if uid not in entries:
            raise KeyError(uid)
        name, home = entries[uid]
        return types.SimpleNamespace(pw_name=name, pw_dir=home)

    monkeypatch.setattr(pwd, "getpwuid", getpwuid)


@pytest.mark.parametrize("euid, sudo_uid, sudo_gid", [
    (1000, "1000", "1000"),  # not root
    (0, None, None),         # real root shell
    (0, "0", "0"),           # sudo from root
    (0, "1000", None),       # incomplete sudo env
    (0, "abc", "1000"),      # garbled uid
    (0, "4242", "4242"),     # no passwd entry
])
def test_sudo_invoker_none_cases(monkeypatch, euid, sudo_uid, sudo_gid):
    _fake_pwd(monkeypatch, {1000: ("alice", "/home/alice")})
    monkeypatch.setattr(wke.os, "geteuid", lambda: euid)
    for name, value in (("SUDO_UID", sudo_uid), ("SUDO_GID", sudo_gid)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    assert wke.sudo_invoker() is None


def test_sudo_invoker_returns_invoking_user(monkeypatch):
    _fake_pwd(monkeypatch, {1000: ("alice", "/home/alice")})
    monkeypatch.setattr(wke.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1001")
    assert wke.sudo_invoker() == wke.WineRunAs(uid=1000, gid=1001, user="alice",
                                               home="/home/alice")


def test_user_name_falls_back_to_uid(monkeypatch):
    _fake_pwd(monkeypatch, {1000: ("alice", "/home/alice")})
    assert wke._user_name(1000) == "alice"
    assert wke._user_name(4242) == "4242"
