"""Tests for friTap's automatic Wine -> GDB key-extraction routing in
``SSL_Logger`` (detection, spawn/attach argument mapping, and the
plaintext-unsupported notice)."""

import logging
import os
import threading
import types

from friTap.legacy.ssl_logger_core import SSL_Logger


def _make_logger(*, spawn=True, target="wine app.exe", target_argv=None,
                 keylog=None, pcap=None, live=False, socket_trace=None,
                 payload_modification=False, device_id=None, mobile=False,
                 host=None, pid=None, wine_mode="auto", backend="frida",
                 backend_explicit=False, full_capture=False):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.wine.routing")
    obj.logger.setLevel(logging.DEBUG)
    obj.pid = pid
    obj._done_event = threading.Event()
    obj._config = types.SimpleNamespace(
        target=target,
        target_argv=target_argv,
        backend=backend,
        backend_explicit=backend_explicit,
        debug_output=False,
        device=types.SimpleNamespace(
            spawn=spawn, device_id=device_id, mobile=mobile, host=host,
        ),
        output=types.SimpleNamespace(
            keylog=keylog, pcap=pcap, live=live, socket_trace=socket_trace,
            verbose=False, full_capture=full_capture, json_output=None,
        ),
        hooking=types.SimpleNamespace(
            payload_modification=payload_modification, wine_mode=wine_mode,
        ),
    )
    # No frida session on the Wine path; _end_session's helpers see these.
    obj.process = obj.device = None
    obj.events = []
    obj._event_bus = types.SimpleNamespace(emit=obj.events.append)
    # Spies for the session finalizers: the real cleanup() ends in os._exit.
    obj.finalize_calls = []
    obj.pcap_cleanup = lambda *a: obj.finalize_calls.append(("pcap_cleanup", a))
    obj.cleanup = lambda *a: obj.finalize_calls.append(("cleanup", a))
    return obj


# --- detection ------------------------------------------------------------

def test_detects_wine_spawn_on_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"])
    assert obj._should_use_wine_gdb() is True


def test_non_wine_target_not_routed(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["/usr/bin/notepad"], target="/usr/bin/notepad")
    assert obj._should_use_wine_gdb() is False


def test_not_routed_off_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"])
    assert obj._should_use_wine_gdb() is False


def test_not_routed_for_remote_device(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], device_id="deadbeef")
    assert obj._should_use_wine_gdb() is False


def test_attach_pid_detected_via_proc(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=False, target="4321", target_argv=None)
    monkeypatch.setattr(obj, "_pid_is_wine", lambda pid: int(pid) == 4321)
    assert obj._should_use_wine_gdb() is True


# --- --wine precedence ----------------------------------------------------

def test_wine_off_disables_route(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], wine_mode="off")
    assert obj._should_use_wine_gdb() is False


def test_wine_on_forces_route_even_for_nonwine(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["/usr/bin/foo"], target="/usr/bin/foo",
                       wine_mode="on")
    assert obj._should_use_wine_gdb() is True


def test_explicit_backend_frida_suppresses_auto_route(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       backend="frida", backend_explicit=True)
    assert obj._should_use_wine_gdb() is False


def test_wine_on_overrides_explicit_backend_frida(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       backend="frida", backend_explicit=True, wine_mode="on")
    assert obj._should_use_wine_gdb() is True


# --- argument mapping / run ------------------------------------------------

def _patch_runner(monkeypatch):
    """Patch both extraction entry points; spawn uses launch_and_attach, attach
    uses run_wine_key_extraction. Returns (spawn_calls, attach_calls)."""
    spawn_calls, attach_calls = {}, {}

    import agent_gdb.wine.wine_key_extract as wke
    monkeypatch.setattr(wke, "launch_and_attach", lambda **kw: spawn_calls.update(kw) or 0)
    monkeypatch.setattr(wke, "run_wine_key_extraction", lambda **kw: attach_calls.update(kw) or 0)
    return spawn_calls, attach_calls


def test_run_maps_spawn_arguments(monkeypatch):
    spawn_calls, _ = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "/p/app.exe", "--foo"],
                       keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    # Spawn launches Wine normally and attaches (robust on wow64).
    assert spawn_calls["wine_cmd"] == "wine"
    assert spawn_calls["program"] == "/p/app.exe"
    assert spawn_calls["program_args"] == ["--foo"]
    assert spawn_calls["keylog"] == "k.log"
    assert obj._done_event.is_set()


def test_run_maps_attach_pid(monkeypatch):
    _, attach_calls = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=False, target="4321", keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert attach_calls["attach"] == "4321"


def test_plaintext_request_warns(monkeypatch, caplog):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       keylog="k.log", pcap="out.pcap")
    with caplog.at_level(logging.WARNING):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert "not currently supported for Wine" in caplog.text


def test_missing_keylog_defaults_with_warning(monkeypatch, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog=None)
    with caplog.at_level(logging.WARNING):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["keylog"].endswith("wine_sslkeys.log")
    assert "No keylog file given" in caplog.text


def test_plaintext_warning_suggests_full_capture(monkeypatch, caplog):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       keylog="k.log", pcap="out.pcap")
    with caplog.at_level(logging.WARNING):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert "-p <file> -f" in caplog.text


def test_full_capture_does_not_warn(monkeypatch, caplog):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       keylog="k.log", pcap="out.pcapng", full_capture=True)
    with caplog.at_level(logging.INFO):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert "not currently supported" not in caplog.text
    assert "Full packet capture is active" in caplog.text


# --- session finalization --------------------------------------------------

def test_runner_finish_calls_pcap_cleanup_and_cleanup(monkeypatch):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       keylog="k.log", pcap="cap.pcapng", full_capture=True)
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    obj._wine_thread.join(5)
    assert [name for name, _ in obj.finalize_calls] == ["pcap_cleanup", "cleanup"]
    assert obj.finalize_calls[0][1] == (True, False, "cap.pcapng")


def test_runner_finish_goes_through_end_session(monkeypatch):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    obj._config.output.json_output = "out.json"
    obj._session_data_lock = threading.Lock()
    obj.session_data = {"session_info": {}, "statistics": {}, "ssl_sessions": []}
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    obj._wine_thread.join(5)
    assert obj.session_data["session_info"]["end_reason"] == (
        "Wine GDB key extraction finished (gdb exit 0)"
    )
    assert [e.event_type for e in obj.events] == ["ended"]
    assert obj._session_end_claimed is True


def test_finish_skipped_after_teardown_already_ran():
    obj = _make_logger()
    obj._cleanup_done = True
    obj._finish_wine_session("done")
    assert obj.finalize_calls == []
    assert obj._done_event.is_set()


def test_finish_skipped_when_session_end_already_claimed():
    obj = _make_logger()
    obj._session_end_claimed = True
    obj._finish_wine_session("done")
    assert obj.finalize_calls == [] and obj.events == []
    assert obj._done_event.is_set()


def test_finish_sets_done_event_even_if_cleanup_raises():
    obj = _make_logger()

    def boom(*_a):
        raise RuntimeError("teardown failed")

    obj.cleanup = boom
    obj._finish_wine_session("done")
    assert obj._done_event.is_set()


def test_wine_keylog_lines_keeps_only_valid_nss(tmp_path):
    cr, secret = "ab" * 32, "cd" * 48
    keylog = tmp_path / "keys.log"
    keylog.write_text(
        "# comment\n"
        f"CLIENT_RANDOM {cr} {secret}\n"
        "garbage line\n"
        "\n"
        f"CLIENT_TRAFFIC_SECRET_0 {cr} {secret}\n"
    )
    obj = _make_logger()
    obj._wine_keylog_path = str(keylog)
    assert obj._wine_keylog_lines() == [
        f"CLIENT_RANDOM {cr} {secret}",
        f"CLIENT_TRAFFIC_SECRET_0 {cr} {secret}",
    ]


def test_wine_keylog_lines_empty_without_wine_session(tmp_path):
    obj = _make_logger()
    assert obj._wine_keylog_lines() == []
    obj._wine_keylog_path = str(tmp_path / "missing.log")
    assert obj._wine_keylog_lines() == []


# --- attach resolution / hint ------------------------------------------------

def _fake_procs(monkeypatch, obj, procs, wine_pids):
    monkeypatch.setattr(obj, "_iter_proc_cmdlines", lambda: iter(procs))
    monkeypatch.setattr(obj, "_pid_is_wine", lambda pid: str(pid) in wine_pids)


def test_attach_without_spawn_hints_at_s(monkeypatch, caplog):
    spawn_calls, attach_calls = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"], keylog="k.log")
    _fake_procs(monkeypatch, obj, [], set())
    with caplog.at_level(logging.ERROR):
        obj._run_wine_gdb_session()
    assert obj._done_event.is_set()
    assert "-s/--spawn" in caplog.text
    assert "fritap -s -k keys.log wine app.exe" in caplog.text
    assert spawn_calls == {} and attach_calls == {}
    assert obj.finalize_calls == []


def test_attach_falls_back_to_exe_path(monkeypatch):
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"])
    _fake_procs(monkeypatch, obj, [("100", "bash"), ("200", "/p/app.exe ")], {"200"})
    assert obj._resolve_wine_attach_pid() == 200


def test_attach_falls_back_to_exe_basename(monkeypatch):
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"])
    procs = [("300", "C:\\apps\\app.exe "), ("301", "vim notes-app.exe.txt")]
    _fake_procs(monkeypatch, obj, procs, {"300"})
    assert obj._resolve_wine_attach_pid() == 300


def test_attach_exe_fallback_ignores_non_wine(monkeypatch):
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"])
    _fake_procs(monkeypatch, obj, [("400", "tail -f /p/app.exe.log")], set())
    assert obj._resolve_wine_attach_pid() is None


def test_attach_literal_match_wins(monkeypatch):
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"])
    procs = [("500", "/p/app.exe "), ("501", "wine /p/app.exe ")]
    _fake_procs(monkeypatch, obj, procs, {"500", "501"})
    assert obj._resolve_wine_attach_pid() == 501


def test_attach_scans_proc_once_and_caches_wine_checks(monkeypatch):
    obj = _make_logger(spawn=False, target="wine /p/app.exe",
                       target_argv=["wine", "/p/app.exe"])
    scans, checks = [], []
    procs = [("600", "tail -f /p/app.exe"), ("601", "C:\\p\\app.exe ")]

    def scan():
        scans.append(1)
        return iter(procs)

    monkeypatch.setattr(obj, "_iter_proc_cmdlines", scan)
    monkeypatch.setattr(obj, "_pid_is_wine", lambda pid: checks.append(pid) or pid == "601")
    assert obj._resolve_wine_attach_pid() == 601
    assert len(scans) == 1
    assert checks == ["600", "601"]  # "600" matched the exe-path AND basename needles


def test_iter_proc_cmdlines_excludes_own_lineage(monkeypatch):
    import agent_gdb.wine.wine_key_extract as wke
    seen = {}
    monkeypatch.setattr(wke, "own_process_lineage", lambda: {"1", "2"})
    monkeypatch.setattr(wke, "iter_proc_cmdlines",
                        lambda exclude=(): seen.setdefault("exclude", exclude) and iter(()))
    assert list(SSL_Logger._iter_proc_cmdlines()) == []
    assert seen["exclude"] == {"1", "2"}


def test_attach_numeric_target_unchanged(monkeypatch):
    obj = _make_logger(spawn=False, target="4321")
    monkeypatch.setattr(obj, "_iter_proc_cmdlines", lambda: (_ for _ in ()).throw(AssertionError))
    assert obj._resolve_wine_attach_pid() == 4321


# --- prefix pre-flight / privilege drop ----------------------------------------

def _clear_sudo_env(monkeypatch):
    for var in ("SUDO_UID", "SUDO_GID", "SUDO_USER", "WINEPREFIX"):
        monkeypatch.delenv(var, raising=False)


def test_foreign_prefix_aborts_spawn(monkeypatch, tmp_path, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    _clear_sudo_env(monkeypatch)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    monkeypatch.setenv("WINEPREFIX", str(prefix))
    monkeypatch.setattr(os, "geteuid", lambda: prefix.stat().st_uid + 1)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    with caplog.at_level(logging.ERROR):
        obj._run_wine_gdb_session()
    assert obj._done_event.is_set()
    assert str(prefix) in caplog.text and "owned by" in caplog.text
    assert spawn_calls == {}
    assert obj.finalize_calls == []


def test_own_prefix_spawns_without_run_as(monkeypatch, tmp_path):
    spawn_calls, _ = _patch_runner(monkeypatch)
    _clear_sudo_env(monkeypatch)
    monkeypatch.setenv("WINEPREFIX", str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["run_as"] is None


def _fake_sudo(monkeypatch, home, uid=None, *, uid_offset=None,
               blocker="test default: keep root"):
    """Pretend friTap runs as root via sudo for user alice (home *home*).

    With *uid_offset* a ``home/.wine`` prefix is created and alice's uid is its
    owner's uid plus the offset (0 = alice owns it). The gdb privilege probe is
    stubbed to return *blocker*; its call log is returned.
    """
    import pwd
    if uid_offset is not None:
        prefix = home / ".wine"
        prefix.mkdir()
        uid = prefix.stat().st_uid + uid_offset
    _clear_sudo_env(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setenv("SUDO_GID", "20")
    entry = types.SimpleNamespace(pw_name="alice", pw_dir=str(home))
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: entry)
    return _patch_blocker(monkeypatch, blocker)


def _patch_blocker(monkeypatch, reason):
    """Stub unprivileged_gdb_blocker (no real probe); returns its call log."""
    import agent_gdb.wine.wine_key_extract as wke
    calls = []

    def fake_blocker(run_as, keylog, target_pid=None):
        calls.append((run_as, keylog, target_pid))
        return reason

    monkeypatch.setattr(wke, "unprivileged_gdb_blocker", fake_blocker)
    return calls


def test_sudo_passes_run_as_and_checks_user_prefix(monkeypatch, tmp_path, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    _fake_sudo(monkeypatch, tmp_path, uid_offset=0)
    owner = (tmp_path / ".wine").stat().st_uid
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    with caplog.at_level(logging.INFO):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    run_as = spawn_calls["run_as"]
    assert (run_as.uid, run_as.gid, run_as.user, run_as.home) == (owner, 20, "alice", str(tmp_path))
    assert "launching Wine as alice" in caplog.text


def test_sudo_user_prefix_owned_by_other_aborts(monkeypatch, tmp_path, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    _fake_sudo(monkeypatch, tmp_path, uid_offset=1)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    with caplog.at_level(logging.ERROR):
        obj._run_wine_gdb_session()
    assert obj._done_event.is_set()
    assert str(tmp_path / ".wine") in caplog.text
    assert spawn_calls == {}
    assert obj.finalize_calls == []


def test_real_root_shell_has_no_run_as(monkeypatch):
    _clear_sudo_env(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "0")
    monkeypatch.setenv("SUDO_GID", "0")
    import agent_gdb.wine.wine_key_extract as wke
    assert wke.sudo_invoker() is None


# --- least-privilege gdb under sudo ---------------------------------------------

def test_sudo_spawn_runs_gdb_as_invoker_when_unblocked(monkeypatch, tmp_path, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    calls = _fake_sudo(monkeypatch, tmp_path, uid_offset=0, blocker=None)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    with caplog.at_level(logging.INFO):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["gdb_run_as"] == spawn_calls["run_as"] is not None
    assert calls == [(spawn_calls["run_as"], "k.log", None)]
    assert "Running gdb as alice" in caplog.text


def test_sudo_spawn_keeps_gdb_root_when_blocked(monkeypatch, tmp_path, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    _fake_sudo(monkeypatch, tmp_path, uid_offset=0,
               blocker="kernel.yama.ptrace_scope=1 blocks it")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    with caplog.at_level(logging.INFO):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["gdb_run_as"] is None
    assert spawn_calls["run_as"] is not None
    assert "Keeping gdb as root: kernel.yama.ptrace_scope=1" in caplog.text


def test_sudo_attach_runs_gdb_as_invoker(monkeypatch, tmp_path):
    _, attach_calls = _patch_runner(monkeypatch)
    calls = _fake_sudo(monkeypatch, tmp_path, 1000, blocker=None)
    obj = _make_logger(spawn=False, target="4321", keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    run_as = attach_calls["run_as"]
    assert (run_as.uid, run_as.user) == (1000, "alice")
    assert calls == [(run_as, "k.log", 4321)]


def test_non_sudo_never_probes_gdb_privileges(monkeypatch, tmp_path):
    spawn_calls, attach_calls = _patch_runner(monkeypatch)
    import agent_gdb.wine.wine_key_extract as wke
    _clear_sudo_env(monkeypatch)
    monkeypatch.setattr(wke, "sudo_invoker", lambda: None)
    calls = _patch_blocker(monkeypatch, None)
    monkeypatch.setenv("WINEPREFIX", str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid)
    spawner = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog="k.log")
    spawner._run_wine_gdb_session()
    attacher = _make_logger(spawn=False, target="4321", keylog="k.log")
    attacher._run_wine_gdb_session()
    assert spawner._done_event.wait(5) and attacher._done_event.wait(5)
    assert spawn_calls["gdb_run_as"] is None
    assert attach_calls["run_as"] is None
    assert calls == []


# --- review fixes -----------------------------------------------------------

def test_attach_by_name_without_extractor_is_not_wine(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=False, target="firefox", target_argv=None)

    def missing():
        raise ImportError("No module named 'agent_gdb'")

    monkeypatch.setattr(SSL_Logger, "_wine_extractor_module", staticmethod(missing))
    assert obj._should_use_wine_gdb() is False


def test_extractor_module_adds_repo_root_on_import_error(monkeypatch):
    import importlib
    import sys
    sentinel, attempts = object(), []

    def fake_import(name):
        attempts.append(name)
        if len(attempts) == 1:
            raise ImportError(name)
        return sentinel

    monkeypatch.setattr(importlib, "import_module", fake_import)
    monkeypatch.setattr(sys, "path", [])
    assert SSL_Logger._wine_extractor_module() is sentinel
    assert attempts == ["agent_gdb.wine.wine_key_extract"] * 2
    assert os.path.isdir(os.path.join(sys.path[0], "agent_gdb"))


def test_exe_needles_skip_launcher_switches():
    obj = _make_logger(spawn=False, target="wine start /unix /p/app.exe",
                       target_argv=["wine", "start", "/unix", "/p/app.exe"])
    assert obj._wine_exe_needles(obj.target_app) == ["/p/app.exe", "app.exe"]


def test_exe_needles_empty_without_exe_argument():
    obj = _make_logger(spawn=False, target="wine cmd /c",
                       target_argv=["wine", "cmd", "/c"])
    assert obj._wine_exe_needles(obj.target_app) == []


def test_basename_needle_matches_only_whole_basename():
    matches = SSL_Logger._cmdline_matcher("a.exe")
    assert not matches("C:\\data.exe ")
    assert matches("C:\\dir\\A.EXE --flag")
    assert matches("/p/a.exe ")


def test_attach_basename_does_not_match_longer_exe(monkeypatch):
    obj = _make_logger(spawn=False, target="wine a.exe", target_argv=["wine", "a.exe"])
    _fake_procs(monkeypatch, obj, [("700", "C:\\data.exe ")], {"700"})
    assert obj._resolve_wine_attach_pid() is None


def test_quoted_target_path_with_spaces(monkeypatch):
    spawn_calls, _ = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target="wine '/p/my app.exe' --x", keylog="k.log")
    assert obj._target_is_wine() is True
    assert obj._wine_exe_needles(obj.target_app) == ["/p/my app.exe", "my app.exe"]
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["program"] == "/p/my app.exe"
    assert spawn_calls["program_args"] == ["--x"]


_CR, _SECRET = "ab" * 32, "cd" * 48
_OLD_LINE = f"CLIENT_RANDOM {'11' * 32} {_SECRET}"
_NEW_LINE = f"CLIENT_RANDOM {_CR} {_SECRET}"


def test_keylog_lines_only_from_this_session(monkeypatch, tmp_path):
    _patch_runner(monkeypatch)
    keylog = tmp_path / "keys.log"
    keylog.write_text(_OLD_LINE + "\n")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog=str(keylog))
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert obj._wine_keylog_offset == len(_OLD_LINE) + 1
    with keylog.open("a") as handle:
        handle.write(f"{_NEW_LINE}\n{_NEW_LINE}\n")
    assert obj._wine_keylog_lines() == [_NEW_LINE]


def test_keylog_lines_reread_truncated_file(tmp_path):
    keylog = tmp_path / "keys.log"
    keylog.write_text(_NEW_LINE + "\n")
    obj = _make_logger()
    obj._wine_keylog_path = str(keylog)
    obj._wine_keylog_offset = 10_000
    assert obj._wine_keylog_lines() == [_NEW_LINE]


def test_runner_failure_reason_reaches_end_session(monkeypatch):
    import agent_gdb.wine.wine_key_extract as wke

    def boom(**_kw):
        raise RuntimeError("gdb vanished")

    monkeypatch.setattr(wke, "run_wine_key_extraction", boom)
    obj = _make_logger(spawn=False, target="4321", keylog="k.log")
    reasons = []
    obj._end_session = reasons.append
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert reasons == ["Wine GDB key extraction failed: gdb vanished"]


def test_attach_pid_resolved_once(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    _, attach_calls = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=False, target="app.exe", keylog="k.log")
    scans = []
    monkeypatch.setattr(obj, "_iter_proc_cmdlines",
                        lambda: scans.append(1) or iter([("800", "C:\\app.exe ")]))
    monkeypatch.setattr(obj, "_pid_is_wine", lambda pid: str(pid) == "800")
    assert obj._should_use_wine_gdb() is True
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert attach_calls["attach"] == "800"
    assert len(scans) == 1
