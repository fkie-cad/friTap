"""Apple platform binary detection, fail-fast hints and --macos-unsign-copy.

All subprocess calls (codesign/lipo/sysctl) are faked; no frida or macOS needed.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
import types

import pytest

from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.fritap_utility import Failure
from friTap.platform_support import macos_targets as mt

FRIDA_HELPER_CRASH = (
    "oops, frida-helper appears to have crashed. It may have been killed by the "
    "system while trying to access a hardened process."
)
LOGGER = logging.getLogger("test.macos_targets")
REAL_SCHEDULE_CLEANUP = mt.schedule_cleanup


@pytest.fixture(autouse=True)
def _no_leaks_into_system_tmp(tmp_path, monkeypatch):
    """Keep every fritap-unsigned-* dir under tmp_path and never start the real watcher.

    Without this, make_unsigned_copy(tmp_root=None) wrote into $TMPDIR and the
    test's no-op cleanup left the dir behind on every run.
    """
    monkeypatch.setattr(mt.tempfile, "tempdir", str(tmp_path))

    def no_watcher(path, *_a, **_kw):
        raise AssertionError(f"test would start the detached cleanup watcher for {path}")

    monkeypatch.setattr(mt, "schedule_cleanup", no_watcher)


def _completed(cmd, rc=0, out="", err=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)


class FakeRunner:
    """Answers codesign/lipo/sysctl like a host; records every command."""

    def __init__(self, platform_binary=True, archs="x86_64 arm64e", boot_args="",
                 fail_on=None):
        self.platform_binary = platform_binary
        self.archs = archs
        self.boot_args = boot_args
        self.fail_on = fail_on
        self.calls = []

    def __call__(self, cmd, **_kwargs):
        self.calls.append(cmd)
        if self.fail_on and cmd[0] == self.fail_on and "-dv" not in cmd and "-archs" not in cmd:
            return _completed(cmd, rc=1, err=f"{self.fail_on} exploded")
        if cmd[:2] == ["codesign", "-dv"]:
            ident = "Platform identifier=26\n" if self.platform_binary else ""
            return _completed(cmd, err=f"Executable={cmd[-1]}\n{ident}flags=0x0(none)\n")
        if cmd[:2] == ["lipo", "-archs"]:
            return _completed(cmd, out=self.archs + "\n")
        if cmd[0] == "lipo" and "-thin" in cmd:
            out_path = cmd[cmd.index("-output") + 1]
            with open(out_path, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe")
            return _completed(cmd)
        if cmd[0] == "codesign":
            return _completed(cmd)
        if cmd[:3] == ["sysctl", "-n", "kern.bootargs"]:
            return _completed(cmd, out=self.boot_args + "\n")
        if cmd[:3] == ["sysctl", "-n", "hw.optional.arm64"]:
            return _completed(cmd, out="1\n")
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "curl"
    path.write_bytes(b"\xca\xfe\xba\xbe")
    return str(path)


@pytest.fixture
def darwin(monkeypatch):
    monkeypatch.setattr(mt.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mt.platform, "machine", lambda: "arm64")


def _parsed(path, **overrides):
    values = dict(exec=f"{path} -s https://example.com",
                  exec_argv=[path, "-s", "https://example.com"],
                  spawn=True, mobile=False, host=None, macos_unsign_copy=False)
    values.update(overrides)
    return types.SimpleNamespace(**values)


# --- probing --------------------------------------------------------------

def test_probe_target_detects_platform_arm64e(target):
    info = mt.probe_target(target, FakeRunner())
    assert info.platform_binary and info.has_arm64e
    assert info.archs == ("x86_64", "arm64e")
    assert info.native_slice == "arm64e"


def test_probe_target_third_party_binary(target):
    info = mt.probe_target(target, FakeRunner(platform_binary=False, archs="arm64"))
    assert not info.platform_binary
    assert info.native_slice == "arm64"


def test_probe_target_returns_none_when_tools_missing(target):
    def broken(cmd, **_kw):
        raise FileNotFoundError(cmd[0])
    assert mt.probe_target(target, broken) is None


@pytest.mark.parametrize("boot_args,expected", [
    ("", False),
    ("-v", False),
    ("-arm64e_preview_abi", True),
    ("-arm64e_preview_abi thid_should_crash=0 tss_should_crash=0", True),
])
def test_privileged_injection_possible(boot_args, expected):
    assert mt.privileged_injection_possible(boot_args) is expected


def test_is_hardened_process_error():
    assert mt.is_hardened_process_error(FRIDA_HELPER_CRASH)
    assert not mt.is_hardened_process_error("unable to find process with name 'x'")


# --- hint text ---------------------------------------------------------------

def test_hint_lines_name_every_option():
    text = "\n".join(mt.platform_binary_hint_lines("/usr/bin/curl"))
    assert 'sudo nvram boot-args="-arm64e_preview_abi"' in text
    assert "REBOOT" in text and "sudo fritap" in text
    assert "--macos-unsign-copy" in text
    assert "brew install curl" in text


def test_hardened_hint_only_on_darwin(monkeypatch):
    monkeypatch.setattr(mt.platform, "system", lambda: "Linux")
    assert mt.hardened_process_hint_lines(FRIDA_HELPER_CRASH, "curl") == []


def test_hardened_hint_on_darwin(darwin):
    assert mt.hardened_process_hint_lines(FRIDA_HELPER_CRASH, "curl -s x")
    assert mt.hardened_process_hint_lines("some other denial", "curl") == []


# --- prepare_macos_spawn_target -----------------------------------------------

def test_fail_fast_with_exit_code_1(darwin, target):
    with pytest.raises(Failure) as exc:
        mt.prepare_macos_spawn_target(_parsed(target), LOGGER, run=FakeRunner())
    assert exc.value.code == EXIT_RUNTIME_ERROR == 1
    assert "-arm64e_preview_abi" in exc.value.info


def test_boot_arg_set_lets_spawn_proceed(darwin, target, monkeypatch):
    monkeypatch.setattr(mt.os, "geteuid", lambda: 0)
    parsed = _parsed(target)
    mt.prepare_macos_spawn_target(parsed, LOGGER, run=FakeRunner(boot_args="-arm64e_preview_abi"))
    assert parsed.exec_argv[0] == target


def test_third_party_binary_untouched(darwin, target):
    parsed = _parsed(target)
    mt.prepare_macos_spawn_target(parsed, LOGGER, run=FakeRunner(platform_binary=False))
    assert parsed.exec_argv[0] == target


@pytest.mark.parametrize("override", [
    {"spawn": False}, {"mobile": "serial"}, {"host": "1.2.3.4:27042"},
])
def test_skipped_for_attach_and_remote(darwin, target, override):
    runner = FakeRunner()
    mt.prepare_macos_spawn_target(_parsed(target, **override), LOGGER, run=runner)
    assert runner.calls == []


def test_skipped_on_linux(monkeypatch, target):
    monkeypatch.setattr(mt.platform, "system", lambda: "Linux")
    runner = FakeRunner()
    mt.prepare_macos_spawn_target(_parsed(target), LOGGER, run=runner)
    assert runner.calls == []


def test_unsign_copy_rewrites_argv_and_schedules_cleanup(darwin, target, tmp_path):
    parsed = _parsed(target, macos_unsign_copy=True)
    runner, cleaned = FakeRunner(), []
    mt.prepare_macos_spawn_target(parsed, LOGGER, run=runner, cleanup=cleaned.append)
    copy = parsed.exec_argv[0]
    assert copy != target and os.path.basename(copy) == "curl"
    assert os.path.dirname(os.path.dirname(copy)) == str(tmp_path)
    assert parsed.exec_argv[1:] == ["-s", "https://example.com"]
    assert parsed.exec == " ".join(parsed.exec_argv)
    assert cleaned == [os.path.dirname(copy)]
    assert ["lipo", target, "-thin", "arm64e", "-output", copy] in runner.calls
    assert ["codesign", "--force", "--sign", "-", copy] in runner.calls


def test_unsign_copy_failure_cleans_temp_dir_and_exits_1(darwin, target, tmp_path, monkeypatch):
    work = tmp_path / "work"

    def fake_mkdtemp(prefix, dir=None):
        work.mkdir()
        return str(work)

    monkeypatch.setattr(mt.tempfile, "mkdtemp", fake_mkdtemp)
    with pytest.raises(Failure) as exc:
        mt.prepare_macos_spawn_target(_parsed(target, macos_unsign_copy=True), LOGGER,
                                      run=FakeRunner(fail_on="codesign"), cleanup=lambda _p: None)
    assert exc.value.code == 1
    assert "codesign exploded" in exc.value.info
    assert not work.exists()


def test_unsign_copy_removes_dir_when_watcher_cannot_start(darwin, target, tmp_path):
    def broken_cleanup(_path):
        raise OSError("fork failed")

    with pytest.raises(Failure, match="could not schedule removal"):
        mt.prepare_macos_spawn_target(_parsed(target, macos_unsign_copy=True), LOGGER,
                                      run=FakeRunner(), cleanup=broken_cleanup)
    assert not list(tmp_path.glob("fritap-unsigned-*"))


def test_unsign_copy_default_cleanup_is_resolved_at_call_time(darwin, target, monkeypatch):
    scheduled = []
    monkeypatch.setattr(mt, "schedule_cleanup", scheduled.append)
    parsed = _parsed(target, macos_unsign_copy=True)
    mt.prepare_macos_spawn_target(parsed, LOGGER, run=FakeRunner())
    assert scheduled == [os.path.dirname(parsed.exec_argv[0])]


def test_unsign_copy_rejects_app_bundles(darwin, tmp_path):
    bundle_bin = tmp_path / "Safari.app" / "Contents" / "MacOS" / "Safari"
    bundle_bin.parent.mkdir(parents=True)
    bundle_bin.write_bytes(b"x")
    with pytest.raises(Failure, match="app bundles"):
        mt.prepare_macos_spawn_target(_parsed(str(bundle_bin), macos_unsign_copy=True),
                                      LOGGER, run=FakeRunner(), cleanup=lambda _p: None)


def test_single_slice_binary_is_copied_not_thinned(target, tmp_path):
    info = mt.MacOSTargetInfo(path=target, archs=("arm64e",), platform_binary=True)
    runner = FakeRunner(archs="arm64e")
    copy = mt.make_unsigned_copy(info, runner, tmp_root=str(tmp_path))
    assert os.path.exists(copy)
    assert not any(c[0] == "lipo" for c in runner.calls)


def test_schedule_cleanup_spawns_detached_watcher():
    seen = {}

    def fake_popen(cmd, **kwargs):
        seen.update(cmd=cmd, kwargs=kwargs)

    REAL_SCHEDULE_CLEANUP("/tmp/fritap-unsigned-x", owner_pid=4242, popen=fake_popen)
    assert seen["cmd"][-2:] == ["4242", "/tmp/fritap-unsigned-x"]
    assert seen["kwargs"]["start_new_session"] is True


def test_cli_wires_flag_and_call_sites():
    from friTap import friTap as cli_mod
    source = open(cli_mod.__file__, encoding="utf-8").read()
    assert '"--macos-unsign-copy"' in source
    assert "prepare_macos_spawn_target(parsed, logger)" in source
    assert "hardened_process_hint_lines(str(e)" in source


@pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs a POSIX shell")
def test_real_watcher_removes_dir_after_owner_exits(tmp_path):
    """End to end: the detached watcher deletes the dir once the owner pid is gone."""
    work = tmp_path / "fritap-unsigned-e2e"
    work.mkdir()
    (work / "curl").write_bytes(b"x")
    owner = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
    owner.wait()  # reaped: kill -0 on the pid now fails, as after friTap's exit
    REAL_SCHEDULE_CLEANUP(str(work), owner_pid=owner.pid)
    deadline = time.monotonic() + 10
    while work.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not work.exists()
