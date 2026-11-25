import subprocess
import time

from dev import tlshunter as hunter


def stat(tick):
    return "42 (name has ) spaces) S " + "0 " * 18 + str(tick)


def sample(monkeypatch, end=10, namespace="net:[9]", fd_error=False):
    def shell(config, command, **kwargs):
        if command.startswith("cat /proc/sys"):
            return ("11111111-2222-3333-4444-555555555555\n"
                    "42 10123 org.fixture:worker\n43 10123 org.unrelated\n")
        if "dumpsys activity" in command:
            return "mResumedActivity: ActivityRecord{123 u0 org.foreign/.Main}"
        assert "/proc/42/" in command and "/proc/43/" not in command
        return "\n".join([
            stat(10), "@identity", "10123", "org.fixture:worker",
            "@namespace", "net:[9]", "@fds", "fd -> socket:[7]",
            "@fd_error" if fd_error else "", "@tcp", "TABLE_ERROR", "@tcp6",
            "@udp", "0: 0100007F:1234 00000000:0000 07 0:0 0:0 0 10123 0 7",
            "@udp6", "@maps", "/apex/example/libssl.so", "@end_namespace", namespace, "@end", stat(end),
        ])
    monkeypatch.setattr(hunter, "_shell", shell)
    config = hunter.Config("fixture", 0, ("org.fixture",))
    return hunter._snapshot(config, {"org.fixture": 10123}, time.monotonic() + 5)


def test_socket_holder_and_visibility(monkeypatch):
    result = sample(monkeypatch, fd_error=True)
    assert result["foreground_hint"] == ["org.foreign"]
    assert result["processes"][0]["sockets"][0]["peer_hex"] is None
    assert {gap["reason"] for gap in result["gaps"]} == {
        "fd_visibility_incomplete", "socket_table_unavailable"}
    report = hunter.summarize([dict(result, phase=phase)
                               for phase in ("baseline", "interaction")])
    assert report["first_observations"][1]["seen_at_baseline"]
    assert report["action_attribution"] == "unresolved"


def test_restart_and_namespace_change(monkeypatch):
    assert not sample(monkeypatch, end=11)["processes"]
    assert not sample(monkeypatch, namespace="net:[10]")["processes"]


def test_cli_entrypoints():
    import sys

    for args in (["dev/tlshunter"], ["-m", "dev.tlshunter"]):
        result = subprocess.run([sys.executable, *args, "--help"],
                                check=True, capture_output=True, text=True)
        assert "--package" in result.stdout


def test_clock_uncertainty_preserved():
    assert hunter.lead_time_bounds(100, 130, 20, 40) == (-10, 10)


def test_offline_timing_and_binder_scope():
    from dev.tlshunter.offline import binder_edges, compare_timing

    trial = dict(id="case", candidate_host_ns=100, handshake_device_ns=150,
                 clock_host_before_ns=90, clock_host_after_ns=100,
                 clock_device_ns=120, readiness_ns=25)
    assert compare_timing(trial)["status"] == "clock_ambiguous"
    assert compare_timing(dict(trial, readiness_ns=20))["status"] == "sufficient_lead"
    assert compare_timing(dict(trial, readiness_ns=31))["status"] == "insufficient_lead"
    assert compare_timing(dict(trial, candidate_host_ns=None))["status"] == "candidate_missed"
    row = dict(client_process="client", client_pid="50", client_upid="5", client_ts="20",
               server_process="worker", server_pid="51", server_upid="6", server_ts="21")
    assert not list(binder_edges([row], ["client"]))
    edge, = binder_edges([row], ["client", "worker"])
    assert edge["server"]["upid"] == 6
    assert edge["action_attribution"] == "unresolved"


def test_clock_sampling_preserves_proc_resolution(monkeypatch):
    from dev.tlshunter import offline

    monkeypatch.setattr(offline.subprocess, "run",
                        lambda *a, **kw: subprocess.CompletedProcess(a, 0, "12.34 5.0\n"))
    clock = offline.sample_clock("fixture")
    assert clock["clock_device_ns"] == 12_340_000_000
    assert clock["clock_resolution_ns"] == 10_000_000
    assert clock["clock_host_before_ns"] <= clock["clock_host_after_ns"]
