"""Unit tests for friTap/wine_process_watcher.py — following a Wine app's
processes via /proc so friTap can attach the Chromium network service early
(fkie-cad/friTap#52).

WineProcessWatcher takes all /proc access as injected callables (list_pids,
read_cmdline, read_maps, read_prefix) plus a fake monotonic clock, so these
tests drive poll_once() directly against in-memory process tables — no real
/proc, no monkeypatching of open().

Run: pytest tests/unit/test_wine_process_watcher.py
"""

import os

from friTap.wine_process_watcher import (
    WineProcessWatcher,
    classify_wine_cmdline,
    is_network_process,
    split_cmdline,
    wine_process_ready,
)

PREFIX = "/home/u/.wine-test"
READY_MAPS = "7f00-7f01 r--p 0 00:00 0 .../cefclient.exe\n... kernelbase.dll\n"


def _cmd(*argv):
    return "\x00".join(argv).encode() + b"\x00"


def test_classify_wine_cmdline():
    assert classify_wine_cmdline(["Z:\\a\\cefclient.exe", "--no-sandbox"]) == "cefclient.exe"
    assert classify_wine_cmdline(["cefclient.exe", "--type=utility",
                                  "--utility-sub-type=network.mojom.NetworkService"]) == "cefclient.exe [network service]"
    assert classify_wine_cmdline(["cefclient.exe", "--type=utility"]) == "cefclient.exe [utility]"
    # Non-TLS Chromium children and Wine system processes are ignored.
    assert classify_wine_cmdline(["cefclient.exe", "--type=renderer"]) is None
    assert classify_wine_cmdline(["cefclient.exe", "--type=gpu-process"]) is None
    assert classify_wine_cmdline(["cefclient.exe", "--type=utility",
                                  "--utility-sub-type=storage.mojom.StorageService"]) is None
    assert classify_wine_cmdline(["C:\\windows\\system32\\services.exe"]) is None
    assert classify_wine_cmdline(["C:\\windows\\system32\\explorer.exe", "/desktop"]) is None
    assert classify_wine_cmdline(["/usr/lib/wine/wine64", "cefclient.exe"]) is None  # argv0 not .exe
    assert classify_wine_cmdline([]) is None


def test_is_network_process():
    assert is_network_process("cefclient.exe [network service]")
    assert is_network_process("cefclient.exe [utility]")
    assert not is_network_process("cefclient.exe")


def test_wine_process_ready():
    assert wine_process_ready("... /x/cefclient.exe ...\n... kernel32.dll", "cefclient.exe")
    assert wine_process_ready("... cefclient.exe ...\n... kernelbase.dll", "cefclient.exe")
    assert not wine_process_ready("... cefclient.exe ...", "cefclient.exe")  # no kernel yet
    assert not wine_process_ready("... kernel32.dll", "cefclient.exe")       # exe not mapped


def test_split_cmdline():
    assert split_cmdline(b"a\x00b\x00") == ["a", "b"]
    assert split_cmdline(b"") == []


def _watcher(procs, **kw):
    """procs: {pid(str): {"cmdline": bytes|None, "maps": str, "prefix": str}}."""
    clock = {"t": 0.0}
    w = WineProcessWatcher(
        kw.pop("on_new"),
        prefix=PREFIX,
        list_pids=lambda: list(procs.keys()),
        read_cmdline=lambda p: procs.get(p, {}).get("cmdline"),
        read_maps=lambda p: procs.get(p, {}).get("maps", ""),
        # Like process_wine_prefix, report the prefix realpath'd (on macOS
        # /home resolves to /System/Volumes/Data/home).
        read_prefix=lambda p: os.path.realpath(procs.get(p, {}).get("prefix", PREFIX)),
        clock=lambda: clock["t"],
        **kw,
    )
    return w, clock


def test_reports_network_service_immediately_with_zero_settle():
    seen = []
    procs = {"100": {"cmdline": _cmd("cefclient.exe", "--type=utility",
                                     "--utility-sub-type=network.mojom.NetworkService"),
                     "maps": READY_MAPS}}
    w, _ = _watcher(procs, on_new=lambda pid, label: seen.append((pid, label)), settle_seconds=0.0)
    w.poll_once()
    assert seen == [(100, "cefclient.exe [network service]")]
    assert w.reported == {100: "cefclient.exe [network service]"}
    # Reported once only.
    w.poll_once()
    assert seen == [(100, "cefclient.exe [network service]")]


def test_other_prefix_is_skipped():
    seen = []
    procs = {"100": {"cmdline": _cmd("cefclient.exe", "--type=utility",
                                     "--utility-sub-type=network.mojom.NetworkService"),
                     "maps": READY_MAPS, "prefix": "/some/other/.wine"}}
    w, _ = _watcher(procs, on_new=lambda pid, label: seen.append(pid), settle_seconds=0.0)
    w.poll_once()
    assert seen == []


def test_not_ready_is_retried_then_reported_when_kernel_maps():
    seen = []
    procs = {"100": {"cmdline": _cmd("cefclient.exe", "--type=utility",
                                     "--utility-sub-type=network.mojom.NetworkService"),
                     "maps": "... cefclient.exe ...(no kernel yet)"}}
    w, _ = _watcher(procs, on_new=lambda pid, label: seen.append(pid), settle_seconds=0.0)
    w.poll_once()
    assert seen == []                      # not ready: kernel32/kernelbase not mapped
    procs["100"]["maps"] = READY_MAPS      # kernel now mapped
    w.poll_once()
    assert seen == [100]


def test_empty_cmdline_retried_none_dropped():
    seen = []
    procs = {"100": {"cmdline": b"", "maps": READY_MAPS},     # transient mid-exec
             "200": {"cmdline": None, "maps": READY_MAPS}}    # gone/kernel thread
    w, _ = _watcher(procs, on_new=lambda pid, label: seen.append(pid), settle_seconds=0.0)
    w.poll_once()
    assert seen == []
    assert "200" in w._done and "100" not in w._done          # None dropped, "" retried
    # Once the empty-cmdline process shows a real network-service cmdline, it reports.
    procs["100"]["cmdline"] = _cmd("cefclient.exe", "--type=utility",
                                   "--utility-sub-type=network.mojom.NetworkService")
    w.poll_once()
    assert seen == [100]


def test_browser_deferred_until_network_seen():
    seen = []
    procs = {
        "100": {"cmdline": _cmd("Z:\\a\\cefclient.exe", "--no-sandbox"), "maps": READY_MAPS},
        "200": {"cmdline": _cmd("cefclient.exe", "--type=utility",
                                "--utility-sub-type=network.mojom.NetworkService"), "maps": READY_MAPS},
    }
    # Large defer so the browser only reports after the network service does.
    w, clock = _watcher(procs, on_new=lambda pid, label: seen.append(pid),
                        settle_seconds=0.0, non_network_defer_seconds=1000.0)
    w.poll_once()
    # Network service (200) reported; browser (100) held back.
    assert 200 in seen and 100 not in seen
    w.poll_once()
    # Now that a network service was seen, the browser is reported too.
    assert 100 in seen


def test_exclude_pids_never_reported():
    seen = []
    procs = {"100": {"cmdline": _cmd("cefclient.exe", "--type=utility",
                                     "--utility-sub-type=network.mojom.NetworkService"),
                     "maps": READY_MAPS}}
    w, _ = _watcher(procs, on_new=lambda pid, label: seen.append(pid),
                    settle_seconds=0.0, exclude=["100"])
    w.poll_once()
    assert seen == []
