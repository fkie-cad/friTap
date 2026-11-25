import json
import subprocess
from types import SimpleNamespace

import pytest

from friTap.backends import ebpf_android, ebpf_native
from friTap.backends.capture import select_capture_backend
from friTap.config import DeviceConfig


@pytest.mark.parametrize(
    "output,detail",
    [
        ("4.19.255\nCONFIG_BPF_SYSCALL=y\nCONFIG_UPROBES=y\n", "minimum of 5.4"),
        ("6.6.30\n# CONFIG_BPF_SYSCALL is not set\n", "CONFIG_BPF_SYSCALL disabled"),
    ],
)
def test_android_kernel_gate(monkeypatch, output, detail):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=output, returncode=0))
    with pytest.raises(ebpf_native.NativeError, match=detail) as error:
        ebpf_android.kernel_checks("emulator-5570")
    assert error.value.status == "unsupported"


def test_android_readiness_runs_real_preflight_on_selected_serial(monkeypatch):
    serial = "emulator-5570"
    adb = ["adb", "-s", serial, "shell"]
    remote = [*adb, "-T", "/data/local/tmp/fritap-ebpf-agent"]
    expected = [
        (["adb", "-s", serial, "get-state"], "device\n"),
        ([*adb, "getprop", "ro.build.version.sdk"], "30\n"),
        ([*adb, "uname", "-rm"], "5.4.86 aarch64\n"),
        ([*adb, "-T", ebpf_android._PROBE],
         "5.4.86\nCONFIG_BPF_SYSCALL=y\nCONFIG_UPROBES=y\n# CONFIG_DEBUG_INFO_BTF is not set\n"),
        ([*remote, "--version"], ebpf_native._ABI.encode()),
        ([*remote, "preflight", "1234"],
         json.dumps({"type": "ready", "build_id": "aabb", "kernel": "5.4.86", "transport": "perf"}).encode()),
    ]

    def run(argv, **kwargs):
        command, stdout = expected.pop(0)
        assert argv == command
        return SimpleNamespace(stdout=stdout, stderr=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    backend = select_capture_backend("ebpf")
    report = backend.diagnose(DeviceConfig(mobile=serial), target="1234")
    assert report.capture_supported and report.status == "ready"
    assert report.target == "1234" and report.target_os == "android"
    assert "transport: perf" in report.detail
    assert any(check.name == "CONFIG_DEBUG_INFO_BTF" and check.detail == "disabled" for check in report.checks)
    assert not expected
