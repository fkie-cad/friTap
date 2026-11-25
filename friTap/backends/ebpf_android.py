"""Android-side prerequisites for the OpenSSL eBPF capture runtime."""

import re
import subprocess

from ..android import run_adb
from .capture import ReadinessCheck
from .ebpf_native import NativeError

MIN_KERNEL = (5, 4)
_CONFIG_KEYS = ("BPF_SYSCALL", "ARCH_SUPPORTS_UPROBES", "UPROBES", "UPROBE_EVENTS", "DEBUG_INFO_BTF")
_CONFIG_PATTERN = "|".join(_CONFIG_KEYS)
_PROBE = f"""
uname -r
if test -r /proc/config.gz; then
    zcat /proc/config.gz | grep -E '^(CONFIG_({_CONFIG_PATTERN})=|# CONFIG_({_CONFIG_PATTERN}) is not set)'
fi
test ! -r /sys/kernel/btf/vmlinux || echo kernel_btf=present
test ! -e /sys/kernel/tracing/uprobe_events || echo uprobe_events=present
"""


def kernel_checks(serial) -> tuple[ReadinessCheck, ...]:
    """Read kernel evidence as the exact ADB identity that launches capture."""
    try:
        result = run_adb(
            ["adb", "-s", serial, "shell", "-T", _PROBE],
            capture_output=True, text=True, timeout=8, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NativeError("setup_required", f"Could not inspect Android kernel on {serial} over ADB") from exc
    lines = result.stdout.splitlines()
    kernel = lines[0].strip() if lines else ""
    version = re.match(r"(\d+)\.(\d+)", kernel)
    if not version:
        raise NativeError("unsupported", "Could not identify the Android kernel version")
    if tuple(map(int, version.groups())) < MIN_KERNEL:
        raise NativeError(
            "unsupported",
            f"Android kernel {kernel} is below the eBPF capture minimum of 5.4",
        )

    observed = set(lines[1:])
    checks = [ReadinessCheck("kernel_version", "observed", kernel)]
    for key in _CONFIG_KEYS:
        enabled = f"CONFIG_{key}=y" in observed
        disabled = f"# CONFIG_{key} is not set" in observed
        checks.append(ReadinessCheck(
            f"CONFIG_{key}", "observed" if enabled or disabled else "unknown",
            "enabled" if enabled else "disabled" if disabled else "unconfirmed",
        ))
        if disabled and key in ("BPF_SYSCALL", "UPROBES"):
            raise NativeError("unsupported", f"Android kernel {kernel} has CONFIG_{key} disabled")
    for probe in ("kernel_btf", "uprobe_events"):
        present = f"{probe}=present" in observed
        checks.append(ReadinessCheck(probe, "observed" if present else "unknown",
                                     "visible" if present else "not visible to ADB shell"))
    return tuple(checks)
