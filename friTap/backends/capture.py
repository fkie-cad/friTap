"""Backend selection and target readiness for capture frontends."""

from __future__ import annotations

import errno
import json
import os
import platform
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .base import BackendInvalidArgumentError, BackendInvalidOperationError, BackendName

if TYPE_CHECKING:
    from ..config import DeviceConfig, FriTapConfig
    from ..legacy.ssl_logger_core import SSL_Logger
    from ..session import Session


# adb reports these transport states as errors ("error: device unauthorized.").
_ADB_STATE_ERROR = re.compile(r"device (unauthorized|offline|authorizing|connecting)")


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class CaptureReadiness:
    backend: str
    target: str
    status: str
    detail: str
    capture_supported: bool
    checks: tuple[ReadinessCheck, ...] = ()
    target_os: str | None = None


class CaptureBackend(ABC):
    name: BackendName

    @abstractmethod
    def readiness(self, device: DeviceConfig) -> CaptureReadiness:
        """Inspect the selected execution environment."""

    def diagnose(self, device: DeviceConfig, *, kernel_helper: str | None = None, target: str | None = None) -> CaptureReadiness:
        """Run explicit readiness diagnostics for the selected backend."""
        if kernel_helper is not None:
            raise BackendInvalidArgumentError("Kernel helpers require the eBPF backend")
        return self.readiness(device)


class FridaCaptureBackend(CaptureBackend):
    name = BackendName.FRIDA

    def readiness(self, device: DeviceConfig) -> CaptureReadiness:
        from ..server_manager.probe import is_attach_capable, probe_frida_server
        from . import get_backend

        if not (device.mobile or device.device_id or device.host):
            get_backend(self.name).get_local_device()
            return CaptureReadiness(self.name, "local", "ready", "Local Frida available", True)
        target = device.host or device.device_id or device.mobile
        selected = get_backend(self.name).get_device(
            mobile=device.device_id or device.mobile, host=device.host,
        )
        state = probe_frida_server(selected)
        return CaptureReadiness(self.name, str(target), state.value, state.value,
                                is_attach_capable(state))


class EbpfCaptureBackend(CaptureBackend):
    name = BackendName.EBPF

    def readiness(self, device: DeviceConfig) -> CaptureReadiness:
        if device.host:
            return self._report(device.host, "unsupported", "eBPF does not accept a frida-server address")
        if device.device_id or device.mobile:
            return self._android_readiness(device.device_id or device.mobile)
        if platform.system() != "Linux":
            return self._report("local", "unsupported", "Local eBPF requires Linux")
        checks = (
            ReadinessCheck("execution_uid", "observed", str(os.geteuid())),
            self._linux_file_check("unprivileged_bpf", Path("/proc/sys/kernel/unprivileged_bpf_disabled")),
            self._linux_file_check("kernel_btf", Path("/sys/kernel/btf/vmlinux"), read=False),
        )
        return self._report("local", "unknown", f"Linux {platform.release()} ({platform.machine()})", checks, "linux")

    def diagnose(self, device: DeviceConfig, *, kernel_helper: str | None = None, target: str | None = None) -> CaptureReadiness:
        report = self.readiness(device)
        if target is not None:
            if kernel_helper is not None:
                raise BackendInvalidArgumentError("Use the kernel helper with target-free readiness")
            return self._diagnose_target(report, target)
        if report.status != "unknown":
            return report
        return self._diagnose_kernel(report, kernel_helper)

    def _diagnose_target(self, report: CaptureReadiness, target: str) -> CaptureReadiness:
        """Run the native attach preflight for one PID (Android: after the kernel gate)."""
        if report.status != "unknown":
            return report
        from .ebpf_native import NativeError, preflight

        serial = report.target if report.target_os == "android" else None
        checks = report.checks
        try:
            if serial:
                from .ebpf_android import kernel_checks

                checks += kernel_checks(serial)
            result = preflight(target, serial=serial) if serial else preflight(target)
        except NativeError as exc:
            return self._report(target, exc.status, str(exc), checks, report.target_os)
        detail = f"OpenSSL build ID {result['build_id']}, Linux {result['kernel']}"
        if transport := result.get("transport"):
            detail += f", transport: {transport}"
        if serial:
            detail = f"PID {target} on {serial}. {detail}"
        return CaptureReadiness(self.name, target, "ready", detail, True, checks, report.target_os)

    def _diagnose_kernel(self, report: CaptureReadiness, kernel_helper: str | None) -> CaptureReadiness:
        """Target-free kernel probe: an explicit or discovered helper, else bpftool."""
        explicit_helper = kernel_helper is not None
        if report.target_os == "android":
            command = ["adb", "-s", report.target, "shell", "bpftool"]
            if not explicit_helper:
                from .ebpf_android import kernel_checks
                from .ebpf_native import NativeError

                try:
                    report = replace(report, checks=(*report.checks, *kernel_checks(report.target)))
                except NativeError as exc:
                    return self._report(report.target, exc.status, str(exc), report.checks, "android")
        elif report.target_os == "linux":
            command = ["bpftool"]
            if not explicit_helper:
                kernel_helper = self._find_kernel_helper()
        else:
            return report
        checks, used_helper = self._probe_kernel_capabilities(command, kernel_helper, explicit_helper)
        status = self._status_from_checks(checks, report.status) if used_helper else report.status
        return replace(report, status=status, checks=(*report.checks, *checks))

    def _probe_kernel_capabilities(
        self, command: list[str], kernel_helper: str | None, explicit_helper: bool,
    ) -> tuple[tuple[ReadinessCheck, ...], bool]:
        """Probe with the helper when given; an unusable discovered helper falls back to bpftool."""
        if kernel_helper is None:
            return (self._probe_kernel(command),), False
        if explicit_helper and not re.fullmatch(r"/[A-Za-z0-9_./-]+", kernel_helper):
            raise BackendInvalidArgumentError("Use an absolute readiness helper path on the execution target")
        checks = self._probe_helper([*command[:-1], kernel_helper])
        if not explicit_helper and all(check.status == "setup_required" for check in checks):
            return (self._probe_kernel(command),), False
        return checks, True

    @staticmethod
    def _status_from_checks(checks: tuple[ReadinessCheck, ...], fallback: str) -> str:
        statuses = {check.status for check in checks}
        if statuses == {"verified"}:
            return "kernel_verified"
        if "denied" in statuses:
            return "permission_denied"
        if statuses == {"unsupported"}:
            return "unsupported"
        if statuses == {"setup_required"}:
            return "setup_required"
        return fallback

    @staticmethod
    def _find_kernel_helper() -> str | None:
        from .ebpf_native import _find_native_binary

        helper = _find_native_binary("fritap-ebpf-check-kernel", "dev/ebpf/build")
        return str(helper) if helper is not None else None

    @staticmethod
    def _probe_helper(command: list[str]) -> tuple[ReadinessCheck, ...]:
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=5)
            data = json.loads(result.stdout)
            outcomes = tuple(data[key] for key in ("map_errno", "program_errno"))
            if any(type(value) is not int or not 0 <= value <= 4095 for value in outcomes):
                raise ValueError("Invalid errno")
        except (FileNotFoundError, subprocess.CalledProcessError):
            return (ReadinessCheck("kernel_helper", "setup_required", "Could not run the target helper"),)
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            return (ReadinessCheck("kernel_helper", "unknown", "No valid helper result"),)
        return tuple(
            ReadinessCheck(name, status, os.strerror(code) if code else "succeeded")
            for name, code in zip(("bpf_map_create", "bpf_socket_filter_load"), outcomes)
            for status in (
                "verified" if code == 0 else
                "denied" if code in (errno.EPERM, errno.EACCES) else
                "unsupported" if code == errno.ENOSYS else "unknown",
            )
        )

    @staticmethod
    def _probe_kernel(command: list[str]) -> ReadinessCheck:
        name = "bpf_syscall"
        try:
            result = subprocess.run(
                [*command, "-j", "feature", "probe", "kernel", "unprivileged"],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except FileNotFoundError:
            return ReadinessCheck(name, "setup_required", "bpftool is unavailable")
        except subprocess.TimeoutExpired:
            return ReadinessCheck(name, "unknown", "bpftool timed out")
        except OSError:
            return ReadinessCheck(name, "unknown", "could not run bpftool")
        if result.returncode == 127:
            return ReadinessCheck(name, "setup_required", "bpftool is unavailable on the target")
        if result.returncode:
            if "permission" in result.stderr.lower() or "not permitted" in result.stderr.lower():
                return ReadinessCheck(name, "denied", "bpftool permission denied")
            return ReadinessCheck(name, "unknown", "bpftool could not complete the probe")
        try:
            report = json.loads(result.stdout)
            available = report["syscall_config"]["have_bpf_syscall"]
        except (ValueError, KeyError, TypeError):
            return ReadinessCheck(name, "unknown", "bpftool did not report syscall availability")
        if available is True:
            return ReadinessCheck(name, "observed", "bpftool detected the BPF syscall")
        return ReadinessCheck(name, "unknown", "bpftool could not establish syscall availability")

    @staticmethod
    def _linux_file_check(name: str, path: Path, *, read: bool = True) -> ReadinessCheck:
        try:
            if read:
                return ReadinessCheck(name, "observed", path.read_text().strip())
            path.stat()
            return ReadinessCheck(name, "observed", "present")
        except FileNotFoundError:
            return ReadinessCheck(name, "unknown", "not visible in the current environment")
        except PermissionError:
            return ReadinessCheck(name, "denied", "permission denied")
        except OSError:
            return ReadinessCheck(name, "unknown", "could not inspect")

    def _android_readiness(self, selector: bool | str) -> CaptureReadiness:
        target = str(selector) if selector is not True else "Android"
        try:
            if selector is True:
                target, problem = self._only_adb_serial()
                if problem:
                    return self._report(target, "setup_required", problem)
            state = self._adb_device_state(target)
            if state != "device":
                return self._report(target, "setup_required", f"ADB device state: {state or 'missing'}")
            android = self._adb(target, "shell", "getprop", "ro.build.version.sdk").strip()
            if not android.isdecimal():
                return self._report(target, "unsupported", "ADB target did not identify as Android")
            kernel = self._adb(target, "shell", "uname", "-rm").strip()
            return self._report(target, "unknown", f"Android API {android}, kernel {kernel}", target_os="android")
        except FileNotFoundError:
            return self._report(target, "setup_required", "Install Android platform-tools (adb)")
        except subprocess.TimeoutExpired:
            return self._report(target, "unknown", "ADB readiness check timed out")
        except (OSError, subprocess.CalledProcessError):
            return self._report(target, "unknown", "ADB readiness check failed")

    @staticmethod
    def _adb(serial: str, *args: str) -> str:
        from ..android import run_adb

        return run_adb(
            ["adb", "-s", serial, *args], check=True, capture_output=True, text=True, timeout=5,
        ).stdout

    @staticmethod
    def _adb_state_query(*args: str) -> subprocess.CompletedProcess:
        from ..android import run_adb

        return run_adb(["adb", *args], check=False, capture_output=True, text=True, timeout=5)

    @classmethod
    def _only_adb_serial(cls) -> tuple[str, str | None]:
        """Serial of the only ADB device, or ("Android", why one could not be chosen)."""
        result = cls._adb_state_query("get-serialno")
        serial = (result.stdout or "").strip()
        if result.returncode == 0 and serial and serial != "unknown":
            return serial, None
        error = (result.stderr or "").lower()
        if "more than one" in error:
            return "Android", "Select an Android ADB serial"
        state = _ADB_STATE_ERROR.search(error)
        if state:
            return "Android", f"ADB device state: {state.group(1)}"
        if "no devices" in error or "not found" in error:
            return "Android", "No Android ADB device found"
        raise subprocess.CalledProcessError(result.returncode, "adb get-serialno", result.stdout, result.stderr)

    @classmethod
    def _adb_device_state(cls, serial: str) -> str | None:
        """ADB state of *serial* (``device``, ``unauthorized``, ...); None when it is not connected."""
        result = cls._adb_state_query("-s", serial, "get-state")
        if result.returncode == 0:
            return (result.stdout or "").strip() or None
        error = (result.stderr or "").lower()
        state = _ADB_STATE_ERROR.search(error)
        if state:
            return state.group(1)
        if "not found" in error or "no devices" in error:
            return None
        raise subprocess.CalledProcessError(result.returncode, "adb get-state", result.stdout, result.stderr)

    def _report(self, target, status, detail, checks=(), target_os=None) -> CaptureReadiness:
        if status == "unknown":
            detail += ". Capture runtime capabilities have not been verified"
        return CaptureReadiness(self.name, target, status, detail, False, checks, target_os)


def select_capture_backend(name: str) -> CaptureBackend | None:
    """Resolve capture adapters while retaining the existing debugger paths."""
    selected = BackendName(name)
    if selected == BackendName.EBPF:
        return EbpfCaptureBackend()
    if selected == BackendName.FRIDA:
        return FridaCaptureBackend()
    return None


def create_ebpf_producer(config: FriTapConfig):
    """Validate the scope of the Linux plaintext adapter before opening outputs."""
    from .ebpf_native import EbpfCaptureProducer

    device = config.device
    if config.custom_hook_script:
        raise BackendInvalidArgumentError("eBPF does not support Frida custom scripts")
    if (device.host or device.spawn or device.enable_child_gating or device.enable_spawn_gating
            or device.spawn_gating_all or device.follow_exec
            or device.profile_capture_requested):
        raise BackendInvalidOperationError("eBPF capture requires attach to one PID")
    if (list(config.protocols) != ["tls"]
            or config.output.json_stream or config.output.live
            or config.output.socket_trace or config.output.owner_capture):
        raise BackendInvalidOperationError("eBPF supports TLS plaintext capture with callbacks, TAP, PCAP or JSON files")
    if config.output.full_capture and not config.output.pcap:
        raise BackendInvalidArgumentError("Full capture (-f) requires a PCAP destination (-p)")

    serial = None
    if device.mobile or device.device_id:
        from .ebpf_android import kernel_checks

        report = EbpfCaptureBackend().readiness(device)
        if report.status != "unknown" or report.target_os != "android":
            raise BackendInvalidOperationError(report.detail)
        if config.output.full_capture:
            raise BackendInvalidOperationError("Android eBPF supports plaintext capture output")
        serial = report.target
        kernel_checks(serial)
    elif platform.system() != "Linux":
        raise BackendInvalidOperationError("Local eBPF capture requires Linux")
    return EbpfCaptureProducer(config.target, keylog_path=config.output.keylog, serial=serial)


class LegacyCaptureProducer:
    """Adapt the existing instrumentation lifecycle to a core capture session.

    Legacy capture already sends records through MessageRouter and owns its
    configured output handlers. Keep that stream intact during the migration.
    """

    def __init__(self, logger: SSL_Logger, *, embedded: bool) -> None:
        self._logger = logger
        self._embedded = embedded
        self._completed = False

    def start(self, emit, finished) -> None:
        from threading import Thread

        self._logger.start_fritap_session()
        done = getattr(self._logger, "_done_event", None)
        if done is None:
            return

        def wait_for_termination():
            done.wait()
            self._completed = True
            finished(None)

        Thread(target=wait_for_termination, name="fritap-capture-completion", daemon=True).start()

    def stop(self) -> None:
        if self._embedded and not self._completed:
            self._logger.stop_fritap_session()


def create_legacy_capture_session(
    config: FriTapConfig, logger: SSL_Logger, *, embedded: bool,
) -> Session:
    """Coordinate startup while respecting the CLI's process-exit ownership."""
    from ..core import CoreController

    return CoreController().create_session(
        config, producer=LegacyCaptureProducer(logger, embedded=embedded),
        manage_capture_resources=False,
    )
