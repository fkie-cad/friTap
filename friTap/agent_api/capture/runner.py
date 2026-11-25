"""Build the friTap command line for a live capture run as a subprocess.

A capture is never run in-process: ``SSL_Logger`` teardown ends in ``os._exit``, which would kill an
MCP/REST server. :func:`build_argv` (pure) turns a :class:`CaptureRequest` into the argv of
``python -m friTap.friTap`` with machine-friendly flags (``-j -`` JSONL on stdout, ``--tap``,
``--duration``, ``--non-interactive``, ``-q``); :func:`validate_request` holds the catalog-dependent checks.

The ``ebpf`` backend attaches to one PID and only writes files (no ``-j -`` stream, no ``-s``,
protocol ``tls`` only): its status comes from the process exit and the ``.tap`` file size.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from friTap.agent_api import protocol_catalog
from friTap.agent_api.errors import ToolError
from friTap.agent_api.protocol_catalog import CAPTURE_MODES

DEFAULT_CAPTURE_MODE = "plaintext"
MIN_DURATION_S = 1
MAX_DURATION_S = 3600
DEFAULT_DURATION_S = 60
#: Upper bound on ``also_package`` entries of one capture.
MAX_ALSO_PACKAGES = 16

LOCAL_DEVICE = "local"
USB_DEVICE = "usb"
AUTO_PROTOCOL = "auto"

FRIDA_BACKEND = "frida"
EBPF_BACKEND = "ebpf"
CAPTURE_BACKENDS = (FRIDA_BACKEND, EBPF_BACKEND)
#: The only protocol (and the default) of an eBPF capture.
EBPF_PROTOCOLS = ("tls",)
#: eBPF writes plaintext only: no keylog (``keys``/``full`` would report an empty keys.log).
EBPF_CAPTURE_MODES = ("plaintext",)

TAP_NAME = "capture.tap"
KEYLOG_NAME = "keys.log"
PCAP_NAME = "plain.pcap"

_KEY_MODES = frozenset({"keys", "full"})


@dataclass(frozen=True)
class CaptureRequest:
    """Everything needed to launch one capture.

    ``args`` go after ``--`` for a spawned executable. ``device``: ``None``/``"local"`` = local system,
    ``"usb"`` = first USB device, else a Frida device id (``-m``). ``host`` is a remote ``ip:port``
    (``-H``). Empty ``protocols`` = ``--protocol auto``. ``capture`` (``keys``/``plaintext``/``full``) is
    what is written to disk. ``follow_exec`` is off by default: Frida child gating can crash fork children.
    ``profile`` (a tlsLibHunter discovery profile path) and ``also_packages`` map onto
    ``--profile`` / ``--also-package`` (Android device captures only).
    """

    target: str
    session_dir: Path
    args: tuple[str, ...] = ()
    device: Optional[str] = None
    host: Optional[str] = None
    spawn: bool = True
    protocols: tuple[str, ...] = ()
    protocol_options: Mapping[str, Any] = field(default_factory=dict)
    capture: str = DEFAULT_CAPTURE_MODE
    duration_s: int = DEFAULT_DURATION_S
    follow_exec: bool = False
    anti_root: bool = False
    backend: str = FRIDA_BACKEND
    profile: Optional[str] = None
    also_packages: tuple[str, ...] = ()

    @property
    def tap_path(self) -> Path:
        return self.session_dir / TAP_NAME

    @property
    def keylog_path(self) -> Optional[Path]:
        return self.session_dir / KEYLOG_NAME if self.capture in _KEY_MODES else None

    @property
    def pcap_path(self) -> Optional[Path]:
        return self.session_dir / PCAP_NAME if self.capture == "full" else None


def fritap_command() -> list[str]:
    """The interpreter + module prefix that runs the friTap CLI."""
    return [sys.executable, "-m", "friTap.friTap"]


def build_argv(req: CaptureRequest, command: Optional[list[str]] = None) -> list[str]:
    """Return the full argv of the capture subprocess (pure)."""
    argv = list(command if command is not None else fritap_command())
    if req.backend == EBPF_BACKEND:
        return argv + _ebpf_argv(req)
    argv += _device_flags(req.device, req.host)
    argv += ["-s"] if req.spawn else []
    argv += ["--protocol", ",".join(req.protocols) or AUTO_PROTOCOL]
    argv += _output_flags(req)
    argv += ["--duration", str(req.duration_s), "--non-interactive", "-q", "-j", "-"]
    argv += ["--follow-exec"] if req.follow_exec else []
    argv += ["--anti_root"] if req.anti_root else []
    argv += _option_flags(req.protocol_options)
    argv += _profile_flags(req)
    return argv + ["--", req.target, *req.args]


def _profile_flags(req: CaptureRequest) -> list[str]:
    """``--profile`` / repeated ``--also-package`` of an Android multi-process capture."""
    flags = ["--profile", req.profile] if req.profile else []
    for package in req.also_packages:
        flags += ["--also-package", package]
    return flags


def _ebpf_argv(req: CaptureRequest) -> list[str]:
    """eBPF attach flags: file outputs only (the CLI rejects ``-j -``), never ``-s``."""
    argv = ["--backend", EBPF_BACKEND, *_device_flags(req.device, req.host)]
    argv += ["--protocol", ",".join(req.protocols or EBPF_PROTOCOLS)]
    argv += _output_flags(req)
    argv += ["--duration", str(req.duration_s), "--non-interactive", "-q"]
    return argv + ["--", req.target]


def device_selector(device: Optional[str]) -> Union[bool, str]:
    """The one mapping of a tool's ``device`` string: False = local, True = first USB, else an id.

    Same convention as ``friTap.commands.devices.ListingArgs.device``.
    """
    if not device or device == LOCAL_DEVICE:
        return False
    if device == USB_DEVICE:
        return True
    return device


def _device_flags(device: Optional[str], host: Optional[str]) -> list[str]:
    if host:
        return ["-H", host]
    selector = device_selector(device)
    if selector is False:
        return []
    return ["-m"] if selector is True else ["-m", selector]


def _output_flags(req: CaptureRequest) -> list[str]:
    flags = ["--tap", str(req.tap_path)]
    if req.keylog_path is not None:
        flags += ["-k", str(req.keylog_path)]
    if req.pcap_path is not None:
        flags += ["-p", str(req.pcap_path)]
    return flags


def _option_flags(options: Mapping[str, Any]) -> list[str]:
    if not options:
        return []
    return list(protocol_catalog.options_to_cli_flags(dict(options)))


def session_keylog_files(session_dir: Path) -> list[Path]:
    """Existing keylog files of a session: ``keys.log`` and the per-protocol split.

    With several key-emitting protocols friTap splits ``-k keys.log`` into ``keys.<proto>.log``, so
    the base file may not exist. Candidate names come from the output factory's own rule
    (``active_keylog_paths`` under ``auto``, the superset), so they cannot drift from what was written.
    """
    base = session_dir / KEYLOG_NAME
    candidates = [base, *sorted(_split_keylog_paths(base))]
    return [path for path in candidates if path.is_file()]


def _split_keylog_paths(base: Path) -> set[Path]:
    from friTap.output.factory import active_keylog_paths
    from friTap.protocols.registry import create_default_registry

    paths = active_keylog_paths(str(base), [AUTO_PROTOCOL], create_default_registry())
    return {Path(path) for path in paths.values()} - {base}


def validate_request(req: CaptureRequest) -> None:
    """Reject requests the CLI would refuse, with an actionable ToolError."""
    if not req.target.strip():
        raise ToolError("target must not be empty", "bad_param", param="target")
    if req.capture not in CAPTURE_MODES:
        raise ToolError(f"unknown capture mode {req.capture!r}", "bad_param",
                        hint=f"one of: {', '.join(CAPTURE_MODES)}", param="capture")
    if not MIN_DURATION_S <= req.duration_s <= MAX_DURATION_S:
        raise ToolError(f"duration_s must be {MIN_DURATION_S}..{MAX_DURATION_S}",
                        "bad_param", param="duration_s")
    for name in ("device", "host"):
        value = getattr(req, name)
        # Passed as the value of -m/-H: a leading '-' would be parsed as another
        # friTap option (e.g. --custom_script=..., -p outside the sandbox root).
        if value and value.startswith("-"):
            raise ToolError(f"{name} must not start with '-'", "bad_param",
                            hint="pass a device id / ip:port", param=name)
    if req.args and not req.spawn:
        raise ToolError("args are only used when spawning", "bad_param",
                        hint="set spawn=true or drop args", param="args")
    if req.backend not in CAPTURE_BACKENDS:
        raise ToolError(f"unknown backend {req.backend!r}", "bad_param",
                        hint=f"one of: {', '.join(CAPTURE_BACKENDS)}", param="backend")
    if req.backend == EBPF_BACKEND:
        _validate_ebpf_request(req)
    _validate_profile_request(req)
    if req.protocols or req.protocol_options:
            protocol_catalog.validate_protocol_options(list(req.protocols), dict(req.protocol_options))


def _validate_ebpf_request(req: CaptureRequest) -> None:
    """eBPF attaches to one local/ADB PID and captures TLS plaintext only."""
    _reject_ebpf(req.spawn, "spawn", "eBPF capture attaches to a running process",
                 "set spawn=false (or omit it) and pass the numeric PID as target")
    if not _is_pid(req.target):
        raise ToolError("eBPF capture requires one positive numeric PID as target", "bad_param",
                        hint="find the PID with list_apps / ps", param="target")
    unsupported = [p for p in req.protocols if p not in EBPF_PROTOCOLS]
    _reject_ebpf(unsupported, "protocols", f"eBPF capture does not support {', '.join(unsupported)}",
                 "use protocols=[\"tls\"] (the default) or backend=frida")
    _reject_ebpf(req.capture not in EBPF_CAPTURE_MODES, "capture",
                 f"eBPF capture does not write key material (capture={req.capture!r})",
                 "use capture=plaintext or backend=frida")
    _reject_ebpf(req.host, "host", "eBPF capture does not support remote hosts",
                 "use device (ADB serial) or the local system")
    for name in ("follow_exec", "anti_root", "protocol_options", "profile"):
        _reject_ebpf(getattr(req, name), name, f"eBPF capture does not support {name}",
                     "drop it or use backend=frida")
    _reject_ebpf(req.also_packages, "also_package", "eBPF capture does not support also_package",
                 "drop it or use backend=frida")


def _validate_profile_request(req: CaptureRequest) -> None:
    """``profile``/``also_package`` need an Android device (``-m``); packages must be well-formed."""
    from friTap.android_discovery import is_valid_android_package, untrusted_excerpt

    requested = [name for name, value in (("profile", req.profile),
                                          ("also_package", req.also_packages)) if value]
    if not requested:
        return
    if req.host or device_selector(req.device) is False:
        raise ToolError(f"{requested[0]} needs an Android device capture", "bad_param",
                        hint="set device to 'usb' or the device id (not local / host)",
                        param=requested[0])
    if len(req.also_packages) > MAX_ALSO_PACKAGES:
        raise ToolError(f"at most {MAX_ALSO_PACKAGES} also_package entries", "bad_param",
                        param="also_package")
    for package in req.also_packages:
        if not is_valid_android_package(package):
            raise ToolError(f"also_package: invalid Android package name "
                            f"{untrusted_excerpt(package)!r}", "bad_param", param="also_package",
                            hint="e.g. com.google.android.googlequicksearchbox")


def _reject_ebpf(condition: Any, param: str, message: str, hint: str) -> None:
    if condition:
        raise ToolError(message, "bad_param", hint=hint, param=param)


def _is_pid(target: str) -> bool:
    return target.isascii() and target.isdigit() and 0 < int(target) <= 2**31 - 1


__all__ = [
    "CaptureRequest", "build_argv", "validate_request", "fritap_command", "session_keylog_files",
    "device_selector", "CAPTURE_BACKENDS", "FRIDA_BACKEND", "EBPF_BACKEND", "EBPF_PROTOCOLS",
    "CAPTURE_MODES", "DEFAULT_CAPTURE_MODE", "MIN_DURATION_S", "MAX_DURATION_S",
    "DEFAULT_DURATION_S", "LOCAL_DEVICE", "USB_DEVICE", "TAP_NAME", "KEYLOG_NAME",
]
