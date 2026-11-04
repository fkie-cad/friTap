"""
Build the friTap command line for a live capture run as a subprocess.

A capture is never run in-process: ``SSL_Logger`` teardown ends in
``os._exit``, which would kill an MCP/REST server. :func:`build_argv` turns a
:class:`CaptureRequest` into the argv of ``python -m friTap.friTap`` with the
machine-friendly flags (``-j -`` JSONL on stdout, ``--tap``, ``--duration``,
``--non-interactive``, ``-q``). It is pure; :func:`validate_request` holds the
checks that need the protocol catalog.
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

LOCAL_DEVICE = "local"
USB_DEVICE = "usb"
AUTO_PROTOCOL = "auto"

TAP_NAME = "capture.tap"
KEYLOG_NAME = "keys.log"
PCAP_NAME = "plain.pcap"

_KEY_MODES = frozenset({"keys", "full"})


@dataclass(frozen=True)
class CaptureRequest:
    """Everything needed to launch one capture.

    Attributes:
        target: App identifier, process name, pid or executable path.
        session_dir: Directory receiving the tap/keylog/pcap/stderr files.
        args: Arguments for a spawned executable (placed after ``--``).
        device: ``None``/``"local"`` = local system, ``"usb"`` = first USB
            device, anything else = a Frida device id (``-m <id>``).
        host: Remote frida-server ``ip:port`` (``-H``).
        spawn: Spawn the target instead of attaching.
        protocols: Protocols to hook; empty = ``--protocol auto``.
        protocol_options: Per-protocol options (see ``protocol_catalog``).
        capture: ``keys`` | ``plaintext`` | ``full`` (what is written to disk).
        duration_s: Capture stops cleanly after this many seconds.
        follow_exec: Spawn mode: follow the target across ``exec()``.
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
    follow_exec: bool = True

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
    argv += _device_flags(req.device, req.host)
    argv += ["-s"] if req.spawn else []
    argv += ["--protocol", ",".join(req.protocols) or AUTO_PROTOCOL]
    argv += _output_flags(req)
    argv += ["--duration", str(req.duration_s), "--non-interactive", "-q", "-j", "-"]
    argv += [] if req.follow_exec else ["--no-follow-exec"]
    argv += _option_flags(req.protocol_options)
    return argv + ["--", req.target, *req.args]


def device_selector(device: Optional[str]) -> Union[bool, str]:
    """The one mapping of a tool's ``device`` string: False = local, True = first USB, else an id.

    Same convention as :attr:`friTap.commands.devices.ListingArgs.device`.
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

    With several key-emitting protocols (``--protocol auto``/``all`` or a
    multi-protocol selection) friTap splits ``-k keys.log`` into
    ``keys.<proto>.log`` (e.g. ``keys.tls.log``), so the base file may not
    exist. The candidate names come from the output factory's own rule
    (:func:`friTap.output.factory.active_keylog_paths` under ``auto``, the
    superset of every selection), so they cannot drift from what was written.
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
    if req.protocols or req.protocol_options:
            protocol_catalog.validate_protocol_options(list(req.protocols), dict(req.protocol_options))


__all__ = [
    "CaptureRequest", "build_argv", "validate_request", "fritap_command", "session_keylog_files",
    "device_selector",
    "CAPTURE_MODES", "DEFAULT_CAPTURE_MODE", "MIN_DURATION_S", "MAX_DURATION_S",
    "DEFAULT_DURATION_S", "LOCAL_DEVICE", "USB_DEVICE", "TAP_NAME", "KEYLOG_NAME",
]
