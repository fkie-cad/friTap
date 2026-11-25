"""Android process discovery service (``discover_processes``), wrapping :mod:`friTap.android_discovery`.

tlsLibHunter samples the device (it runs ``su`` commands over adb) to find the processes that carry an
app's TLS traffic: the app, its ``:process`` siblings, delegate apps, SDK sandboxes and shared system
processes. It is gated like a live capture. Process/package names and evidence come from the device,
so they are returned escaped and capped under ``untrusted``; the saved profile feeds
``start_capture(profile=...)``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from friTap import android_discovery
from friTap.agent_api.capture.manager import check_capture_allowed
from friTap.agent_api.capture.runner import LOCAL_DEVICE, USB_DEVICE
from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import ok
from friTap.agent_api.errors import ToolError
from friTap.agent_api.paths import resolve_under_root
from friTap.analysis._digest_shapes import safe_untrusted
from friTap.exit_codes import EXIT_RUNTIME_ERROR

PROCESS_DISCOVERY_SCHEMA = "fritap.process_discovery/1"
MIN_DISCOVERY_S = 1
MAX_DISCOVERY_S = 120
DEFAULT_DISCOVERY_S = 15
PROFILE_SUFFIX = ".json"
KNOWN_ROLES = (android_discovery.ROLE_TARGET, android_discovery.ROLE_SIBLING,
               android_discovery.ROLE_DELEGATE, android_discovery.ROLE_SDK_SANDBOX,
               android_discovery.ROLE_SHARED_SYSTEM)
UNKNOWN_ROLE = "unknown"
MAX_CANDIDATES = 200
MAX_EVIDENCE_ITEMS = 10
_MAX_NAME_CHARS = 120
_MAX_EVIDENCE_CHARS = 80
# adb serials: emulator-5556, 192.168.1.5:5555, R58M123ABC; never an option-like "-x".
_ADB_SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def discover_processes(params: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """Run tlsLibHunter discovery for ``params['package']`` and report the candidates."""
    package = _require_package(params["package"])
    check_capture_allowed(package, ctx)
    serial = adb_serial(params.get("device"))
    duration = params.get("duration_s", DEFAULT_DISCOVERY_S)
    profile_path = _profile_output_path(params.get("write_profile"), ctx)
    document = _run_discovery(serial, package, duration)
    doc = discovery_result(document, serial, package, duration)
    if profile_path is not None:
        write_profile_document(document, profile_path)
        doc["profile"] = str(profile_path)
    return ok(PROCESS_DISCOVERY_SCHEMA, doc)


def _require_package(package: str) -> str:
    if not android_discovery.is_valid_android_package(package):
        raise ToolError("package must be an Android package name", "bad_param", param="package",
                        hint="e.g. com.example.app (see list_apps identifiers)")
    return package


def adb_serial(device: Optional[str]) -> Optional[str]:
    """The adb serial for ``device``: ``None``/``usb`` = adb's default device; ``local`` is refused."""
    if not device or device == USB_DEVICE:
        return None
    if device == LOCAL_DEVICE:
        raise ToolError("process discovery needs an Android device", "bad_param", param="device",
                        hint="pass the adb serial (list_devices) or 'usb'")
    if not _ADB_SERIAL_RE.fullmatch(device):
        raise ToolError("device is not an adb serial", "bad_param", param="device",
                        hint="e.g. emulator-5556 or 192.168.1.5:5555")
    return device


def _profile_output_path(path: Optional[str], ctx: ToolContext) -> Optional[Path]:
    if path is None:
        return None
    try:
        return resolve_under_root(path, ctx.root, suffix=PROFILE_SUFFIX, must_exist=False)
    except ToolError as error:
        raise ToolError(f"write_profile: {error.error}", error.error_type, hint=error.hint,
                        param="write_profile") from error


def _run_discovery(serial: Optional[str], package: str, duration: int) -> dict:
    try:
        return android_discovery.discover_profile_document(serial, package, duration)
    except android_discovery.DiscoveryUnavailableError as exc:
        raise ToolError(str(exc), "missing_dependency", exit_code=EXIT_RUNTIME_ERROR,
                        hint="install tlsLibHunter with process discovery, or pass a saved "
                             "profile to start_capture(profile=...)") from exc
    except (android_discovery.DiscoveryFailedError, OSError, ValueError) as exc:
        raise ToolError(f"process discovery failed: {android_discovery.untrusted_excerpt(exc)}",
                        "discovery_failed", exit_code=EXIT_RUNTIME_ERROR,
                        hint="check adb connectivity and root (su) on the device") from exc


def discovery_result(document: dict, serial: Optional[str], package: str,
                     duration: int) -> dict[str, Any]:
    """The tool result for a validated profile document (device strings under ``untrusted``)."""
    raw = list(document.get("candidates") or ())
    candidates = [candidate_row(cand) for cand in raw[:MAX_CANDIDATES]]
    return {"device": serial, "package": package, "duration_s": duration,
            "total": len(raw), "candidates": candidates,
            "untrusted": {"gate_packages": [_name(pkg) for pkg in
                                            document.get("gate_packages") or ()]}}


def candidate_row(cand: dict) -> dict[str, Any]:
    """One candidate: trusted shape (pid, role, attributable) + escaped device strings."""
    role = cand.get("role") if cand.get("role") in KNOWN_ROLES else UNKNOWN_ROLE
    row: dict[str, Any] = {
        "pid": int(cand["pid"]), "role": role,
        "attributable": role != android_discovery.ROLE_SHARED_SYSTEM,
        "untrusted": {"process": _name(cand.get("process")), "package": _name(cand.get("package")),
                      "evidence": _evidence(cand.get("evidence"))}}
    if isinstance(cand.get("confirmed"), bool):
        row["confirmed"] = cand["confirmed"]
    return row


def _name(value: object) -> str:
    return safe_untrusted(value, limit=_MAX_NAME_CHARS)


def _evidence(items: object) -> list[str]:
    if not isinstance(items, (list, tuple)):
        return []
    return [safe_untrusted(item, limit=_MAX_EVIDENCE_CHARS) for item in items[:MAX_EVIDENCE_ITEMS]]


def write_profile_document(document: dict, path: Path) -> None:
    """Save the discovered profile as a ``--profile`` JSON file (parent dirs created)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")


__all__ = ["discover_processes", "discovery_result", "candidate_row", "adb_serial",
           "write_profile_document", "PROCESS_DISCOVERY_SCHEMA", "MIN_DISCOVERY_S",
           "MAX_DISCOVERY_S", "DEFAULT_DISCOVERY_S"]
