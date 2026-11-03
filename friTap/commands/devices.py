"""
``fritap devices`` / ``fritap apps`` — list Frida devices and targets.

Script/AI-agent friendly discovery before a capture::

    fritap devices [--json]
    fritap apps [-m [ID] | --device ID | -H HOST] [--running] [--json]

``apps`` lists the device's installed applications (name, identifier, pid; pid
0 = not running). Devices that expose no applications (a desktop's local
device) list their running processes instead (``kind: "process"``).

Dispatch guard (see ``friTap.friTap._dispatch_special_mode``): ``devices`` /
``apps`` is only treated as this subcommand when EVERY following token is one
of the options above. Anything else (``fritap apps -k keys.log``,
``fritap devices -v``) falls through to a normal capture of a process with
that name, and so does any invocation that puts an option first
(``fritap -m apps``).

Errors with ``--json`` are printed as ``{"error": ..., "error_type": ...,
"exit_code": ...}`` on stdout, with the exit codes of :mod:`friTap.exit_codes`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional

from friTap.exit_codes import EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR

LISTING_COMMANDS = ("devices", "apps")
DEVICES_SCHEMA = "fritap.devices/1"
APPS_SCHEMA = "fritap.apps/1"

_DEVICE_FLAGS = ("-m", "--mobile", "--device")
_HOST_FLAGS = ("-H", "--host")
_HELP_FLAGS = ("-h", "--help")

USAGE = (
    "usage: fritap devices [--json]\n"
    "       fritap apps [-m [ID] | --device ID | -H HOST] [--running] [--json]\n"
)


class ListingUsageError(ValueError):
    """Invalid ``devices``/``apps`` arguments (exit code 2)."""


@dataclass
class ListingArgs:
    command: str
    as_json: bool = False
    running_only: bool = False
    device: "bool | str" = False  # False = local, True = first USB, str = id
    host: Optional[str] = None
    show_help: bool = False


def _takes_value(tokens: List[str], index: int) -> bool:
    return index + 1 < len(tokens) and not tokens[index + 1].startswith("-")


# Hand-rolled (not argparse) so any unknown token makes "devices"/"apps" a capture target.
def parse_listing_args(command: str, tokens: List[str]) -> ListingArgs:
    """Parse the tokens after ``devices``/``apps``.

    Raises :class:`ListingUsageError` on a token that is not a listing option,
    which the dispatcher reads as "this is a capture target, not a subcommand".
    """
    args = ListingArgs(command=command)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--json":
            args.as_json = True
        elif token in _HELP_FLAGS:
            args.show_help = True
        elif token == "--running" and command == "apps":
            args.running_only = True
        elif token in _DEVICE_FLAGS and command == "apps":
            args.device = True
            if _takes_value(tokens, index):
                index += 1
                args.device = tokens[index]
        elif token in _HOST_FLAGS and command == "apps":
            if not _takes_value(tokens, index):
                raise ListingUsageError(f"{token} requires <ip:port>")
            index += 1
            args.host = tokens[index]
        else:
            raise ListingUsageError(f"unrecognized argument: {token}")
        index += 1
    return args


def is_listing_invocation(argv: List[str]) -> bool:
    """True when ``argv`` (``sys.argv``) is ``fritap devices|apps [listing opts]``."""
    if len(argv) < 2 or argv[1] not in LISTING_COMMANDS:
        return False
    try:
        parse_listing_args(argv[1], argv[2:])
    except ListingUsageError:
        return False
    return True


# ---------------------------------------------------------------------------
# Device access via the instrumentation backend (error wrapping + the same
# device-selection rules as a capture); a function so tests can mock it.
# ---------------------------------------------------------------------------

def _backend():
    from friTap.backends import get_backend
    return get_backend()


def describe_device(device) -> dict:
    return {
        "id": getattr(device, "id", ""),
        "name": getattr(device, "name", ""),
        "type": getattr(device, "type", ""),
    }


def list_devices() -> List[dict]:
    return [describe_device(d) for d in _backend().enumerate_devices()]


def resolve_device(args: ListingArgs):
    return _backend().get_device(mobile=args.device, host=args.host)


def _app_entry(app) -> dict:
    return {"name": app.name, "identifier": app.identifier,
            "pid": int(getattr(app, "pid", 0) or 0), "kind": "app"}


def _process_entry(process) -> dict:
    return {"name": process.name, "identifier": None,
            "pid": int(process.pid), "kind": "process"}


def _dedupe_key(entry: dict):
    """Apps are unique by identifier, processes by pid."""
    if entry["kind"] == "app" and entry["identifier"]:
        return ("app", entry["identifier"])
    return ("process", entry["pid"], entry["name"])


def _richness(entry: dict) -> tuple:
    """How informative an entry is: a running one (pid) beats a stopped one."""
    return (bool(entry["pid"]), bool(entry["name"]))


def dedupe_entries(entries: List[dict]) -> List[dict]:
    """Drop duplicates (Frida can enumerate one app twice), keeping the most
    informative entry per identifier/pid, in first-seen order."""
    best: dict = {}
    for entry in entries:
        key = _dedupe_key(entry)
        if key not in best or _richness(entry) > _richness(best[key]):
            best[key] = entry
    return list(best.values())


def list_apps(device, running_only: bool = False) -> List[dict]:
    """Installed apps of *device* (deduplicated); its processes when it exposes no apps."""
    try:
        entries = [_app_entry(a) for a in device.enumerate_applications()]
    except Exception:  # noqa: BLE001 - e.g. not supported on this device type
        entries = []
    if not entries:
        entries = [_process_entry(p)
                   for p in _backend().enumerate_processes(device)]
    entries = dedupe_entries(entries)
    if running_only:
        entries = [e for e in entries if e["pid"]]
    return sorted(entries, key=lambda e: (e["pid"] == 0, e["name"].lower()))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _print_json(document: dict, out) -> None:
    out.write(json.dumps(document, ensure_ascii=False) + "\n")


def _render_devices_table(devices: List[dict]) -> str:
    lines = [f"{'ID':<28} {'TYPE':<8} NAME"]
    lines += [f"{d['id']:<28} {d['type']:<8} {d['name']}" for d in devices]
    return "\n".join(lines) + "\n"


def _render_apps_table(entries: List[dict]) -> str:
    lines = [f"{'PID':>7}  {'NAME':<32} IDENTIFIER"]
    for e in entries:
        pid = str(e["pid"]) if e["pid"] else "-"
        lines.append(f"{pid:>7}  {e['name']:<32} {e['identifier'] or ''}")
    return "\n".join(lines) + "\n"


def _run_devices(args: ListingArgs, out) -> None:
    devices = list_devices()
    if args.as_json:
        _print_json({"schema": DEVICES_SCHEMA, "devices": devices}, out)
    else:
        out.write(_render_devices_table(devices))


def _run_apps(args: ListingArgs, out) -> None:
    device = resolve_device(args)
    entries = list_apps(device, running_only=args.running_only)
    if args.as_json:
        _print_json({"schema": APPS_SCHEMA, "device": describe_device(device),
                     "apps": entries}, out)
    else:
        out.write(_render_apps_table(entries))


_RUNNERS: dict[str, Callable] = {"devices": _run_devices, "apps": _run_apps}


def _error_type(error: Exception) -> str:
    """The underlying (e.g. frida) class name, not the backend's wrapper type."""
    return type(getattr(error, "original_exception", None) or error).__name__


def _report_error(as_json: bool, error: Exception, exit_code: int, out, err) -> int:
    if as_json:
        _print_json({"error": str(error) or type(error).__name__,
                     "error_type": _error_type(error),
                     "exit_code": exit_code}, out)
    else:
        err.write(f"fritap: error: {error}\n")
    return exit_code


def run_listing_cli(command: str, tokens: List[str], out=None, err=None) -> int:
    """Entry point for ``fritap devices|apps``; returns the process exit code."""
    out = out or sys.stdout
    err = err or sys.stderr
    as_json = "--json" in tokens
    try:
        args = parse_listing_args(command, tokens)
    except ListingUsageError as e:
        return _report_error(as_json, e, EXIT_USAGE_ERROR, out, err)
    if args.show_help:
        out.write(USAGE)
        return EXIT_OK
    try:
        _RUNNERS[command](args, out)
    except Exception as e:  # noqa: BLE001 - backend errors -> structured error
        return _report_error(args.as_json, e, EXIT_RUNTIME_ERROR, out, err)
    return EXIT_OK
