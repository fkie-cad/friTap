#!/usr/bin/env python3
"""Minimal frida attach / NSS-keylog helpers for the standalone calibrate tool.

Vendored (ported verbatim) from ``research/memory_scan_lsass/schannel_secret_scan.py``
so ``dev/schannel_calibrate/`` is a self-contained developer tool with no import
into the shipped ``friTap`` package. Only the symbols ``schannel_calibrate.py``
needs are here: the fatal :class:`ProfileError`, the NSS keylog line parser, the
append-only dedup file, the frida device/pid/path resolution, and the
attach/rpc plumbing. frida is imported lazily so ``--help`` works without it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


class ProfileError(Exception):
    """A fatal setup error: the run must not start, or must not continue.

    Covers a missing frida install, a process name that does not resolve, and a
    target that cannot be attached. ``__main__`` catches exactly this and exits.
    """


# --------------------------------------------------------------------------- #
# NSS keylog helpers
# --------------------------------------------------------------------------- #

def is_hex_blob(text: str) -> bool:
    """True for an even-length run of hex digits (a whole number of bytes)."""
    return bool(text) and len(text) % 2 == 0 and _HEX_RE.fullmatch(text) is not None


def parse_keylog_line(line: str) -> tuple[str, str, str] | None:
    """Parse an NSS keylog line into (label, client_random, secret), else None.

    Returns None for blank lines, ``#`` comments and anything that is not three
    whitespace-separated fields with hex in the last two.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    fields = stripped.split()
    if len(fields) != 3:
        return None
    label, client_random, secret = fields
    if not is_hex_blob(client_random) or not is_hex_blob(secret):
        return None
    return label.upper(), client_random.lower(), secret.lower()


# --------------------------------------------------------------------------- #
# Append-only dedup file (the oracle keylog writer)
# --------------------------------------------------------------------------- #

def _read_existing_lines(path: Path) -> set[str]:
    """Seed the dedup set from a previous run so re-running only appends news."""
    if not path.exists():
        return set()
    return {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}


class DedupLineFile:
    """Append-only text file that writes each distinct line at most once.

    Flushing after every line is deliberate: the interesting runs are the ones
    that end with Ctrl-C or with the target being killed.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seen = _read_existing_lines(path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("a", encoding="utf-8")

    def add(self, line: str) -> bool:
        """Write the line unless it was already written; True when it was new."""
        if line in self._seen:
            return False
        self._seen.add(line)
        self._handle.write(line + "\n")
        self._handle.flush()
        return True

    def close(self) -> None:
        self._handle.close()

    def __len__(self) -> int:
        return len(self._seen)


# --------------------------------------------------------------------------- #
# frida device / pid / path resolution and attach
# --------------------------------------------------------------------------- #

def _import_frida():
    """Import frida on first use (deferred so ``--help`` works without it)."""
    try:
        import frida
    except ImportError as exc:
        raise ProfileError("frida is not installed (pip install frida)") from exc
    return frida


def open_device(spec: str):
    """Resolve --device: the three usual aliases, or an explicit frida device id."""
    frida = _import_frida()
    aliases = {
        "usb": frida.get_usb_device,
        "local": frida.get_local_device,
        "remote": frida.get_remote_device,
    }
    if spec in aliases:
        return aliases[spec]()
    return frida.get_device(spec)


def resolve_pid(device, pid: int | None, name: str | None) -> int:
    """Return the pid to attach to, resolving --name against the device.

    An exact name match wins outright; a genuinely ambiguous name is an error
    rather than a guess (attaching to the wrong process scans nothing useful).
    """
    if pid is not None:
        return pid
    processes = device.enumerate_processes()
    exact = [p for p in processes if p.name == name]
    if len(exact) == 1:
        return exact[0].pid
    matches = [p for p in processes if name and name.lower() in p.name.lower()]
    if not matches:
        raise ProfileError(f"no process on the device matches '{name}'")
    if len(matches) > 1:
        listing = ", ".join(f"{p.name}({p.pid})" for p in matches)
        raise ProfileError(f"'{name}' is ambiguous, pass --pid: {listing}")
    print(f"[*] '{name}' resolved to {matches[0].name} pid {matches[0].pid}", file=sys.stderr)
    return matches[0].pid


def resolve_path(candidate: str) -> Path:
    """Resolve a path against the cwd, then against this script's directory."""
    path = Path(candidate)
    if path.is_absolute() or path.exists():
        return path
    fallback = SCRIPT_DIR / candidate
    return fallback if fallback.exists() else path


def attach_agent(args, on_message: Callable[..., None]):
    """Attach to the target and load ``args.agent``; returns (session, script)."""
    device = open_device(args.device)
    pid = resolve_pid(device, args.pid, args.name)
    session = device.attach(pid)
    agent_path = resolve_path(args.agent)
    script = session.create_script(agent_path.read_text(encoding="utf-8"))
    script.set_log_handler(
        lambda level, text: print(f"[agent] {text}", file=sys.stderr, flush=True))
    script.on("message", on_message)
    script.load()
    print(f"[*] attached to pid {pid}, loaded {agent_path}", file=sys.stderr)
    return session, script


def rpc_call(script, name: str, *call_args: Any, alias: str | None = None) -> Any:
    """Call one agent rpc export by name (frida snake-cases JS export names)."""
    exports = script.exports_sync
    export = getattr(exports, name, None)
    if export is None and alias is not None:
        export = getattr(exports, alias, None)
    if export is None:
        raise ProfileError(f"the agent does not export {name}()")
    return export(*call_args)
