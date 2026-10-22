#!/usr/bin/env python3

"""
Reliable frida-server liveness probe.

Frida 17 trap: a USB Android device with NO frida-server running still
answers ``enumerate_processes()`` (the whole ADB process list),
``enumerate_applications()`` and ``query_system_parameters()`` via its
jailed (ADB-backed) fallback. Only ``attach()`` fails, with
``frida.ServerNotRunningError``. So "enumeration works" does NOT mean
"frida-server is running".

The reliable signal is ``query_system_parameters()["access"]``:
``"full"`` means a real (root) frida-server; ``"jailed"`` means either
the ADB fallback (no server) or a frida-gadget-injected app. The two
jailed cases are told apart by the process list: a Gadget reports
exactly one process (itself), the ADB fallback reports hundreds.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

ACCESS_FULL = "full"
ACCESS_JAILED = "jailed"
GADGET_PROCESS_COUNT = 1


class ServerState(Enum):
    """Outcome of probing a device for a usable frida endpoint."""

    RUNNING = "running"
    GADGET = "gadget"
    NOT_RUNNING = "not running"
    UNREACHABLE = "unreachable"


def is_attach_capable(state: ServerState) -> bool:
    """Return True if ``attach()`` is expected to work in *state*."""
    return state in (ServerState.RUNNING, ServerState.GADGET)


def probe_frida_server(device: Any) -> ServerState:
    """Classify *device*'s frida endpoint without attaching to anything.

    ``UNREACHABLE`` if the device is missing or cannot be queried at all.
    """
    if device is None:
        return ServerState.UNREACHABLE
    try:
        params = device.query_system_parameters()
    except Exception:
        return ServerState.UNREACHABLE
    return _classify_access(device, params.get("access"))


def _classify_access(device: Any, access: Any) -> ServerState:
    """Map the reported ``access`` level to a :class:`ServerState`."""
    if access == ACCESS_FULL:
        return ServerState.RUNNING
    if access is None:
        return _classify_without_access_key(device)
    if access == ACCESS_JAILED:
        return _classify_jailed(device)
    return ServerState.NOT_RUNNING


def _classify_without_access_key(device: Any) -> ServerState:
    """Fallback for older frida that does not report ``access``.

    Those versions predate the jailed ADB fallback, so a successful
    ``enumerate_processes()`` there does imply a live frida-server.
    """
    try:
        device.enumerate_processes()
    except Exception:
        return ServerState.NOT_RUNNING
    return ServerState.RUNNING


def _classify_jailed(device: Any) -> ServerState:
    """Distinguish a frida-gadget (one process) from the ADB fallback."""
    try:
        processes = device.enumerate_processes()
    except Exception:
        return ServerState.NOT_RUNNING
    if len(processes) == GADGET_PROCESS_COUNT:
        return ServerState.GADGET
    return ServerState.NOT_RUNNING
