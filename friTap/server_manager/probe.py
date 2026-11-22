#!/usr/bin/env python3

"""Reliable frida-server liveness probe.

Frida 17 trap: a USB Android device with NO frida-server still answers
``enumerate_processes()``, ``enumerate_applications()`` and
``query_system_parameters()`` via its jailed (ADB-backed) fallback; only ``attach()``
fails (``frida.ServerNotRunningError``). So working enumeration does not mean a server runs.

The reliable signal is ``query_system_parameters()["access"]``: ``"full"`` is a real
(root) frida-server; ``"jailed"`` is the ADB fallback or a frida-gadget app, told apart
by the process list (a Gadget reports exactly one process, the fallback hundreds).
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
    """Fallback for older frida without ``access``: it predates the jailed fallback, so successful enumeration implies a live server."""
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
