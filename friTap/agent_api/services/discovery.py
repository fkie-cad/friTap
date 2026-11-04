"""
Device / app discovery services, wrapping :mod:`friTap.commands.devices`.

Device selection matches the capture tools: ``None``/``"local"`` = local
system, ``"usb"`` = first USB device, anything else = a Frida device id;
``host`` (``ip:port``) selects a remote frida-server and wins over ``device``.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from friTap.agent_api.capture.runner import device_selector
from friTap.agent_api.envelope import ok, paginate
from friTap.commands import devices as listing

DEVICES_SCHEMA = listing.DEVICES_SCHEMA
APPS_SCHEMA = listing.APPS_SCHEMA
#: How long a later page (``cursor`` given) reuses the first page's app snapshot.
APPS_SNAPSHOT_TTL_S = 30.0


def list_devices() -> dict[str, Any]:
    return ok(DEVICES_SCHEMA, {"devices": listing.list_devices()})


class AppSnapshots:
    """Per ``(device, host, running)`` app listing, reused while paging.

    The first page (no cursor) always enumerates the device; later pages reuse
    that snapshot for up to ``ttl`` seconds instead of one frida-server
    enumeration per page (and page through a consistent list).
    """

    def __init__(self, ttl: float = APPS_SNAPSHOT_TTL_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._snapshots: dict[tuple, tuple[float, dict, list]] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple, fresh: bool, enumerate_apps: Callable[[], tuple[dict, list]]):
        now = self._clock()
        with self._lock:
            cached = self._snapshots.get(key)
        if not fresh and cached is not None and now - cached[0] <= self.ttl:
            return cached[1], cached[2]
        device, entries = enumerate_apps()
        with self._lock:
            self._snapshots[key] = (now, device, entries)
        return device, entries


app_snapshots = AppSnapshots()


def list_apps(device: Optional[str] = None, host: Optional[str] = None,
              running: bool = False, limit: int = 200,
              cursor: Optional[str] = None) -> dict[str, Any]:
    def enumerate_apps() -> tuple[dict, list]:
        args = listing.ListingArgs(command="apps", device=device_selector(device),
                                   host=host, running_only=running)
        frida_device = listing.resolve_device(args)
        return (listing.describe_device(frida_device),
                listing.list_apps(frida_device, running_only=running))

    described, entries = app_snapshots.get((device, host, running), not cursor, enumerate_apps)
    page, next_cursor = paginate(entries, limit, cursor)
    doc: dict[str, Any] = {"device": described, "total": len(entries), "apps": page}
    if next_cursor is not None:
        doc["next_cursor"] = next_cursor
    return ok(APPS_SCHEMA, doc)


__all__ = ["list_devices", "list_apps", "AppSnapshots", "app_snapshots", "APPS_SNAPSHOT_TTL_S"]
