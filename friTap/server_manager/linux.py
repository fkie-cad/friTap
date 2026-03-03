#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Linux frida-server manager.

Local Linux targets do not need frida-server (Frida injects directly).
Remote Linux targets require server deployment and management.
"""

from __future__ import annotations

import platform
from typing import Any

from .base import LocalUnixServerManager

_ARCH_MAP = {
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "armv7l": "arm",
    "i686": "x86",
}


class LinuxServerManager(LocalUnixServerManager):
    """Manage frida-server for Linux targets."""

    @property
    def platform_name(self) -> str:
        return "linux"

    def detect_arch(self, device: Any = None) -> str:
        if device:
            try:
                params = device.query_system_parameters()
                return params.get("arch", "x86_64")
            except Exception:
                pass
        machine = platform.machine()
        return _ARCH_MAP.get(machine, machine)
