#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""macOS frida-server manager.

Local macOS targets do not need frida-server (Frida injects via
task_for_pid). Remote macOS targets require server deployment.
"""

from __future__ import annotations

import platform
from typing import Any

from .base import LocalUnixServerManager


class MacOSServerManager(LocalUnixServerManager):
    """Manage frida-server for macOS targets."""

    @property
    def platform_name(self) -> str:
        return "macos"

    def detect_arch(self, device: Any = None) -> str:
        if device:
            try:
                params = device.query_system_parameters()
                return params.get("arch", "arm64")
            except Exception:
                pass
        return "arm64" if platform.machine() == "arm64" else "x86_64"
