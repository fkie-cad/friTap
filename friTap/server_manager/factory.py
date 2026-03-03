#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Factory for platform-specific frida-server managers.

Auto-detects the target platform from a Frida device object and returns
the appropriate server manager instance.
"""

from __future__ import annotations

import sys
from typing import Any

from .base import BaseFridaServerManager


def get_server_manager(device: Any = None) -> BaseFridaServerManager:
    """Return the appropriate server manager for the given device.

    Args:
        device: A Frida device object. If ``None``, returns a manager
                for the local platform.

    Returns:
        A platform-specific ``BaseFridaServerManager`` subclass instance.

    Raises:
        ValueError: If the platform cannot be determined or is unsupported.
    """
    if device is None:
        return _local_manager()

    # For USB/remote devices, detect platform via Frida API
    try:
        params = device.query_system_parameters()
        os_info = params.get("os", {})
        os_id = os_info.get("id", "").lower() if isinstance(os_info, dict) else ""
    except Exception:
        # If query fails, try to infer from device type
        if hasattr(device, "type") and device.type == "local":
            return _local_manager()
        raise ValueError(
            f"Cannot determine platform for device '{getattr(device, 'name', device)}'. "
            "Ensure frida-server is running on the target."
        )

    return _manager_for_os(os_id, device)


def _local_manager() -> BaseFridaServerManager:
    """Return a manager for the local host platform."""
    if sys.platform == "darwin":
        from .macos import MacOSServerManager
        return MacOSServerManager()
    elif sys.platform == "win32":
        from .windows import WindowsServerManager
        return WindowsServerManager()
    else:
        from .linux import LinuxServerManager
        return LinuxServerManager()


def _manager_for_os(os_id: str, device: Any) -> BaseFridaServerManager:
    """Return a manager matching the detected OS identifier."""
    if os_id == "android":
        from .android import AndroidServerManager
        device_serial = getattr(device, "id", None)
        return AndroidServerManager(device_serial=device_serial)
    elif os_id == "ios":
        from .ios import IOSServerManager
        return IOSServerManager()
    elif os_id == "linux":
        from .linux import LinuxServerManager
        return LinuxServerManager()
    elif os_id in ("macos", "darwin"):
        from .macos import MacOSServerManager
        return MacOSServerManager()
    elif os_id == "windows":
        from .windows import WindowsServerManager
        return WindowsServerManager()
    else:
        raise ValueError(f"Unsupported platform: {os_id}")
