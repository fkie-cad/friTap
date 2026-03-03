#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Android frida-server manager wrapping AndroidFridaManager."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .base import BaseFridaServerManager


class AndroidServerManager(BaseFridaServerManager):
    """Manage frida-server on Android devices via AndroidFridaManager.

    Wraps the ``AndroidFridaManager`` package with version-pinned
    downloads to avoid frida version mismatches.
    """

    def __init__(self, device_serial: Optional[str] = None) -> None:
        super().__init__()
        self._device_serial = device_serial
        self._fm: Any = None  # Lazy-loaded FridaManager instance

    def _get_fm(self) -> Any:
        """Lazy-load FridaManager to avoid import errors when not on Android."""
        if self._fm is None:
            from AndroidFridaManager import FridaManager
            self._fm = FridaManager(device_serial=self._device_serial)
        return self._fm

    @property
    def platform_name(self) -> str:
        return "android"

    def detect_arch(self, device: Any = None) -> str:
        try:
            return self._get_fm().get_device_arch()
        except Exception:
            if device:
                params = device.query_system_parameters()
                return params.get("arch", "arm64")
            return "arm64"

    def deploy(self, binary_path: Path, device: Any = None) -> None:
        # Use AndroidFridaManager's install with version pinned to frida.__version__
        self._get_fm().install_frida_server(version=self._frida_version)

    def start(self, device: Any = None) -> None:
        self._get_fm().run_frida_server()

    def stop(self, device: Any = None) -> None:
        self._get_fm().stop_frida_server()

    def is_running(self, device: Any = None) -> bool:
        try:
            return self._get_fm().is_frida_server_running()
        except Exception:
            return False

    def needs_server(self) -> bool:
        return True

    def install(self, device: Any = None, callback: Any = None) -> None:
        """Override install to use AndroidFridaManager's built-in install.

        This ensures version-matched frida-server (pinned to frida.__version__)
        instead of downloading 'latest'.
        """
        if callback:
            callback(f"Installing frida-server {self._frida_version} via AndroidFridaManager...")
        self._get_fm().install_frida_server(version=self._frida_version)
        if callback:
            callback("Installation complete.")
