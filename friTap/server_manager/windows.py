#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Windows frida-server manager.

Local Windows targets do not need frida-server (Frida injects directly).
Remote Windows targets require server deployment.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .base import BaseFridaServerManager


class WindowsServerManager(BaseFridaServerManager):
    """Manage frida-server for Windows targets."""

    @property
    def platform_name(self) -> str:
        return "windows"

    def _default_server_path(self) -> Path:
        """Return platform-appropriate temp path for the server binary."""
        tmp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
        return Path(tmp) / "frida-server.exe"

    def detect_arch(self, device: Any = None) -> str:
        if device:
            try:
                params = device.query_system_parameters()
                return params.get("arch", "x86_64")
            except Exception:
                pass
        machine = platform.machine()
        if machine in ("AMD64", "x86_64"):
            return "x86_64"
        elif machine in ("ARM64", "aarch64"):
            return "arm64"
        return "x86"

    def deploy(self, binary_path: Path, device: Any = None) -> None:
        dest = self._default_server_path()
        shutil.copy2(str(binary_path), str(dest))
        self._logger.info("Deployed frida-server to %s", dest)

    def start(self, device: Any = None) -> None:
        self._kill_existing()
        server_path = self._default_server_path()
        try:
            subprocess.Popen(
                [str(server_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self._logger.info("frida-server started")
        except Exception as exc:
            raise RuntimeError(f"Failed to start frida-server: {exc}")

    def stop(self, device: Any = None) -> None:
        self._kill_existing()
        self._logger.info("frida-server stopped")

    def _kill_existing(self) -> None:
        """Kill any running frida-server process."""
        try:
            subprocess.run(
                ["taskkill", "/f", "/im", "frida-server.exe"],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            # Not on Windows or no taskkill available
            try:
                subprocess.run(
                    ["killall", "frida-server"],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass

    def is_running(self, device: Any = None) -> bool:
        try:
            # Try Windows-native check
            result = subprocess.run(
                ["tasklist", "/fi", "imagename eq frida-server.exe"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "frida-server.exe" in result.stdout.lower()
        except Exception:
            try:
                result = subprocess.run(
                    ["pgrep", "-x", "frida-server"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            except Exception:
                return False

    def needs_server(self) -> bool:
        return False  # Local Windows doesn't need it
