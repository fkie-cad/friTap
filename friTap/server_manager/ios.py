#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""iOS frida-server manager for jailbroken devices."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .base import BaseFridaServerManager


class IOSServerManager(BaseFridaServerManager):
    """Manage frida-server on jailbroken iOS devices.

    Deployment requires SSH access to the device. If SSH is unavailable,
    provides manual instructions instead of failing silently.
    """

    REMOTE_PATH = "/usr/local/bin/frida-server"

    def __init__(self, ssh_host: str = "root@localhost", ssh_port: int = 2222) -> None:
        super().__init__()
        self._ssh_host = ssh_host
        self._ssh_port = ssh_port

    @property
    def platform_name(self) -> str:
        return "ios"

    def detect_arch(self, device: Any = None) -> str:
        if device:
            try:
                params = device.query_system_parameters()
                return params.get("arch", "arm64")
            except Exception:
                pass
        return "arm64"  # All modern iOS devices are arm64

    def _ssh_cmd(self, command: str) -> subprocess.CompletedProcess:
        """Run a command on the iOS device via SSH."""
        return subprocess.run(
            ["ssh", "-p", str(self._ssh_port), self._ssh_host, command],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _scp_to_device(self, local_path: Path, remote_path: str) -> None:
        """Copy a file to the iOS device via SCP."""
        subprocess.run(
            [
                "scp", "-P", str(self._ssh_port),
                str(local_path),
                f"{self._ssh_host}:{remote_path}",
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )

    def deploy(self, binary_path: Path, device: Any = None) -> None:
        try:
            self._scp_to_device(binary_path, self.REMOTE_PATH)
            self._ssh_cmd(f"chmod +x {self.REMOTE_PATH}")
            self._logger.info("Deployed frida-server to %s", self.REMOTE_PATH)
        except FileNotFoundError:
            msg = (
                "SSH/SCP not available. To deploy frida-server manually:\n"
                f"  1. Copy {binary_path} to the device at {self.REMOTE_PATH}\n"
                f"  2. Run: chmod +x {self.REMOTE_PATH}\n"
                f"  3. Run: {self.REMOTE_PATH} -D"
            )
            self._logger.warning(msg)
            raise RuntimeError(msg)
        except subprocess.TimeoutExpired:
            raise RuntimeError("SSH connection timed out. Verify device is accessible.")

    def start(self, device: Any = None) -> None:
        try:
            # Kill any existing instance first, then start daemonized
            self._ssh_cmd("killall frida-server 2>/dev/null; true")
            self._ssh_cmd(f"{self.REMOTE_PATH} -D")
            self._logger.info("frida-server started on iOS device")
        except FileNotFoundError:
            raise RuntimeError(
                "SSH not available. Start frida-server manually on the device:\n"
                f"  {self.REMOTE_PATH} -D"
            )

    def stop(self, device: Any = None) -> None:
        try:
            self._ssh_cmd("killall frida-server")
            self._logger.info("frida-server stopped on iOS device")
        except FileNotFoundError:
            raise RuntimeError(
                "SSH not available. Stop frida-server manually on the device:\n"
                "  killall frida-server"
            )

    def is_running(self, device: Any = None) -> bool:
        # First try Frida API
        if device:
            try:
                device.enumerate_processes()
                return True
            except Exception:
                pass
        # Fall back to SSH check
        try:
            result = self._ssh_cmd("pgrep -x frida-server")
            return result.returncode == 0
        except Exception:
            return False

    def needs_server(self) -> bool:
        return True
