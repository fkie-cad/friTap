#!/usr/bin/env python3

"""Android frida-server manager wrapping AndroidFridaManager."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from .base import BaseFridaServerManager
from .probe import ServerState, is_attach_capable, probe_frida_server

STALE_SERVER_SETTLE_SECONDS = 1.0
FRESH_DEVICE_TIMEOUT = 2


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
        # get_device_arch() only exists in AndroidFridaManager >= 2.0.6.
        get_device_arch = getattr(self._get_fm(), "get_device_arch", None)
        if callable(get_device_arch):
            try:
                return get_device_arch()
            except Exception as exc:
                self._logger.debug("get_device_arch failed, falling back: %s", exc)
        return self._arch_from_device(device)

    @staticmethod
    def _arch_from_device(device: Any) -> str:
        """Fallback: read ``arch`` from frida's system parameters."""
        if device:
            params = device.query_system_parameters()
            return params.get("arch", "arm64")
        return "arm64"

    def deploy(self, binary_path: Path, device: Any = None) -> None:
        # Use AndroidFridaManager's install with version pinned to frida.__version__
        self._get_fm().install_frida_server(version=self._frida_version)

    def start(self, device: Any = None) -> None:
        # run_frida_server() reports failure by returning False, not raising.
        if self._get_fm().run_frida_server() is False:
            raise RuntimeError(self._start_failed_message())

    def stop(self, device: Any = None) -> None:
        self._get_fm().stop_frida_server()

    def is_running(self, device: Any = None) -> bool:
        # With a device, ask frida itself: a process named frida-server may be
        # stale/hung, and frida 17's jailed ADB fallback answers enumeration
        # even with no server at all.
        if device is not None:
            return is_attach_capable(probe_frida_server(device))
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

    # ------------------------------------------------------------------
    # ensure_running — the single entry point for "make attach work"
    # ------------------------------------------------------------------

    def ensure_running(
        self,
        device: Any,
        callback: Optional[Callable[[str], None]] = None,
        timeout: float = 15.0,
    ) -> ServerState:
        """Make *device* attach-capable (install / restart / start as needed).

        Returns the final :class:`ServerState`; raises ``RuntimeError`` with
        an actionable message when the server cannot be brought up.
        """
        state = probe_frida_server(device)
        if is_attach_capable(state):
            return state
        notify = callback or (lambda _msg: None)
        self._require_root()
        # Stop a stale server first so the install never overwrites a
        # binary that is still executing.
        self._stop_stale_server(notify)
        self._install_if_version_mismatch(notify)
        notify("Starting frida-server ...")
        self.start(device)
        return self._await_ready(device, timeout)

    def _serial_label(self) -> str:
        return self._device_serial or "the Android device"

    def _start_failed_message(self) -> str:
        return (
            f"frida-server failed to start on {self._serial_label()} — "
            "see `adb logcat` for a crash/tombstone, and check the device is rooted"
        )

    def _require_root(self) -> None:
        """Fail early with a clear message when the device has no root."""
        if getattr(self._get_fm(), "is_device_rooted", True) is False:
            raise RuntimeError(
                f"{self._serial_label()} is not rooted — frida-server needs root. "
                "Root the device, use an emulator, or inject frida-gadget instead."
            )

    def _install_if_version_mismatch(self, notify: Callable[[str], None]) -> None:
        """Install the frida.__version__-matched binary if missing or different."""
        installed = self._get_fm().get_installed_server_version()
        if installed == self._frida_version:
            return
        found = installed or "none"
        notify(f"Installing frida-server {self._frida_version} (found: {found}) ...")
        try:
            self._get_fm().install_frida_server(version=self._frida_version)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Installing frida-server {self._frida_version} on "
                f"{self._serial_label()} failed: {exc}"
            ) from exc

    def _stop_stale_server(self, notify: Callable[[str], None]) -> None:
        """Kill a frida-server process that exists but frida cannot reach.

        AndroidFridaManager's run_frida_server() returns early whenever any
        process named frida-server exists, so a hung one must go first.
        """
        if not self._get_fm().is_frida_server_running():
            return
        notify("Stopping unresponsive frida-server ...")
        self._get_fm().stop_frida_server()
        self._sleep(STALE_SERVER_SETTLE_SECONDS)

    def _await_ready(self, device: Any, timeout: float) -> ServerState:
        """Poll until attach-capable, else raise the jailed-fallback error."""
        state = self._wait_until_attach_capable(lambda: self._probe_any(device), timeout)
        if is_attach_capable(state):
            return state
        raise RuntimeError(
            f"frida-server was started on {self._serial_label()} but frida still "
            f"reports jailed access (ADB fallback) after {timeout:.0f}s — likely a "
            f"client/server version mismatch (client {self._frida_version}) or the "
            "server died; see `adb logcat`."
        )

    def _probe_any(self, device: Any) -> ServerState:
        """Probe the passed device, then a freshly looked-up one by serial."""
        state = probe_frida_server(device)
        if is_attach_capable(state):
            return state
        fresh = self._fresh_device()
        if fresh is None or fresh is device:
            return state
        return probe_frida_server(fresh)

    def _fresh_device(self) -> Any:
        """Look the device up again via frida; None if that is not possible."""
        if not self._device_serial:
            return None
        try:
            import frida
            return frida.get_device(self._device_serial, timeout=FRESH_DEVICE_TIMEOUT)
        except Exception:
            return None
