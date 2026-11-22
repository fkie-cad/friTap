"""frida-server pre-flight for TUI captures on USB/remote devices.

``FridaServerPreflightMixin`` is mixed into ``CaptureController``. The probe runs
on the worker thread; activity-log writes go through ``app.call_from_thread``.
"""

from __future__ import annotations


class FridaServerPreflightMixin:
    """Probe the device's frida-server before attach; auto-start it on Android."""

    @staticmethod
    def _preflight_target_for(state) -> tuple[str, str] | None:
        """(device_id, device_name) for a USB/remote device, else None."""
        device_id = getattr(state, "device_id", "")
        if getattr(state, "device_type", "local") == "local" or not device_id:
            return None
        return device_id, getattr(state, "device_name", "") or device_id

    def _ensure_frida_server(self) -> None:
        """Probe the mobile device's frida-server; auto-start it on Android.

        Frida 17: a USB device with no frida-server still enumerates via the ADB
        fallback, so only a probe shows attach would fail. Runs on the worker
        thread; raises RuntimeError if the server cannot be started.
        """
        target = self._preflight_target
        if not self.server_preflight_enabled or target is None:
            return
        device_id, device_name = target
        from friTap.server_manager.probe import is_attach_capable, probe_frida_server
        device = self._lookup_frida_device(device_id)
        state = probe_frida_server(device)
        if not is_attach_capable(state):
            state = self._start_frida_server(device, device_name, state)
        self._screen.app.call_from_thread(self._screen._show_server_state, state)

    @staticmethod
    def _lookup_frida_device(device_id: str):
        """Same lookup the backend uses for a pre-enumerated device id."""
        import frida
        return frida.get_device(device_id)

    def _start_frida_server(self, device, device_name: str, state):
        """Start frida-server via ensure_running (Android only); return the state.

        Non-Android devices only get a warning; attach is still tried.
        """
        from friTap.server_manager.factory import get_server_manager
        try:
            mgr = get_server_manager(device)
        except Exception:
            mgr = None
        if mgr is None or mgr.platform_name != "android":
            self._console_log(
                "log_warning",
                f"frida-server is {state.value} on {device_name} — attach will likely fail.",
            )
            return state
        self._console_log(
            "log_info",
            f"frida-server not running on {device_name} — starting it via AndroidFridaManager…",
        )
        try:
            return mgr.ensure_running(
                device, callback=lambda msg: self._console_log("log_info", msg),
            )
        except Exception as exc:
            raise RuntimeError(
                f"frida-server is not running on {device_name} and could not be "
                f"started: {exc}"
            ) from exc

    def _console_log(self, level: str, message: str) -> None:
        """Write *message* to the activity log (marshals to the Textual thread)."""
        self._screen.app.call_from_thread(
            lambda: getattr(self._screen._get_activity_log(), level)(message)
        )
