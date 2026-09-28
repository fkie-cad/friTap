"""LSASS is a Windows-service concept: it must only ever be hooked when friTap
runs on a local Windows host. These tests lock down the platform guard in
``LsassHookManager.start_lsass_hook`` so a direct call off Windows is a clear
no-op (never an attempt), while a local win32 call is allowed to proceed.

Frida-free: the platform guard runs before any device/SSL_Logger work, so the
positive case is exercised by making ``get_pid_of_lsass`` return ``None``
(LSASS "not found"). Whether that resolver was reached tells us whether the
platform guard let the call through -- no thread, no frida, no 2s sleep.
"""

import friTap.friTap as fritap


def test_start_lsass_hook_is_noop_off_windows(monkeypatch):
    """Off Windows the guard returns before touching the LSASS resolver."""
    monkeypatch.setattr(fritap.sys, "platform", "linux")

    called = {"resolver": False}

    def _fail_resolver():
        called["resolver"] = True
        raise AssertionError("get_pid_of_lsass must not run off Windows")

    monkeypatch.setattr(fritap, "get_pid_of_lsass", _fail_resolver)

    manager = fritap.LsassHookManager()
    result = manager.start_lsass_hook()

    assert result is None
    assert called["resolver"] is False
    assert manager.is_running() is False


def test_start_lsass_hook_is_noop_on_macos(monkeypatch):
    """Sanity: any non-win32 platform (e.g. darwin) is refused too."""
    monkeypatch.setattr(fritap.sys, "platform", "darwin")
    monkeypatch.setattr(
        fritap, "get_pid_of_lsass",
        lambda: (_ for _ in ()).throw(AssertionError("resolver must not run")))

    assert fritap.LsassHookManager().start_lsass_hook() is None


def test_start_lsass_hook_allowed_on_win32_local(monkeypatch):
    """On local win32 the guard passes and the LSASS resolver is consulted.

    Returning ``None`` from the resolver simulates "LSASS process not found",
    which keeps the test free of frida / threads while still proving the
    platform guard did NOT block the call.
    """
    monkeypatch.setattr(fritap.sys, "platform", "win32")

    called = {"resolver": False}

    def _resolver():
        called["resolver"] = True
        return None  # simulate lsass.exe not found -> graceful skip

    monkeypatch.setattr(fritap, "get_pid_of_lsass", _resolver)

    manager = fritap.LsassHookManager()
    result = manager.start_lsass_hook()

    assert called["resolver"] is True, "platform guard must let win32 through"
    assert result is None  # because the resolver reported no lsass process
