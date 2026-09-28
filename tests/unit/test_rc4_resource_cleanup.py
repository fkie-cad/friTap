"""RC4 offline helpers must release what they acquire.

* R3 ``memreader._enable_se_debug``: the OpenProcessToken handle is closed on
  every path (success, lookup failure, and an exception mid-way).
* R5 ``handle_offline_cli_extras``: the keyless placeholder keylog it writes is
  unlinked at interpreter exit.
"""
from __future__ import annotations

import ctypes
import os
from types import SimpleNamespace

import pytest

from friTap.offline import rc4 as rc4_pkg
from friTap.offline.rc4 import memreader

_TOKEN = 0x1234


class _FakeAdvapi:
    def __init__(self, lookup_ok=True, adjust_raises=False):
        self.lookup_ok, self.adjust_raises = lookup_ok, adjust_raises

    def OpenProcessToken(self, _proc, _access, htok_ref):
        htok_ref._obj.value = _TOKEN
        return 1

    def LookupPrivilegeValueW(self, *_a):
        return 1 if self.lookup_ok else 0

    def AdjustTokenPrivileges(self, *_a):
        if self.adjust_raises:
            raise OSError("boom")
        return 1


class _FakeKernel32:
    def __init__(self):
        self.closed = []

    def GetCurrentProcess(self):
        return -1

    def CloseHandle(self, handle):
        self.closed.append(getattr(handle, "value", handle))
        return 1


def _install(monkeypatch, advapi):
    k32 = _FakeKernel32()
    libs = {"advapi32": advapi, "kernel32": k32}
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_k: libs[name], raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    return k32


@pytest.mark.parametrize("advapi, expected", [
    (_FakeAdvapi(), True),
    (_FakeAdvapi(lookup_ok=False), False),
    (_FakeAdvapi(adjust_raises=True), False),
])
def test_enable_se_debug_always_closes_the_token(monkeypatch, advapi, expected):
    k32 = _install(monkeypatch, advapi)
    assert memreader._enable_se_debug() is expected
    assert k32.closed == [_TOKEN]


def test_placeholder_keylog_is_unlinked_at_exit(monkeypatch):
    registered = []
    monkeypatch.setattr("atexit.register", lambda fn, *a: registered.append((fn, a)))
    monkeypatch.setattr(rc4_pkg, "get_rc4_scan_source", lambda: object())
    monkeypatch.setattr(rc4_pkg, "set_rc4_scan_source", lambda **_k: None)
    args = SimpleNamespace(rc4_keylog=None)
    rc4_pkg.handle_offline_cli_extras(args)
    path = args.rc4_keylog
    assert path and os.path.isfile(path)
    assert len(registered) == 1
    fn, fn_args = registered[0]
    fn(*fn_args)  # what the interpreter does at exit
    assert not os.path.exists(path)
    fn(*fn_args)  # an already-removed file is not an error


def test_unlink_quietly_ignores_missing_file(tmp_path):
    rc4_pkg._unlink_quietly(str(tmp_path / "gone.rc4.log"))
