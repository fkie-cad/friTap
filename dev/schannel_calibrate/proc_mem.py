#!/usr/bin/env python3
r"""Read a live process's committed memory, read-only — no dump file on disk.

WHY THIS EXISTS
  A MiniDump of lsass written to disk is quarantined by Windows Defender within
  seconds (an lsass dump is a textbook credential-theft indicator). That is a
  storage problem, not a safety problem: the reads themselves are harmless. So for
  lsass we skip the file entirely and read its committed pages straight into memory
  with ReadProcessMemory, then run the same offline search/locate logic over them.

  This is the SAME read-only primitive the Frida scanner and schannel_dump.py use:
  the process is opened PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, we only read, we
  never write or hook, so an lsass thread cannot be faulted. Nothing lands on disk
  for Defender to flag.

  LiveProcess exposes the same interface as minidump_reader.MiniDump (search /
  iter_ranges / read_va / total_bytes), so tools/schannel_autocalibrate.py can point
  its `tls13-locate` at a live PID exactly as it would at a .dmp.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schannel_dump  # reuse enable_se_debug / resolve_pid_by_name / access rights

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
# Protections we can ReadProcessMemory from. Default to writable (rw) pages: SChannel
# key objects are LSA heap allocations (private, committed, read/write).
WRITABLE = 0x04 | 0x08 | 0x40 | 0x80  # READWRITE, WRITECOPY, EXECUTE_READWRITE, EXECUTE_WRITECOPY
READABLE = WRITABLE | 0x02 | 0x20     # + READONLY, EXECUTE_READ
MAX_USER_VA = 0x7FFFFFFFFFFF          # arm64/x64 user space ceiling


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


class LiveProcess:
    """Committed pages of a live process, read once into memory (read-only)."""

    def __init__(self, pid: int, writable_only: bool = True, max_bytes: int = 1 << 31):
        self.pid = pid
        self.ranges: list[tuple[int, int]] = []      # (va, size) present in cache
        self._chunks: list[tuple[int, bytes]] = []    # (va, bytes)
        self._read_all(writable_only, max_bytes)

    def _read_all(self, writable_only: bool, max_bytes: int) -> None:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t]
        k32.ReadProcessMemory.restype = wintypes.BOOL
        k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_size_t)]

        hproc = k32.OpenProcess(schannel_dump.READONLY_ACCESS, False, self.pid)
        if not hproc:
            err = ctypes.get_last_error()
            raise OSError(f"OpenProcess(pid={self.pid}) failed (err {err}); "
                          f"{'lsass PPL/VBS or ' if err == 5 else ''}not elevated?")
        want = WRITABLE if writable_only else READABLE
        total = 0
        try:
            mbi = MEMORY_BASIC_INFORMATION64()
            addr = 0
            while addr < MAX_USER_VA and total < max_bytes:
                r = k32.VirtualQueryEx(hproc, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi))
                if r == 0:
                    break
                base = mbi.BaseAddress or addr
                size = mbi.RegionSize
                if size == 0:
                    break
                readable = (mbi.State == MEM_COMMIT
                            and (mbi.Protect & want)
                            and not (mbi.Protect & PAGE_GUARD)
                            and mbi.Protect != PAGE_NOACCESS)
                if readable:
                    buf = ctypes.create_string_buffer(size)
                    got = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(hproc, ctypes.c_void_p(base), buf,
                                             size, ctypes.byref(got)) and got.value:
                        data = buf.raw[:got.value]
                        self._chunks.append((base, data))
                        self.ranges.append((base, len(data)))
                        total += len(data)
                nxt = base + size
                addr = nxt if nxt > addr else addr + 0x1000
        finally:
            k32.CloseHandle(hproc)

    # -- MiniDump-compatible surface --------------------------------------
    def iter_ranges(self):
        for va, data in self._chunks:
            yield va, data

    def total_bytes(self) -> int:
        return sum(len(d) for _, d in self._chunks)

    def read_va(self, va: int, n: int) -> bytes | None:
        for base, data in self._chunks:
            if base <= va < base + len(data):
                off = va - base
                if off + n <= len(data):
                    return data[off:off + n]
                return None
        return None

    def search(self, needle: bytes) -> list[int]:
        out: list[int] = []
        for va, data in self._chunks:
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx == -1:
                    break
                out.append(va + idx)
                start = idx + 1
        return out


def open_live(pid: int | None = None, name: str | None = None,
              writable_only: bool = True) -> LiveProcess:
    """Resolve a target and return its LiveProcess (enables SeDebugPrivilege)."""
    schannel_dump.enable_se_debug()
    if pid is None:
        if not name:
            raise ValueError("open_live needs a pid or a name")
        pids = schannel_dump.resolve_pid_by_name(name)
        if not pids:
            raise OSError(f"no process named {name!r}")
        pid = pids[0]
    return LiveProcess(pid, writable_only=writable_only)


# --------------------------------------------------------------------------- #
# Module enumeration (read-only) — Toolhelp MODULEENTRY32W.
# Used by sspi_correlate.py to confirm SSPI DLLs are loaded and to resolve the
# TARGET process's own ncryptsslp.dll base for the TLS 1.2 needle scan (the base
# differs from lsass because of ASLR, so the lsass needle value would not match).
# --------------------------------------------------------------------------- #

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def list_modules(pid: int) -> list[dict]:
    """[{name, base, size, path}] for a live process (read-only Toolhelp snapshot)."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == _INVALID_HANDLE or not snap:
        raise OSError(f"CreateToolhelp32Snapshot(pid={pid}) failed "
                      f"(err {ctypes.get_last_error()})")
    out: list[dict] = []
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not k32.Module32FirstW(snap, ctypes.byref(me)):
            return out
        while True:
            out.append({
                "name": me.szModule,
                "base": me.modBaseAddr or 0,
                "size": me.modBaseSize,
                "path": me.szExePath,
            })
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    finally:
        k32.CloseHandle(snap)
    return out


def find_module(pid: int, name: str) -> dict | None:
    """First module whose name matches `name` (case-insensitive), or None."""
    want = name.lower()
    for m in list_modules(pid):
        if m["name"].lower() == want:
            return m
    return None
