"""Read-only memory sources for offline RC4 key recovery.

A managed-RC4 key (a passphrase held in a client process's own byte arrays) is not
on the wire and not reachable by any crypto-API hook, so the offline decryptor cannot
find it from the pcap alone. It CAN, however, recover it by trial-decryption if it is
given the process's memory to mine candidate keys from — the offline analogue of the
live agent's in-memory trial-decrypt (agent/rc4/libs/rc4_memscan.ts).

This module vendors the minimal read-only readers for that, ported from
``research/memory_scan_lsass/tools/{minidump_reader,proc_mem}.py``:

  * :class:`MiniDump`  — a Windows ``.dmp`` (MiniDumpWithFullMemory) parsed to VA ranges.
  * :class:`FlatDump`  — a flat ``.bin`` memory image, read as one range.
  * :class:`LiveProcess` — a live process read via ``ReadProcessMemory`` (Windows only),
    read-only: the target is opened PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, never
    written and never hooked, so a target thread cannot be faulted. Nothing is written
    to disk. This is the same read-only primitive the Frida scanner uses; it is NEVER
    pointed at lsass (a client process's own RC4 key is the target, and that is not lsass).

All readers expose ``iter_ranges() -> (va, bytes)`` and ``total_bytes()``; the offline
decryptor turns those bytes into RC4 candidate keys via
:func:`friTap.offline.rc4.decrypt.extract_candidates`.
"""

from __future__ import annotations

import logging
import struct
from bisect import bisect_right
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Minidump (.dmp) parser — pure stdlib, offline, no OS dependency.
# --------------------------------------------------------------------------- #

_MINIDUMP_SIGNATURE = 0x504D444D  # 'MDMP'
_STREAM_MEMORY_LIST = 5           # MINIDUMP_MEMORY_LIST
_STREAM_MEMORY64_LIST = 9         # MINIDUMP_MEMORY64_LIST (full-memory dump)


class MiniDump:
    """A parsed minidump: memory ranges plus VA-space read helpers."""

    def __init__(self, data: bytes):
        self.data = data
        # each range = (va, size, file_off)
        self.ranges: List[Tuple[int, int, int]] = _parse_ranges(data)
        self._starts = [va for (va, _s, _o) in self.ranges]

    @classmethod
    def from_path(cls, path: str | Path) -> "MiniDump":
        return cls(Path(path).read_bytes())

    def iter_ranges(self) -> Iterator[Tuple[int, bytes]]:
        for va, size, file_off in self.ranges:
            yield va, self.data[file_off:file_off + size]

    def total_bytes(self) -> int:
        return sum(size for (_va, size, _o) in self.ranges)

    def read_va(self, va: int, n: int) -> Optional[bytes]:
        i = bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        rva, size, file_off = self.ranges[i]
        if not (rva <= va < rva + size):
            return None
        start = file_off + (va - rva)
        end = start + n
        if end > file_off + size:
            return None
        return self.data[start:end]


def _parse_ranges(data: bytes) -> List[Tuple[int, int, int]]:
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != _MINIDUMP_SIGNATURE:
        raise ValueError("not a minidump (bad MDMP signature); is this a flat dump?")
    n_streams, dir_rva = struct.unpack_from("<II", data, 8)
    streams: dict[int, Tuple[int, int]] = {}
    for i in range(n_streams):
        off = dir_rva + i * 12
        stype, dsize, rva = struct.unpack_from("<III", data, off)
        streams.setdefault(stype, (dsize, rva))
    if _STREAM_MEMORY64_LIST in streams:
        return _parse_memory64(data, streams[_STREAM_MEMORY64_LIST][1])
    if _STREAM_MEMORY_LIST in streams:
        return _parse_memory32(data, streams[_STREAM_MEMORY_LIST][1])
    raise ValueError("minidump has no memory stream (need MiniDumpWithFullMemory)")


def _parse_memory64(data: bytes, rva: int) -> List[Tuple[int, int, int]]:
    # MINIDUMP_MEMORY64_LIST: NumberOfMemoryRanges(u64) BaseRva(u64), then
    # MINIDUMP_MEMORY_DESCRIPTOR64[] { StartOfMemoryRange(u64) DataSize(u64) };
    # the raw bytes for every range are concatenated starting at BaseRva.
    count, base_rva = struct.unpack_from("<QQ", data, rva)
    ranges: List[Tuple[int, int, int]] = []
    file_off = base_rva
    entry = rva + 16
    for _ in range(count):
        start, size = struct.unpack_from("<QQ", data, entry)
        entry += 16
        ranges.append((start, size, file_off))
        file_off += size
    return ranges


def _parse_memory32(data: bytes, rva: int) -> List[Tuple[int, int, int]]:
    # MINIDUMP_MEMORY_LIST: NumberOfMemoryRanges(u32), then
    # MINIDUMP_MEMORY_DESCRIPTOR[] { StartOfMemoryRange(u64) DataSize(u32) Rva(u32) }.
    (count,) = struct.unpack_from("<I", data, rva)
    ranges: List[Tuple[int, int, int]] = []
    entry = rva + 4
    for _ in range(count):
        start, size, r = struct.unpack_from("<QII", data, entry)
        entry += 16
        ranges.append((start, size, r))
    return ranges


# --------------------------------------------------------------------------- #
# Flat (.bin) image — one range at VA 0.
# --------------------------------------------------------------------------- #

class FlatDump:
    """A flat memory image (raw ``.bin``) as a single range at VA 0."""

    def __init__(self, data: bytes):
        self._data = data

    def iter_ranges(self) -> Iterator[Tuple[int, bytes]]:
        yield 0, self._data

    def total_bytes(self) -> int:
        return len(self._data)


def load_dump(path: str | Path):
    """A ``.dmp`` minidump (via :class:`MiniDump`) or, when it lacks the MDMP
    signature, a flat ``.bin`` read as one range (:class:`FlatDump`)."""
    data = Path(path).read_bytes()
    try:
        return MiniDump(data)
    except ValueError:
        return FlatDump(data)


# --------------------------------------------------------------------------- #
# Live process (Windows only) — read-only ReadProcessMemory. Ported/inlined from
# research/.../tools/proc_mem.py (which reused schannel_dump for the win32 bits).
# --------------------------------------------------------------------------- #

_MEM_COMMIT = 0x1000
_PAGE_GUARD = 0x100
_PAGE_NOACCESS = 0x01
# Writable protections (a managed RC4 key lives on a private read/write heap).
_WRITABLE = 0x04 | 0x08 | 0x40 | 0x80   # READWRITE, WRITECOPY, EXECUTE_READWRITE, EXECUTE_WRITECOPY
_READABLE = _WRITABLE | 0x02 | 0x20     # + READONLY, EXECUTE_READ
_MAX_USER_VA = 0x7FFFFFFFFFFF           # x64/arm64 user-space ceiling
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_READONLY_ACCESS = _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ


class LiveProcess:
    """Committed pages of a live process, read once into memory (read-only)."""

    def __init__(self, pid: int, writable_only: bool = True, max_bytes: int = 1 << 31):
        self.pid = pid
        self._chunks: List[Tuple[int, bytes]] = []
        self._read_all(writable_only, max_bytes)

    def _read_all(self, writable_only: bool, max_bytes: int) -> None:
        import ctypes
        from ctypes import wintypes

        _enable_se_debug()

        class _MBI64(ctypes.Structure):
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

        hproc = k32.OpenProcess(_READONLY_ACCESS, False, self.pid)
        if not hproc:
            err = ctypes.get_last_error()
            raise OSError(f"OpenProcess(pid={self.pid}) failed (err {err}); "
                          f"{'not elevated / protected process, or ' if err == 5 else ''}"
                          f"is the pid correct?")
        want = _WRITABLE if writable_only else _READABLE
        total = 0
        try:
            mbi = _MBI64()
            addr = 0
            while addr < _MAX_USER_VA and total < max_bytes:
                r = k32.VirtualQueryEx(hproc, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi))
                if r == 0:
                    break
                base = mbi.BaseAddress or addr
                size = mbi.RegionSize
                if size == 0:
                    break
                readable = (mbi.State == _MEM_COMMIT
                            and (mbi.Protect & want)
                            and not (mbi.Protect & _PAGE_GUARD)
                            and mbi.Protect != _PAGE_NOACCESS)
                if readable:
                    buf = ctypes.create_string_buffer(size)
                    got = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(hproc, ctypes.c_void_p(base), buf,
                                             size, ctypes.byref(got)) and got.value:
                        self._chunks.append((base, buf.raw[:got.value]))
                        total += got.value
                nxt = base + size
                addr = nxt if nxt > addr else addr + 0x1000
        finally:
            k32.CloseHandle(hproc)

    def iter_ranges(self) -> Iterator[Tuple[int, bytes]]:
        for va, data in self._chunks:
            yield va, data

    def total_bytes(self) -> int:
        return sum(len(d) for _va, d in self._chunks)


def _enable_se_debug() -> bool:
    """Best-effort SeDebugPrivilege for the current process (Windows only)."""
    import ctypes
    from ctypes import wintypes

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class _LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]

    class _LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]

    class _TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", _LUID_AND_ATTRIBUTES * 1)]

    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        hproc = k32.GetCurrentProcess()
        htok = wintypes.HANDLE()
        if not advapi.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                       ctypes.byref(htok)):
            return False
        try:
            luid = _LUID()
            if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                                ctypes.byref(luid)):
                return False
            tp = _TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            advapi.AdjustTokenPrivileges(htok, False, ctypes.byref(tp), 0, None, None)
            return ctypes.get_last_error() == 0
        finally:
            k32.CloseHandle(htok)  # the token handle is ours on every path
    except Exception:  # noqa: BLE001 - privilege escalation is best-effort
        return False


def resolve_pid_by_name(name: str) -> List[int]:
    """PIDs of running processes whose image name matches *name* (Windows only)."""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    _INVALID = ctypes.c_void_p(-1).value

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == _INVALID or not snap:
        raise OSError(f"CreateToolhelp32Snapshot failed (err {ctypes.get_last_error()})")
    out: List[int] = []
    want = name.lower()
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not k32.Process32FirstW(snap, ctypes.byref(pe)):
            return out
        while True:
            exe = (pe.szExeFile or "").lower()
            if exe == want or exe == want + ".exe":
                out.append(int(pe.th32ProcessID))
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        k32.CloseHandle(snap)
    return out


# --------------------------------------------------------------------------- #
# Reader factory + candidate extraction
# --------------------------------------------------------------------------- #

def open_reader(dump: Optional[str] = None, pid: Optional[int] = None,
                name: Optional[str] = None, all_pages: bool = False):
    """A memory reader from *dump* / *pid* / *name*, or ``None`` when none given.

    A live pid/name read is Windows-only (ctypes.wintypes); ``dump`` works anywhere.
    """
    if dump:
        return load_dump(dump)
    if pid is not None or name:
        resolved = pid
        if resolved is None:
            pids = resolve_pid_by_name(name or "")
            if not pids:
                raise OSError(f"no process named {name!r}")
            resolved = pids[0]
        return LiveProcess(resolved, writable_only=not all_pages)
    return None


def reader_candidates(reader, min_len: int = 5, max_len: int = 64
                      ) -> Iterator[Tuple[str, bytes]]:
    """Every ``("dump", key)`` candidate mined from a memory reader's ranges."""
    from .decrypt import extract_candidates

    for _va, buf in reader.iter_ranges():
        for key in extract_candidates(buf, min_len, max_len):
            yield ("dump", key)
