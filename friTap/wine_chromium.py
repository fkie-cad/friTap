"""Chromium-embedded BoringSSL support for Wine targets (fkie-cad/friTap#52).

Launchers such as Battle.net, the EA app, Ubisoft Connect and the Epic Games
Launcher are CEF / Electron / Chromium apps: BoringSSL is statically linked into
``libcef.dll`` (or ``chrome.dll``, ``msedge.dll``, ``Qt*WebEngineCore.dll``, an
Electron ``.exe``) and TLS runs in a child process (the network service).

The agent can locate ``bssl::ssl_log_secret`` itself (tier-4 anchor locator), but
that scan costs seconds per process on a 200 MB DLL, and a launcher's first
handshakes happen sooner. This module resolves the function's RVA on the host,
from the PE file on disk, *before* the app starts, and hands it to the agent via
the ``--offsets`` channel (``{"libcef.dll": {"ssl_log_secret": {...}}}``), so every
process hooks instantly. Results are cached per file.

The locator is the same algorithm as the agent's x86-64 tier 4
(``agent/shared/x64_xref.ts``): find the NSS keylog label strings in read-only
data, find RIP-relative LEAs of them in code, take the first direct call after
each, and accept the callee only when at least two labels agree.
"""

from __future__ import annotations

import json
import logging
import os
import re
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger("friTap.wine_chromium")

KEYLOG_LABELS = (
    b"CLIENT_RANDOM",
    b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    b"SERVER_HANDSHAKE_TRAFFIC_SECRET",
    b"CLIENT_TRAFFIC_SECRET_0",
    b"SERVER_TRAFFIC_SECRET_0",
    b"EXPORTER_SECRET",
)

#: DLL basenames (lower-case) that embed BoringSSL in Chromium-family apps.
CHROMIUM_MODULE_NAMES = frozenset({
    "libcef.dll", "chrome.dll", "msedge.dll",
    "qt5webenginecore.dll", "qt6webenginecore.dll",
})

#: A PE .exe at least this large may be an Electron app with BoringSSL inside.
ELECTRON_EXE_MIN_SIZE = 64 * 1024 * 1024

#: Bytes after a label LEA searched for the call that consumes it.
CALL_SEARCH_WINDOW = 64

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
# lea rdx, [rip+disp32]: the label is ssl_log_secret's 2nd argument (Win64 rdx).
_LEA_RDX_RIP = re.compile(rb"\x48\x8d\x15", re.DOTALL)
# Any REX.W lea reg, [rip+disp32] (fallback when the label is staged elsewhere).
_LEA_ANY_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.DOTALL)


@dataclass(frozen=True)
class PeSection:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)


def pe_sections(data: bytes) -> List[PeSection]:
    """Section table of a PE image (raises ValueError if *data* is not PE)."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file (no PE signature)")
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsz, = struct.unpack_from("<H", data, pe + 20)
    off = pe + 24 + optsz
    out = []
    for i in range(nsec):
        name, vsize, va, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, off + 40 * i)
        ch, = struct.unpack_from("<I", data, off + 40 * i + 36)
        out.append(PeSection(name.rstrip(b"\0").decode("latin1"), va, vsize, raw_ptr, raw_size, ch))
    return out


def pe_size_of_image(data: bytes) -> int:
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<I", data, pe + 24 + 56)[0]


def _label_rvas(data: bytes, sections: Iterable[PeSection]) -> Dict[int, bytes]:
    """RVA -> label of each NUL-delimited keylog label in non-executable data."""
    found: Dict[int, bytes] = {}
    have = set()
    for sec in sections:
        if sec.executable:
            continue
        blob = data[sec.raw_ptr:sec.raw_ptr + sec.raw_size]
        for label in KEYLOG_LABELS:
            if label in have:
                continue
            i = blob.find(b"\0" + label + b"\0")
            if i >= 0:
                have.add(label)
                found[sec.va + i + 1] = label
    return found


def _first_call_after(blob: bytes, sec_va: int, lea_off: int, image_size: int) -> Optional[int]:
    start = lea_off + 7
    end = min(start + CALL_SEARCH_WINDOW, len(blob) - 5)
    j = blob.find(b"\xe8", start, end)
    while j != -1:
        rel, = struct.unpack_from("<i", blob, j + 1)
        callee = sec_va + j + 5 + rel
        if 0 <= callee < image_size:
            return callee
        j = blob.find(b"\xe8", j + 1, end)
    return None


def _votes(data, sections, targets, image_size, pattern) -> Dict[bytes, int]:
    votes: Dict[bytes, int] = {}
    for sec in sections:
        if not sec.executable:
            continue
        blob = data[sec.raw_ptr:sec.raw_ptr + sec.raw_size]
        for m in pattern.finditer(blob):
            i = m.start()
            if i + 7 > len(blob):
                break
            rel, = struct.unpack_from("<i", blob, i + 3)
            target = sec.va + i + 7 + rel
            label = targets.get(target)
            if label is None or label in votes:
                continue
            callee = _first_call_after(blob, sec.va, i, image_size)
            if callee is not None:
                votes[label] = callee
    return votes


def pick_agreed_callee(votes: Dict[bytes, int]) -> Optional[int]:
    """The callee at least two labels agree on; None on fewer or a tie."""
    counts: Dict[int, int] = {}
    for callee in votes.values():
        counts[callee] = counts.get(callee, 0) + 1
    if not counts:
        return None
    best = max(counts.values())
    winners = [c for c, n in counts.items() if n == best]
    return winners[0] if best >= 2 and len(winners) == 1 else None


def locate_ssl_log_secret_rva(data: bytes) -> Optional[int]:
    """RVA of ``bssl::ssl_log_secret`` in the x86-64 PE image *data*, or None."""
    try:
        sections = pe_sections(data)
        image_size = pe_size_of_image(data)
    except (ValueError, struct.error):
        return None
    targets = _label_rvas(data, sections)
    if len(targets) < 2:
        return None
    agreed = pick_agreed_callee(_votes(data, sections, targets, image_size, _LEA_RDX_RIP))
    if agreed is None:
        agreed = pick_agreed_callee(_votes(data, sections, targets, image_size, _LEA_ANY_RIP))
    return agreed


# --------------------------------------------------------------------------
# File discovery, caching and the --offsets payload
# --------------------------------------------------------------------------

def _cache_path() -> str:
    try:
        from platformdirs import user_cache_dir
        base = user_cache_dir("friTap")
    except Exception:
        base = os.path.join(os.path.expanduser("~"), ".cache", "friTap")
    return os.path.join(base, "chromium_boringssl_rva.json")


def _cache_key(path: str) -> str:
    st = os.stat(path)
    return f"{os.path.realpath(path)}|{st.st_size}|{st.st_mtime_ns}"


def _load_cache(cache_file: str) -> dict:
    try:
        with open(cache_file) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _store_cache(cache_file: str, cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        tmp = cache_file + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(cache, fh, indent=1, sort_keys=True)
        os.replace(tmp, cache_file)
    except OSError as exc:
        logger.debug("could not write %s: %s", cache_file, exc)


def resolve_rva_cached(path: str, cache_file: Optional[str] = None) -> Optional[int]:
    """Locate ssl_log_secret in the PE file *path*, using/refreshing the cache.
    A negative result is cached too (a non-BoringSSL Electron-sized exe)."""
    cache_file = cache_file or _cache_path()
    try:
        key = _cache_key(path)
    except OSError:
        return None
    cache = _load_cache(cache_file)
    if key in cache:
        rva = cache[key]
        return int(rva, 16) if isinstance(rva, str) else None
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    rva = locate_ssl_log_secret_rva(data)
    cache[key] = hex(rva) if rva is not None else None
    _store_cache(cache_file, cache)
    return rva


def wine_path_to_unix(path: str, prefix: Optional[str]) -> str:
    """Map ``C:\\dir\\app.exe`` (via the prefix's dosdevices) or ``Z:\\...`` to a
    Unix path; Unix paths are returned absolute and unchanged otherwise."""
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
    if not m:
        return os.path.abspath(path)
    drive, rest = m.group(1).lower(), m.group(2).replace("\\", "/")
    if drive == "z":
        return "/" + rest
    prefix = prefix or os.path.join(os.path.expanduser("~"), ".wine")
    return os.path.realpath(os.path.join(prefix, "dosdevices", f"{drive}:", rest))


def find_chromium_modules(exe_path: str, max_up: int = 2, max_depth: int = 4,
                          max_entries: int = 20000) -> List[str]:
    """Chromium-family BoringSSL modules shipped with the app at *exe_path*.

    Looks in the exe's directory, then walks from up to *max_up* parent
    directories (depth-limited) since launchers keep CEF elsewhere in their tree
    (e.g. Epic: ``Engine/Binaries/ThirdParty/CEF3/Win64/libcef.dll``). The exe
    itself is included when it is Electron-sized.
    """
    found: List[str] = []
    seen = set()

    def add(p):
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            found.append(p)

    try:
        if os.path.getsize(exe_path) >= ELECTRON_EXE_MIN_SIZE:
            add(exe_path)
    except OSError:
        pass
    root = os.path.dirname(os.path.abspath(exe_path))
    for _ in range(max_up):
        parent = os.path.dirname(root)
        if parent == root or parent in ("/", os.path.expanduser("~")):
            break
        root = parent
    visited = 0
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        visited += len(filenames) + len(dirnames)
        if visited > max_entries:
            logger.debug("Chromium module search under %s stopped after %d entries", root, visited)
            break
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        for name in filenames:
            if name.lower() in CHROMIUM_MODULE_NAMES:
                add(os.path.join(dirpath, name))
    return found


def chromium_offsets(module_paths: Iterable[str], cache_file: Optional[str] = None) -> Dict[str, dict]:
    """``--offsets`` entries ``{basename: {"ssl_log_secret": {...}}}`` for every
    module whose ssl_log_secret could be located."""
    out: Dict[str, dict] = {}
    for path in module_paths:
        rva = resolve_rva_cached(path, cache_file)
        if rva is None:
            continue
        name = os.path.basename(path)
        if name in out:
            # Two different builds under one basename: the agent re-validates
            # the RVA against the prologue, so keep the first and let it scan
            # if this one turns out wrong.
            continue
        out[name] = {"ssl_log_secret": {"address": hex(rva), "absolute": False}}
    return out


def merge_offsets(existing_json: Optional[str], extra: Dict[str, dict]) -> Optional[str]:
    """Merge *extra* into the user's offsets JSON; user entries win."""
    if not extra:
        return existing_json
    try:
        merged = json.loads(existing_json) if existing_json else {}
    except ValueError:
        return existing_json
    if not isinstance(merged, dict):
        return existing_json
    for name, fields in extra.items():
        slot = merged.setdefault(name, {})
        if isinstance(slot, dict):
            for key, value in fields.items():
                slot.setdefault(key, value)
    return json.dumps(merged)
