"""Persistent cache of function RVAs and layout values learned by the agent.

The agent's slow locator finds ``SSL_read``/``SSL_write`` in stripped builds
and reports them as a ``plaintext_api_learned`` message. This store keeps them
keyed by ``build_id|size|arch`` so the next run on the same library build can
hand them back and skip the scan. The agent resolves in the order
exports -> user ``--offsets`` -> learned -> locator, and re-validates each RVA
against the recorded prologue hash, so a stale entry costs a scan, not a hook
in the wrong place.

Entries may also carry named ``functions`` (``{"<ns>.<name>": {rva,
prologue_sha256}}``) and small ``layout`` ints, reported as
``module_offsets_learned``. Those maps are validated and merged per item, so a
report about one library component never clobbers another's fields.

Leaf module: only the stdlib-only :mod:`friTap.cache_files` is imported from friTap.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Callable, Dict, Optional

from .cache_files import CACHE_WRITE_OPTIONS, cache_file_lock, fritap_cache_dir, write_atomic

logger = logging.getLogger("friTap.learned_offsets")

CACHE_FILE_NAME = "learned_offsets.json"
CACHE_DIR_ENV = "FRITAP_LEARNED_OFFSETS_DIR"
FORMAT_VERSION = 1
MAX_ENTRIES = 512
MAX_FILE_BYTES = 1024 * 1024
PLAINTEXT_FUNCTIONS = ("SSL_read", "SSL_write")

_MAX_LIBRARY_SIZE = 1 << 40
# Inner spaces: macOS framework images ("Electron Framework", "Google Chrome Framework").
_MODULE_RE = re.compile(r"^(?=.{1,255}$)[A-Za-z0-9._+\-](?:[A-Za-z0-9._+\- ]*[A-Za-z0-9._+\-])?$")
# GNU build ids (ELF) and 16-byte LC_UUIDs (Mach-O, 32 hex chars) both fit.
_BUILD_ID_RE = re.compile(r"^(?:[0-9a-f]{2}){4,64}$")
# Frida's Process.arch values; anything else is not a key the agent can produce.
_ARCHES = frozenset({"ia32", "x64", "arm", "arm64", "mips"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NAMED_ITEM_RE = re.compile(r"^[a-z0-9_]+(\.[A-Za-z0-9_]+){1,3}$")
_MAX_NAME_LEN = 128
MAX_FUNCTIONS = 64
MAX_LAYOUT = 64
LAYOUT_MIN = -0x10000
LAYOUT_MAX = 0x100000
# Layout names ending in this suffix hold an RVA: 0 < v < LAYOUT_RVA_MAX, not
# bounded by the module size, which on macOS covers only __TEXT (vtables live in
# __DATA_CONST past it). The agent validates the hint live. Agent: isLayoutRva.
_LAYOUT_RVA_SUFFIX = "Rva"
LAYOUT_RVA_MAX = 2 ** 32

AgentEntries = Dict[str, dict]


def default_cache_path() -> str:
    """Same base directory as the Wine Chromium RVA cache, overridable by env."""
    base = os.environ.get(CACHE_DIR_ENV) or fritap_cache_dir()
    return os.path.join(base, CACHE_FILE_NAME)


def make_key(build_id: str, size: int, arch: str) -> str:
    # arch is part of the key so a fat/multi-ISA build never shares RVAs.
    return f"{build_id}|{size}|{arch}"


class InvalidEntry(ValueError):
    """A learned-offsets message or cached entry failed validation."""


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_match(pattern: re.Pattern, value, field: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise InvalidEntry(f"bad {field}: {value!r}")
    return value


def _validate_arch(value) -> str:
    if value not in _ARCHES:
        raise InvalidEntry(f"bad arch: {value!r}")
    return value


def _validate_size(value) -> int:
    if not _is_int(value) or not 0 < value <= _MAX_LIBRARY_SIZE:
        raise InvalidEntry(f"bad size: {value!r}")
    return value


def _is_rva(value, size: int) -> bool:
    return _is_int(value) and 0 < value < size


def _normalized_digest(value, field: str) -> str:
    digest = value.lower() if isinstance(value, str) else value
    return _require_match(_SHA256_RE, digest, field)


def _validate_rvas(value, size: int) -> Dict[str, int]:
    if not isinstance(value, dict):
        raise InvalidEntry("rvas must be an object")
    rvas = {}
    for name in PLAINTEXT_FUNCTIONS:
        rva = value.get(name)
        if not _is_rva(rva, size):
            raise InvalidEntry(f"bad rva for {name}: {rva!r}")
        rvas[name] = rva
    return rvas


def _validate_hashes(value) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise InvalidEntry("prologue_sha256 must be an object")
    return {name: _normalized_digest(value.get(name), f"prologue_sha256.{name}")
            for name in PLAINTEXT_FUNCTIONS}


def _is_item_name(name) -> bool:
    return isinstance(name, str) and len(name) <= _MAX_NAME_LEN and bool(_NAMED_ITEM_RE.match(name))


def _validate_function(value, size: int) -> dict:
    if not isinstance(value, dict):
        raise InvalidEntry("function must be an object")
    rva = value.get("rva")
    if not _is_rva(rva, size):
        raise InvalidEntry(f"bad rva: {rva!r}")
    return {"rva": rva, "prologue_sha256": _normalized_digest(value.get("prologue_sha256"), "prologue_sha256")}


def _is_layout_rva(value) -> bool:
    return _is_int(value) and 0 < value < LAYOUT_RVA_MAX


def _validate_layout_value(name: str, value) -> int:
    if name.endswith(_LAYOUT_RVA_SUFFIX):
        valid = _is_layout_rva(value)
    else:
        valid = _is_int(value) and LAYOUT_MIN <= value <= LAYOUT_MAX
    if not valid:
        raise InvalidEntry(f"bad value: {value!r}")
    return value


def _validate_named_items(value, field: str, limit: int, validate_item) -> dict:
    """Keep each valid ``name -> value`` item; a bad item is dropped, not the entry."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        logger.debug("dropping learned %s: not an object", field)
        return {}
    items = {}
    for name, item in value.items():
        try:
            if not _is_item_name(name):
                raise InvalidEntry("bad name")
            items[name] = validate_item(name, item)
        except InvalidEntry as exc:
            logger.debug("dropping learned %s item %r: %s", field, name, exc)
    if len(items) > limit:
        logger.debug("dropping the oldest learned %s beyond %d items", field, limit)
    return _keep_newest(items, limit)


def _keep_newest(items: dict, limit: int) -> dict:
    """The last *limit* items: merge_entries appends the newest last."""
    return dict(list(items.items())[-limit:]) if len(items) > limit else items


def _merge_named_items(base: dict, update: dict, limit: int) -> dict:
    """*update*'s items win and move to the end; the oldest beyond *limit* go."""
    items = {name: value for name, value in base.items() if name not in update}
    items.update(update)
    return _keep_newest(items, limit)


def _validate_functions(value, size: int) -> Dict[str, dict]:
    return _validate_named_items(value, "functions", MAX_FUNCTIONS,
                                 lambda _name, item: _validate_function(item, size))


def _validate_layout(value) -> Dict[str, int]:
    return _validate_named_items(value, "layout", MAX_LAYOUT, _validate_layout_value)


def _validate_plaintext_pair(message, size: int) -> dict:
    """``rvas``/``prologue_sha256`` for both functions, else InvalidEntry."""
    return {
        "rvas": _validate_rvas(message.get("rvas"), size),
        "prologue_sha256": _validate_hashes(message.get("prologue_sha256")),
    }


def validate_key_fields(message) -> dict:
    """``module``/``build_id``/``size``/``arch`` normalised, or raise InvalidEntry."""
    if not isinstance(message, dict):
        raise InvalidEntry("entry must be an object")
    build_id = message.get("build_id")
    build_id = build_id.lower() if isinstance(build_id, str) else build_id
    return {
        "module": _require_match(_MODULE_RE, message.get("module"), "module"),
        "build_id": _require_match(_BUILD_ID_RE, build_id, "build_id"),
        "size": _validate_size(message.get("size")),
        "arch": _validate_arch(message.get("arch")),
    }


def validate_entry(message) -> dict:
    """Return a normalised entry (without ``last_seen``) or raise InvalidEntry.

    The SSL_read/SSL_write pair is required unless the entry carries at least
    one valid ``functions`` or ``layout`` item; then a bad pair is dropped.
    """
    entry = validate_key_fields(message)
    size = entry["size"]
    functions = _validate_functions(message.get("functions"), size)
    layout = _validate_layout(message.get("layout"))
    has_named_items = bool(functions or layout)
    has_pair = message.get("rvas") is not None or message.get("prologue_sha256") is not None
    if has_pair:
        try:
            entry.update(_validate_plaintext_pair(message, size))
        except InvalidEntry as exc:
            if not has_named_items:
                raise
            logger.debug("dropping learned SSL_read/SSL_write pair: %s", exc)
    elif not has_named_items:
        raise InvalidEntry("no plaintext pair, functions or layout")
    if functions:
        entry["functions"] = functions
    if layout:
        entry["layout"] = layout
    return entry


def merge_entries(base: dict, update: dict) -> dict:
    """``update`` laid over ``base`` (same key): named items merge per item with
    ``update`` winning, and the plaintext pair is replaced only when ``update``
    has one. ``last_seen`` is the newer of the two."""
    merged = dict(base)
    merged["module"] = update["module"]
    if "rvas" in update:
        merged["rvas"] = dict(update["rvas"])
        merged["prologue_sha256"] = dict(update["prologue_sha256"])
    for field, limit in (("functions", MAX_FUNCTIONS), ("layout", MAX_LAYOUT)):
        items = _merge_named_items(base.get(field, {}), update.get(field, {}), limit)
        if items:
            merged[field] = items
    merged["last_seen"] = max(base.get("last_seen", 0.0), update.get("last_seen", 0.0))
    return merged


def _as_timestamp(value) -> float:
    return float(value) if _is_int(value) or isinstance(value, float) else 0.0


def _entry_key(entry: dict) -> str:
    return make_key(entry["build_id"], entry["size"], entry["arch"])


def _agent_view(entry: dict) -> dict:
    view = {"module": entry["module"]}
    if "rvas" in entry:
        view["rvas"] = dict(entry["rvas"])
        view["prologue_sha256"] = dict(entry["prologue_sha256"])
    view["functions"] = {name: dict(fn) for name, fn in entry.get("functions", {}).items()}
    view["layout"] = dict(entry.get("layout", {}))
    return view


class LearnedOffsetsStore:
    """Thread-safe store; ``record``/``touch`` run on the router thread, ``save``
    on the session's background saver."""

    def __init__(self, path: Optional[str] = None, max_entries: int = MAX_ENTRIES,
                 clock: Callable[[], float] = time.time):
        self.path = path or default_cache_path()
        self.max_entries = max_entries
        self._clock = clock
        self._entries: Dict[str, dict] = {}
        self._lock = threading.RLock()
        self._read_warned = False

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ---- loading ---------------------------------------------------------

    def load(self) -> int:
        """Replace in-memory entries with the file's; never raises.

        Returns the number of entries loaded.
        """
        payload = self._read_payload()
        entries = self._entries_from_payload(payload) if payload is not None else {}
        with self._lock:
            self._entries = entries
            self._evict_overflow()
            return len(self._entries)

    def _read_payload(self) -> Optional[dict]:
        try:
            if os.path.getsize(self.path) > MAX_FILE_BYTES:
                self._warn_once("ignoring oversized learned-offsets cache %s", self.path)
                return None
            with open(self.path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            self._warn_once("ignoring unreadable learned-offsets cache %s: %s", self.path, exc)
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("entries"), dict):
            self._warn_once("ignoring malformed learned-offsets cache %s", self.path)
            return None
        return payload

    def _warn_once(self, msg: str, *args) -> None:
        # save() re-reads the file each time; a persistently bad file warns once.
        level = logging.DEBUG if self._read_warned else logging.WARNING
        self._read_warned = True
        logger.log(level, msg, *args)

    @staticmethod
    def _entries_from_payload(payload: dict) -> Dict[str, dict]:
        entries = {}
        for raw in payload["entries"].values():
            try:
                entry = validate_entry(raw)
            except InvalidEntry as exc:
                logger.debug("dropping cached learned offset: %s", exc)
                continue
            entry["last_seen"] = _as_timestamp(raw.get("last_seen"))
            # Recompute the key so a hand-edited key cannot cross ISAs or builds.
            entries[_entry_key(entry)] = entry
        return entries

    # ---- recording -------------------------------------------------------

    def record(self, message) -> Optional[str]:
        """Validate and store a ``plaintext_api_learned`` or
        ``module_offsets_learned`` payload, merged into any entry for the same key.

        Returns the entry key, or None when the message was rejected.
        """
        try:
            entry = validate_entry(message)
        except InvalidEntry as exc:
            logger.debug("rejected learned offsets: %s", exc)
            return None
        entry["last_seen"] = self._clock()
        key = _entry_key(entry)
        with self._lock:
            existing = self._entries.get(key)
            self._entries[key] = merge_entries(existing, entry) if existing else entry
            self._evict_overflow()
        return key

    def touch(self, message) -> Optional[str]:
        """Refresh ``last_seen`` for a cache hit so eviction keeps hot entries.

        Only the key fields are validated. An unknown key is recorded when the
        message is a full valid entry. Returns the key, or None when rejected.
        """
        try:
            key = _entry_key(validate_key_fields(message))
        except InvalidEntry as exc:
            logger.debug("rejected learned-offsets cache hit: %s", exc)
            return None
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                entry["last_seen"] = self._clock()
                return key
        return self.record(message)

    def _evict_overflow(self) -> None:
        overflow = len(self._entries) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self._entries, key=lambda k: self._entries[k]["last_seen"])
        for key in oldest[:overflow]:
            del self._entries[key]

    # ---- saving ----------------------------------------------------------

    def save(self) -> bool:
        """Merge with the file's current entries, then write atomically; never raises.

        The re-read keeps entries other friTap processes saved since our load;
        per key the fields merge and the newer ``last_seen`` wins conflicting
        items. A best-effort file lock serialises concurrent savers.
        """
        with self._lock, cache_file_lock(self.path):
            self._merge_from_disk()
            payload = {"version": FORMAT_VERSION, "entries": self._entries}
            try:
                text = json.dumps(payload, indent=1, sort_keys=True)
                write_atomic(self.path, text.encode("utf-8"), **CACHE_WRITE_OPTIONS)
            except OSError as exc:
                logger.warning("could not write learned-offsets cache %s: %s", self.path, exc)
                return False
        return True

    def _merge_from_disk(self) -> None:
        payload = self._read_payload()
        if payload is None:
            return
        for key, disk_entry in self._entries_from_payload(payload).items():
            ours = self._entries.get(key)
            if ours is None:
                self._entries[key] = disk_entry
                continue
            # Stable sort: on a tie ours stays newer and wins.
            older, newer = sorted((disk_entry, ours), key=lambda e: e["last_seen"])
            self._entries[key] = merge_entries(older, newer)
        self._evict_overflow()

    # ---- agent views -----------------------------------------------------

    def entries_for_agent(self) -> AgentEntries:
        """``{build_id|size|arch: {module, rvas?, prologue_sha256?, functions, layout}}``.

        ``rvas``/``prologue_sha256`` appear only when the entry has the pair.
        """
        with self._lock:
            return {key: _agent_view(entry) for key, entry in self._entries.items()}
