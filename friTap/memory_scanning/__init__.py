#!/usr/bin/env python3

"""friTap memory scanning — heap secret-scanner (the ``--memory-scan`` / ``-ms`` feature).

Memory scanning is a first-class friTap capability, not a plugin. The core
(:class:`friTap.legacy.ssl_logger_core.SSL_Logger`) constructs a
:class:`~friTap.memory_scanning.engine.MemoryScanEngine` via
:func:`build_memory_scan_engine` and drives its ``start`` / ``stop`` / ``close``
lifecycle directly.

The engine is also reachable *through* the plugin system: third-party plugins
can import :class:`MemoryScanEngine` and drive it, or reuse the thin
:class:`~friTap.memory_scanning.plugin.MemoryScanScriptPlugin` adapter that wraps
it in the standard ``ScriptPlugin`` lifecycle.

This module is the single public import surface for both the core and plugins.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .engine import MemoryScanEngine
from .formatter import MemoryScanKeylogFormatter
# The resolver API is re-exported as intentional PUBLIC surface: a third-party
# plugin driving the engine (see MemoryScanScriptPlugin) resolves/validates its
# own profiles through these, so they are importable from the package root even
# though no in-repo caller uses them yet.
from .loader import (
    MemoryScanPatternError,
    group_profiles_by_scan_target,
    load_database,
    load_memory_scan_profile,
    normalize_os_name,
    resolve_schannel_arch,
    select_profile,
    select_profiles,
    select_schannel_offsets,
    validate_profile,
)
from .plugin import MemoryScanScriptPlugin

if TYPE_CHECKING:
    from ..config import Config


def memory_scan_sidecar_paths(config: "Config") -> dict:
    """Derive the memory-scan sidecar paths from the memory-scan keylog path.

    Returns ``{"unpaired": ..., "rc4": ..., "mtproto": ...}`` co-located with
    :func:`~friTap.output.factory.memory_scan_keylog_path` (e.g.
    ``Telegram_memscan.keylog`` -> ``Telegram_memscan.mtproto.keylog``, and
    ``keys.memscan.log`` -> ``keys.memscan.mtproto.keylog``), or ``{}`` when
    memory scanning is off or the path cannot be derived. Best-effort: a bad
    path must never block the scan.
    """
    try:
        from ..output.factory import memory_scan_keylog_path

        ms_path = memory_scan_keylog_path(config)
    except Exception:  # noqa: BLE001 - a bad path must not block the scan
        return {}
    return _sidecar_paths_for(ms_path) if ms_path else {}


def _sidecar_paths_for(ms_path: str) -> dict:
    """The sidecar paths co-located with the memory-scan keylog *ms_path* (``{}`` on error)."""
    try:
        import os

        stem = os.path.splitext(ms_path)[0]
        return {
            "unpaired": stem + ".schannel.unpaired",
            "rc4": stem + ".rc4.keylog",
            "mtproto": stem + ".mtproto.keylog",
        }
    except Exception:  # noqa: BLE001 - a bad path must not block the scan
        return {}


def memory_scan_protocol_keylogs(config: "Config") -> dict:
    """Map protocol name -> the memory-scan keylog holding that protocol's keys.

    ``"tls"`` is the NSS keylog (:func:`memory_scan_keylog_path`); ``"mtproto"``
    and every selected protocol that resolves to the mtproto engine (e.g.
    ``telegram``) map to the ``.mtproto.keylog`` sidecar. Lets the capture
    manifest point an offline decryptor at the scanner's keys. ``{}`` when
    memory scanning is off.
    """
    from ..output.factory import memory_scan_keylog_path
    from .loader import _PROTOCOL_ENGINE_ALIASES

    ms_path = memory_scan_keylog_path(config)
    if not ms_path:
        return {}
    mapping = {"tls": ms_path}
    mtproto_path = _sidecar_paths_for(ms_path).get("mtproto")
    if mtproto_path:
        mapping["mtproto"] = mtproto_path
        selected = list(getattr(config, "protocols", None) or [])
        selected.append(getattr(config, "protocol", None))
        for name in selected:
            if name and _PROTOCOL_ENGINE_ALIASES.get(name) == "mtproto":
                mapping[name] = mtproto_path
    return mapping


def build_memory_scan_engine(config: "Config") -> MemoryScanEngine:
    """Construct a :class:`MemoryScanEngine` from a friTap ``Config``.

    Encapsulates the wiring the core used to inline: reads the ``-ms`` value,
    interval, selected protocols and ``--no-lsass`` flag off *config*, and
    co-locates the two sidecar files with the memory-scan keylog:

    * ``<memscan-keylog-stem>.schannel.unpaired`` — Schannel unpaired secrets for
      the offline pcap correlator;
    * ``<memscan-keylog-stem>.rc4.keylog`` — RC4 keys recovered from the heap,
      written even when ``--protocol rc4`` / ``-k`` was not given.

    A bad/absent keylog path must never block the scan, so sidecar derivation is
    best-effort (falls back to ``None`` → the engine writes to a default file).
    """
    sidecars = memory_scan_sidecar_paths(config)
    return MemoryScanEngine(
        patterns_path=config.hooking.memory_scan_patterns,
        interval=getattr(config.hooking, "memory_scan_interval", 2.0),
        protocols=list(getattr(config, "protocols", None) or []),
        install_lsass_hook=getattr(config, "install_lsass_hook", True),
        unpaired_path=sidecars.get("unpaired"),
        rc4_path=sidecars.get("rc4"),
        mtproto_path=sidecars.get("mtproto"),
        # E4: --ms-emit-unconfirmed opt-in (default OFF) threaded through config.
        emit_unconfirmed=getattr(
            config.hooking, "memory_scan_emit_unconfirmed", False
        ),
        # RC4 oracles (--ms-rc4-known-plaintext / --ms-rc4-ciphertext), default
        # None, threaded through config onto the rc4 profile's params.
        rc4_known_plaintext=getattr(
            config.hooking, "memory_scan_rc4_known_plaintext", None
        ),
        rc4_ciphertext=getattr(
            config.hooking, "memory_scan_rc4_ciphertext", None
        ),
    )


__all__ = [
    "MemoryScanEngine",
    "MemoryScanScriptPlugin",
    "MemoryScanKeylogFormatter",
    "build_memory_scan_engine",
    "memory_scan_sidecar_paths",
    "memory_scan_protocol_keylogs",
    "MemoryScanPatternError",
    "load_database",
    "select_profile",
    "select_profiles",
    "group_profiles_by_scan_target",
    "resolve_schannel_arch",
    "select_schannel_offsets",
    "normalize_os_name",
    "validate_profile",
    "load_memory_scan_profile",
]
