#!/usr/bin/env python3

"""friTap memory scanning: heap secret-scanner (``--memory-scan`` / ``-ms``).

The core builds a :class:`~friTap.memory_scanning.engine.MemoryScanEngine` via
:func:`build_memory_scan_engine` and drives start/stop/close. Plugins can use the
engine or the :class:`~friTap.memory_scanning.plugin.MemoryScanScriptPlugin`
adapter; this module is the single public import surface for both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .engine import MemoryScanEngine
from .formatter import MemoryScanKeylogFormatter

# Resolver API re-exported as public surface for third-party plugins.
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
    """Derive the sidecar paths (``unpaired``, ``rc4``, ``mtproto``, ``tls_midstream_secrets``) next to the memory-scan keylog.

    E.g. ``Telegram_memscan.keylog`` -> ``Telegram_memscan.mtproto.keylog``.
    Returns ``{}`` when scanning is off or the path cannot be derived; never raises.
    """
    try:
        from ..output.factory import memory_scan_keylog_path

        ms_path = memory_scan_keylog_path(config)
    except Exception:  # noqa: BLE001 - a bad path must not block the scan
        return {}
    return _sidecar_paths_for(ms_path) if ms_path else {}


def _sidecar_paths_for(ms_path: str) -> dict:
    try:
        import os

        stem = os.path.splitext(ms_path)[0]
        return {
            "unpaired": stem + ".schannel.unpaired",
            "rc4": stem + ".rc4.keylog",
            "mtproto": stem + ".mtproto.keylog",
            "tls_midstream_secrets": stem + ".tls_midstream.secrets.jsonl",
        }
    except Exception:  # noqa: BLE001 - a bad path must not block the scan
        return {}


def memory_scan_protocol_keylogs(config: "Config") -> dict:
    """Map protocol name -> the memory-scan keylog holding its keys.

    ``"tls"`` is the NSS keylog; ``"mtproto"`` and protocols resolving to it (e.g.
    ``telegram``) map to the ``.mtproto.keylog`` sidecar. ``{}`` when scanning is off.
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
    """Construct a :class:`MemoryScanEngine` from a ``Config``; sidecar paths are best-effort and fall back to ``None`` (default file)."""
    sidecars = memory_scan_sidecar_paths(config)
    return MemoryScanEngine(
        patterns_path=config.hooking.memory_scan_patterns,
        interval=getattr(config.hooking, "memory_scan_interval", 2.0),
        protocols=list(getattr(config, "protocols", None) or []),
        install_lsass_hook=getattr(config, "install_lsass_hook", True),
        unpaired_path=sidecars.get("unpaired"),
        rc4_path=sidecars.get("rc4"),
        mtproto_path=sidecars.get("mtproto"),
        tls_secret_bundle_path=sidecars.get("tls_midstream_secrets"),
        emit_unconfirmed=getattr(
            config.hooking, "memory_scan_emit_unconfirmed", False
        ),
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
