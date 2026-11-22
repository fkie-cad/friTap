"""Write the ``<pcap>.fritap.json`` sidecar manifest of a full capture.

The manifest records server ports and keylog paths so offline ``--from-pcap``
can auto-load Decode-As ports and keys. Each ``_add_*`` helper fills one
section; they run in a fixed order because the key order is the JSON order.
The helpers take the PCAP (or a test stub bound to it) as ``pcap``.
"""
import json
import os

from ._fs_util import is_non_empty_file
from .pcap_utility import MANIFEST_SUFFIX

# Slack for coarse mtime resolution (FAT/exFAT use 2 s steps).
_MTIME_SLACK_SECONDS = 2.0


def _written_this_session(path, not_before) -> bool:
    """Whether *path* is a non-empty file last modified at/after *not_before*.

    ``not_before=None`` skips the age check (callers without a session clock).
    """
    try:
        stat = os.stat(path)
    except OSError:
        return False
    if stat.st_size == 0:
        return False
    return not_before is None or stat.st_mtime >= not_before - _MTIME_SLACK_SECONDS


def _existing_keylog_files(mapping, not_before=None) -> dict:
    """Keep only the ``{protocol: path}`` entries this session actually wrote.

    Memory-scan sidecars (``<base>.memscan.mtproto.keylog``) have stable names and
    are opened only when the first key arrives, so a file from an earlier run
    survives when this run finds no key. Requiring a write at/after *not_before*
    keeps that stale file out of the manifest without deleting it.
    """
    return {proto: path for proto, path in (mapping or {}).items()
            if path and os.path.isfile(path) and _written_this_session(path, not_before)}


def write_capture_manifest(pcap) -> None:
    """Write the manifest for *pcap*; any failure is logged as a warning, never raised."""
    try:
        manifest = {
            "tls_ports": sorted(pcap._observed_server_ports.get("tcp", set())),
            "quic_ports": sorted(pcap._observed_server_ports.get("udp", set())),
        }
        # With several protocol formatters active the -k path is split into
        # <base>.<proto>.log siblings; active_keylogs holds the real paths.
        active_keylogs = getattr(pcap, "active_keylogs", None) or {}
        _add_memory_scan_keylogs(pcap, manifest)
        _add_tls_midstream_secrets(pcap, manifest)
        _add_request_contexts(pcap, manifest)
        # Candidate order: TLS split, base -k (Windows SChannel/LSASS writes its
        # secrets there; set via set_base_keylog), last-handler path. None unless
        # a candidate has content, so a never-written split is omitted, not
        # recorded as a phantom path.
        tls_keylog = pcap._resolve_written_keylog(pcap)  # == written_keylog_path()
        if pcap.keylog_path:
            _add_hooked_keylogs(pcap, manifest, active_keylogs, tls_keylog)
        if active_keylogs:
            _add_split_keylogs(pcap, manifest, active_keylogs, tls_keylog)
        _dump_manifest(pcap, manifest)
    except Exception as e:
        pcap.logger.warning(f"Could not write capture manifest: {e}")


def _add_memory_scan_keylogs(pcap, manifest) -> None:
    """Add the heap-scanner keylogs this session wrote.

    They become the primary keylog fields only when no hooked-key keylog exists
    (memory-scan-only capture).
    """
    memscan_keylogs = _existing_keylog_files(
        getattr(pcap, "memory_scan_keylogs", None),
        not_before=getattr(pcap, "_session_started_at", None),
    )
    if not pcap.keylog_path and memscan_keylogs:
        if "tls" in memscan_keylogs:
            manifest["keylog"] = str(memscan_keylogs["tls"])
        try:
            from friTap.offline.registry import get_offline_decryptor_registry
            for entry in get_offline_decryptor_registry().list():
                if entry.protocol_name == pcap.capture_protocol \
                        and entry.protocol_name in memscan_keylogs:
                    manifest[entry.cli_dest] = str(memscan_keylogs[entry.protocol_name])
                    break
        except Exception as e:
            pcap.logger.debug(f"manifest memory-scan keylog mapping skipped: {e}")
    if memscan_keylogs:
        manifest["memory_scan_keylogs"] = {
            proto: str(path) for proto, path in memscan_keylogs.items()
        }


def _add_tls_midstream_secrets(pcap, manifest) -> None:
    """Add the mid-stream TLS 1.3 secret bundle (flows with no captured ClientHello).

    The BoringSSL memscan engine writes it as ``<stem>.tls_midstream.secrets.jsonl``;
    it enables offline mid-stream binding.
    """
    try:
        # Prefer the engine's advertised path so the reader cannot diverge
        # from the writer's CWD-literal fallback; else derive it from the stem.
        midstream_secrets = getattr(pcap, "_tls_midstream_secrets_path", None)
        if not is_non_empty_file(midstream_secrets):
            midstream_secrets = _midstream_secrets_from_stem(pcap)
        if is_non_empty_file(midstream_secrets):
            manifest["tls_midstream_secrets"] = str(midstream_secrets)
    except Exception as e:
        pcap.logger.debug(
            f"manifest tls_midstream secrets mapping skipped: {e}")


def _midstream_secrets_from_stem(pcap):
    """Derive the bundle path from the memscan keylog stem, or None without one."""
    from friTap.memory_scanning import _sidecar_paths_for
    # All memscan sidecars share one stem, so any entry resolves the same path.
    # Under --protocol signal there is no "tls" keylog but the engine still
    # writes the bundle.
    ms_keylogs = getattr(pcap, "memory_scan_keylogs", None) or {}
    ms_stem_source = ms_keylogs.get("tls")
    if not ms_stem_source and ms_keylogs:
        ms_stem_source = next(iter(ms_keylogs.values()), None)
    if ms_stem_source:
        return _sidecar_paths_for(str(ms_stem_source)).get("tls_midstream_secrets")
    return None


def _add_request_contexts(pcap, manifest) -> None:
    """Add the ``--attribute-sdk`` request-context sidecar when it holds content."""
    # getattr: tests bind the manifest writer to stubs.
    request_contexts = getattr(pcap, "_request_contexts_path", None)
    if is_non_empty_file(request_contexts):
        manifest["request_contexts"] = request_contexts


def _add_hooked_keylogs(pcap, manifest, active_keylogs, tls_keylog) -> None:
    """Add the hooked-key keylog fields (``keylog`` plus the protocol's own field)."""
    # "keylog" is the TLS keylog (what a consumer feeds to tshark). With a split
    # capture, prefer the "tls" split over whichever handler set keylog_path
    # last, or a TLS consumer gets the wrong keys.
    if tls_keylog is not None:
        manifest["keylog"] = tls_keylog
    # Also record the keylog under the protocol's offline decryptor field
    # (registry cli_dest, e.g. "signal_keylog") so offline replay routes the
    # keys to that decryptor, not a generic TLS keylog (0 flows). Use the
    # protocol's split path when one exists: in a split capture the base -k
    # path holds the TLS keys. A never-written split is dropped; the base -k
    # fallback is kept.
    try:
        from friTap.offline.registry import get_offline_decryptor_registry
        for entry in get_offline_decryptor_registry().list():
            if entry.protocol_name == pcap.capture_protocol:
                proto_split = active_keylogs.get(entry.protocol_name)
                if proto_split:
                    if os.path.isfile(proto_split) \
                            and os.path.getsize(proto_split) > 0:
                        manifest[entry.cli_dest] = str(proto_split)
                else:
                    manifest[entry.cli_dest] = str(pcap.keylog_path)
                break
    except Exception as e:
        pcap.logger.debug(f"manifest protocol-keylog mapping skipped: {e}")


def _add_split_keylogs(pcap, manifest, active_keylogs, tls_keylog) -> None:
    """Add every split keylog that was actually written as ``keylogs``.

    A never-written ``<base>.tls``/``<base>.rc4`` is dropped. Single-protocol
    captures have no "keylogs" field; the single "keylog" field is kept for
    older consumers.
    """
    existing_active_keylogs = _existing_keylog_files(
        active_keylogs,
        not_before=getattr(pcap, "_session_started_at", None),
    )
    resolved_keylogs = {
        proto: str(path) for proto, path in existing_active_keylogs.items()
    }
    # The resolved TLS keylog may be the base -k file, not the split.
    if tls_keylog is not None:
        resolved_keylogs["tls"] = tls_keylog
    if resolved_keylogs:
        manifest["keylogs"] = resolved_keylogs


def _dump_manifest(pcap, manifest) -> None:
    manifest_path = pcap.pcap_file_name + MANIFEST_SUFFIX
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    pcap.logger.debug(f"Wrote capture manifest {manifest_path}")
