"""What a finished TUI capture produced: keylog files, key counts, pcap checks.

``CaptureResultsMixin`` is mixed into ``CaptureController``; its state lives on
the controller. The stats helpers do file I/O and run on the worker thread.
"""

from __future__ import annotations

import os

from friTap.flow.models import format_byte_size

# Results-modal line for the distinct key total across several keylog files.
KEYLOG_TOTAL_STAT = "Distinct keys (all keylogs)"


def _selected_protocols(state) -> list[str]:
    """The state's protocol set with ``state.protocol`` first.

    Falls back to ``[state.protocol]`` when ``state.protocols`` is missing or out of sync.
    """
    primary = getattr(state, 'protocol', 'tls')
    protocols = list(getattr(state, 'protocols', None) or [])
    if not protocols or protocols[0] != primary:
        return [primary]
    return protocols


def _count_keys(path: str) -> int | None:
    """Count non-empty, non-comment lines in a keylog file."""
    try:
        with open(path) as f:
            return sum(
                1 for line in f
                if (s := line.strip()) and not s.startswith("#")
            )
    except OSError:
        return None


def _key_count_label(count: int) -> str:
    """``"1 key"`` / ``"N keys"`` (including ``"0 keys"``)."""
    return f"{count} key{'s' if count != 1 else ''}"


def _same_file_key(path: str) -> str:
    """Normalised path so two spellings of one file compare equal."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return path


def _get_file_size(path: str) -> int | None:
    """File size in bytes, or None if the file is missing."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _pcapng_has_packets(f) -> bool:
    """True if a pcapng stream contains at least one packet block."""
    from friTap.offline.net.capture_validation import iter_pcapng_blocks

    head = f.read(12)  # block type (4) + block length (4) + byte-order magic (4)
    if len(head) < 12:
        return False
    if head[8:12] not in (b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"):
        return True  # unknown byte order: fail open, never hide a real capture
    packet_block_types = {0x00000006, 0x00000003, 0x00000002}  # EPB, SPB, obsolete PB
    f.seek(0)
    return any(block_type in packet_block_types for block_type, _, _ in iter_pcapng_blocks(f))


def _pcap_has_packets(path: str) -> bool:
    """True if a pcap/pcapng file holds at least one packet.

    Fails open (True) on any parsing uncertainty so a real capture is never
    hidden; False only when the file is confidently empty (header only).
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            if magic == b"\x0a\x0d\x0d\x0a":  # pcapng Section Header Block
                f.seek(0)
                return _pcapng_has_packets(f)
            classic_magics = {
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",  # microsecond
                b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # nanosecond
            }
            if magic in classic_magics:
                f.seek(24)  # skip 24-byte global header
                return len(f.read(16)) == 16  # one full record header present
    except OSError:
        return True
    return True


class CaptureResultsMixin:
    """Keylog discovery and result statistics for ``CaptureController``."""

    def _memory_scan_keylog_files(self) -> dict[str, str]:
        """Protocol -> memory-scan sidecar keylog written this capture.

        Holds the scanner-recovered keys, separate from the hook keylog. Sidecar
        names are stable across runs, so only files written this session are kept
        (non-empty, modified since session start, as in the capture manifest).
        Each file appears once (mtproto and telegram share one). Any failure yields ``{}``.
        """
        try:
            from friTap.memory_scanning import memory_scan_protocol_keylogs
            from friTap.pcap import _existing_keylog_files
            mapping = memory_scan_protocol_keylogs(self._ssl_logger._config)
            started = getattr(self._ssl_logger, "_session_start_time", None)
            written = _existing_keylog_files(
                mapping,
                not_before=started if isinstance(started, (int, float)) else None)
        except Exception:
            return {}
        files: dict[str, str] = {}
        for proto, path in written.items():
            if path not in files.values():
                files[proto] = path
        return files

    def _memory_scan_keylog_paths(self) -> list[str]:
        """The memory-scan sidecar keylog paths written this capture.

        Any failure yields ``[]`` (hook-only count).
        """
        return list(self._memory_scan_keylog_files().values())

    def _keylog_result_rows(self, base_keylog: str, protocols) -> dict[str, str]:
        """Results-modal keylog rows ``{label: path}``, each file listed once.

        Hook keylogs first, then memory-scan sidecars. Memory-scan-only mode
        writes the tls sidecar to the ``-k`` path, so that one is not repeated.
        Shared by stats and modal so each stat lands on its own file's row.
        """
        rows: dict[str, str] = {}
        keylog_files = self._resolve_keylog_files(base_keylog, protocols)
        if keylog_files:
            multi = len(keylog_files) > 1
            for proto, path in keylog_files.items():
                rows[f"Key log ({proto})" if multi else "Key log"] = path
        elif base_keylog:
            rows["Key log"] = base_keylog
        listed = {_same_file_key(path) for path in rows.values()}
        for proto, path in self._memory_scan_keylog_files().items():
            if _same_file_key(path) not in listed:
                listed.add(_same_file_key(path))
                rows[f"Memory-scan keys ({proto})"] = path
        return rows

    def _gather_result_stats(self) -> dict[str, str]:
        """Gather capture statistics (file I/O); call from a worker thread.

        Each keylog row gets its own file's count; several files add a distinct total.
        """
        stats: dict[str, str] = {}
        state = self._screen._get_state()
        if state.keylog_path:
            stats.update(self._keylog_row_stats(
                self._keylog_result_rows(state.keylog_path, _selected_protocols(state))
            ))
        if state.pcap_path:
            size = _get_file_size(state.pcap_path)
            if size is None:
                from friTap.pcap import temp_capture_path
                size = _get_file_size(temp_capture_path(state.pcap_path))
            if size is not None:
                stats["PCAP"] = format_byte_size(size)
        return stats

    @staticmethod
    def _keylog_row_stats(rows: dict[str, str]) -> dict[str, str]:
        """Per-row key counts for existing keylog files, plus a distinct total."""
        from friTap.offline.keylog_picker import count_distinct_keys
        stats: dict[str, str] = {}
        existing = [path for path in rows.values() if os.path.isfile(path)]
        for label, path in rows.items():
            if os.path.isfile(path):
                stats[label] = _key_count_label(count_distinct_keys([path]))
        if len(existing) > 1:
            stats[KEYLOG_TOTAL_STAT] = _key_count_label(count_distinct_keys(existing))
        return stats

    def _resolve_keylog_files(self, base_keylog: str, protocols) -> dict[str, str]:
        """``{protocol: path}`` of the keylog files this capture wrote that exist on disk.

        A multi-protocol run (e.g. ``--protocol signal``, which also emits TLS
        keys) splits ``-k`` into ``<stem>.<proto>.log``, so the base path may
        never be written verbatim.

        ``protocols`` is a list or a single string. It goes through the same
        :func:`active_keylog_paths` the factory uses on the write side, so both
        sides split identically.
        """
        if not base_keylog:
            return {}
        proto_list = [protocols] if isinstance(protocols, str) else list(protocols)
        fallback_proto = proto_list[0] if proto_list else "tls"
        registry = getattr(self._ssl_logger, "_protocol_registry", None)
        try:
            from friTap.output.factory import active_keylog_paths
            candidates = active_keylog_paths(base_keylog, proto_list, registry)
        except Exception:
            candidates = {fallback_proto: base_keylog}
        existing = {proto: path for proto, path in candidates.items()
                    if path and os.path.isfile(path)}
        if not existing and os.path.isfile(base_keylog):
            existing = {fallback_proto: base_keylog}
        return existing
