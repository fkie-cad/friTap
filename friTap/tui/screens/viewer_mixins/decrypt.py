#!/usr/bin/env python3

"""
Offline decrypt -> flow view: the pcap + keylog to .tap conversion flow.

A plain mixin (no BINDINGS/CSS/compose); the host screen supplies ``app``,
``run_worker``, ``reload_replay``, ``_alert`` and ``_get_activity_log``.
No capture/wizard code, so a replay-only viewer can inherit it.
"""

from __future__ import annotations

import logging
from typing import Optional

from ...modals.decrypt_progress_modal import DecryptProgressModal
from ...widgets.wire_text import safe_static_text

logger = logging.getLogger(__name__)


def _discover_external_decryptors() -> None:
    """Register third-party offline decryptors (cached, never raises), as the ``--from-pcap`` CLI does.

    Kept out of ``pcap_to_tap`` so library callers see no ambient side effects.
    """
    try:
        from friTap.offline.discovery import discover_external_offline_decryptors

        discover_external_offline_decryptors()
    except Exception:
        logger.debug("offline decryptor discovery failed", exc_info=True)


class DecryptMixin:
    """Offline pcap decryption into the flow view (host: a Textual ``Screen``)."""

    def start_decrypt_to_flow(
        self, pcap: str, keylog: str, protocol: str = "tls"
    ) -> None:
        """Decrypt *pcap* with *keylog* into the flow view.

        Per-protocol keylogs are ``split_keylog_path`` siblings of the TLS keylog
        (passed only when present). Runs in a thread worker after decryptor
        discovery, then reloads the .tap.
        """
        self._after_decryptor_discovery(
            lambda: self._build_and_launch_decrypt(
                pcap=pcap, keylog=keylog, proto_keylog="",
                protocol=protocol, tap="",
            )
        )

    def start_decrypt_to_flow_multi(
        self, pcap: str, keylog_files: dict, tap: str = ""
    ) -> None:
        """Decrypt *pcap* with an already-resolved ``{protocol: keylog_path}`` map.

        Bypasses :meth:`_build_convert_args`: re-resolving from one base path
        can misroute a protocol's keylog to the TLS log in multi-protocol
        captures (Signal splits ``-k`` into ``.tls.log`` + ``.signal.log``) and decrypt 0 messages.
        """
        keylog_files = keylog_files or {}
        tls_keylog = keylog_files.get("tls", "")
        protocol_keylogs = {
            proto: path for proto, path in keylog_files.items() if proto != "tls"
        }
        args = self._build_convert_args_multi(
            pcap=pcap, tls_keylog=tls_keylog,
            protocol_keylogs=protocol_keylogs, tap=tap,
        )
        if args is None:
            return
        self._launch_decrypt_worker(args)

    def action_open_pcap(self) -> None:
        """Prompt for a pcap + keylogs and decrypt them into the flow view."""
        from ...modals.open_pcap_modal import OpenPcapModal

        def _on_result(result) -> None:
            if not result:
                return
            self._after_decryptor_discovery(
                lambda: self._build_and_launch_decrypt(
                    pcap=result.get("pcap", ""),
                    keylog=result.get("keylog", ""),
                    proto_keylog=result.get("proto_keylog", ""),
                    protocol=result.get("protocol", "tls") or "tls",
                    tap=result.get("tap", ""),
                )
            )

        self.app.push_screen(OpenPcapModal(), callback=_on_result)

    def _after_decryptor_discovery(self, continuation) -> None:
        """Run *continuation* on the UI thread once third-party decryptors are registered.

        Discovery imports plugin code, so it runs in a thread worker and never
        freezes the TUI; it is cached. :meth:`_build_convert_args` reads the registry.
        """
        def _discover_then_continue() -> None:
            _discover_external_decryptors()
            try:
                self.app.call_from_thread(self._continue_if_live, continuation)
            except RuntimeError:  # the app shut down while discovering
                logger.debug("decrypt dropped: app closed during discovery")

        self.run_worker(
            _discover_then_continue, thread=True, group="decrypt-discovery",
        )

    def _continue_if_live(self, continuation) -> None:
        """Run *continuation* unless the screen was removed meanwhile."""
        if self._is_live_screen():
            continuation()

    def _build_and_launch_decrypt(self, **convert_kwargs) -> None:
        """Build the convert args and start the worker."""
        args = self._build_convert_args(**convert_kwargs)
        if args is None:
            return
        self._launch_decrypt_worker(args)

    def _build_convert_args(
        self,
        pcap: str,
        keylog: str,
        proto_keylog: str,
        protocol: str,
        tap: str,
        resync_search_depth: Optional[int] = None,
    ) -> dict | None:
        """Assemble keyword args for ``convert_pcap_to_tap``.

        ``resync_search_depth`` bounds the mid-stream re-alignment search; ``None``
        keeps each decryptor's default (MTProto: ``DEFAULT_OBF_MAX_BLOCKS``).
        Returns ``None`` (after an alert modal) when the pcap is missing.
        Runs on the UI thread; callers run discovery first.
        """
        import os

        from friTap.output.keylog_paths import split_keylog_path

        if not pcap or not os.path.isfile(pcap):
            self._alert(
                f"PCAP not found: {safe_static_text(pcap) if pcap else '(empty)'}",
                title="PCAP Not Found",
                severity="error",
            )
            return None

        # Prefer the per-TLS split sibling if it exists.
        tls_keylog = None
        if keylog:
            tls_split = split_keylog_path(keylog, "tls")
            if os.path.isfile(tls_split):
                tls_keylog = tls_split
            elif os.path.isfile(keylog):
                tls_keylog = keylog

        protocol_keylogs: dict[str, str] = {}

        try:
            from friTap.offline.registry import get_offline_decryptor_registry
            entries = get_offline_decryptor_registry().list()
        except Exception:
            entries = []

        for entry in entries:
            name = entry.protocol_name
            # Order: explicit per-protocol path, the unsplit base keylog (a
            # single-protocol capture such as --protocol mtproto has no split
            # sibling; without it the decryptor is skipped, 0 flows), then the split sibling.
            candidates = []
            if proto_keylog and protocol == name:
                candidates.append(proto_keylog)
            if protocol == name and keylog:
                candidates.append(keylog)
            if keylog:
                candidates.append(split_keylog_path(keylog, name))
            resolved = next(
                (p for p in candidates if p and os.path.isfile(p)), None
            )
            if resolved is None:
                continue
            self._warn_if_backend_missing(name)
            protocol_keylogs[name] = resolved

        tap_path = tap.strip() if tap else ""
        if not tap_path:
            tap_path = os.path.splitext(pcap)[0] + ".tap"

        # signal_keylog/mtproto_keylog are named args of convert_pcap_to_tap (mirrors cli.merge_manifest).
        return {
            "pcap_path": pcap,
            "keylog_path": tls_keylog,
            "tap_path": tap_path,
            "signal_keylog": protocol_keylogs.get("signal"),
            "mtproto_keylog": protocol_keylogs.get("mtproto"),
            "protocol_keylogs": protocol_keylogs or None,
            "resync_search_depth": resync_search_depth,
            "tshark_path": None,
        }

    def _build_convert_args_multi(
        self,
        pcap: str,
        tls_keylog: str,
        protocol_keylogs: dict[str, str],
        tap: str,
        resync_search_depth: Optional[int] = None,
    ) -> dict | None:
        """Assemble ``convert_pcap_to_tap`` kwargs from a pcap, a TLS keylog and a ``{protocol: keylog_path}`` map.

        Unlike :meth:`_build_convert_args` it takes the wizard's collected map, so
        several layered keylogs (Signal and Telegram) work at once. Only existing
        files are kept. Returns ``None`` (after an alert modal) when the pcap is missing.
        """
        import os

        if not pcap or not os.path.isfile(pcap):
            self._alert(
                f"PCAP not found: {safe_static_text(pcap) if pcap else '(empty)'}",
                title="PCAP Not Found",
                severity="error",
            )
            return None

        tls_path = tls_keylog.strip() if tls_keylog else ""
        resolved_tls = tls_path if (tls_path and os.path.isfile(tls_path)) else None

        resolved_protocols: dict[str, str] = {}
        for name, path in (protocol_keylogs or {}).items():
            candidate = (path or "").strip()
            if candidate and os.path.isfile(candidate):
                self._warn_if_backend_missing(name)
                resolved_protocols[name] = candidate

        tap_path = tap.strip() if tap else ""
        if not tap_path:
            tap_path = os.path.splitext(pcap)[0] + ".tap"

        # Same named args as _build_convert_args.
        return {
            "pcap_path": pcap,
            "keylog_path": resolved_tls,
            "tap_path": tap_path,
            "signal_keylog": resolved_protocols.get("signal"),
            "mtproto_keylog": resolved_protocols.get("mtproto"),
            "protocol_keylogs": resolved_protocols or None,
            "resync_search_depth": resync_search_depth,
            "tshark_path": None,
        }

    def _warn_if_backend_missing(self, protocol: str) -> None:
        """Warn (non-blocking) when a protocol's decrypt backend is missing."""
        try:
            if protocol == "signal":
                from friTap.offline.signal import (
                    SIGNAL_DEPENDENCY_HINT,
                    signal_backend_available,
                )
                if not signal_backend_available():
                    self._alert(
                        SIGNAL_DEPENDENCY_HINT,
                        title="Signal Backend Missing",
                        severity="warning",
                    )
            elif protocol == "mtproto":
                from friTap.offline.mtproto import (
                    MTPROTO_DEPENDENCY_HINT,
                    mtproto_backend_available,
                )
                if not mtproto_backend_available():
                    self._alert(
                        MTPROTO_DEPENDENCY_HINT,
                        title="MTProto Backend Missing",
                        severity="warning",
                    )
        except Exception:
            pass

    def _launch_decrypt_worker(self, args: dict) -> None:
        """Run the offline conversion in a thread worker."""
        # Fail fast with a modal before "Decrypting..." (tshark errors deeper in
        # a decryptor are caught in _decrypt_worker).
        from friTap.offline.tshark import TsharkNotFoundError, find_tshark
        try:
            find_tshark(args.get("tshark_path"))
        except TsharkNotFoundError:
            self._show_tshark_missing_modal()
            return
        # Spinner so a long decrypt never looks hung; the worker updates and dismisses it.
        progress = DecryptProgressModal()
        self._decrypt_progress = progress
        self.app.push_screen(progress)
        self.run_worker(
            lambda: self._decrypt_worker(args, progress),
            thread=True,
            exclusive=True,
            group="decrypt",
        )

    def _on_decrypt_progress(self, message: str) -> None:
        """Update the decrypt spinner's status line."""
        modal = getattr(self, "_decrypt_progress", None)
        if modal is not None:
            modal.update_status(message)

    def _dismiss_decrypt_progress(self, modal=None) -> None:
        """Close the decrypt spinner if still shown (*modal* names a specific one, default the current)."""
        current = getattr(self, "_decrypt_progress", None)
        if modal is None:
            modal = current
        if modal is current:
            self._decrypt_progress = None
        if modal is not None:
            try:
                modal.finish()
            except Exception:
                pass

    def _decrypt_worker(self, args: dict, progress=None) -> None:
        """Worker body: convert the pcap, then hand back to the UI thread.

        A cancelled run closes only its own *progress* spinner.
        """
        from textual.worker import get_current_worker

        from friTap.offline.pcap_to_tap import pcap_to_tap
        from friTap.offline.tshark import TsharkNotFoundError

        worker = get_current_worker()
        _discover_external_decryptors()

        def _report(message: str) -> None:
            if not worker.is_cancelled:
                self.app.call_from_thread(self._on_decrypt_progress, message)

        try:
            # A ``<pcap>.fritap.json`` sidecar fills only values not passed (as in ``--from-pcap``).
            result = pcap_to_tap(**args, use_manifest=True, progress=_report)
        except TsharkNotFoundError:  # tshark invoked by a decryptor but missing
            if not worker.is_cancelled:
                self.app.call_from_thread(self._dismiss_decrypt_progress)
                self.app.call_from_thread(self._show_tshark_missing_modal)
            else:
                self._close_cancelled_spinner(progress)
            return
        except Exception as e:  # conversion failed
            if not worker.is_cancelled:
                self.app.call_from_thread(self._on_decrypt_error, str(e))
            else:
                self._close_cancelled_spinner(progress)
            return
        if worker.is_cancelled:
            self._close_cancelled_spinner(progress)
            return
        coverage = self._zero_flow_coverage(args, result)
        self.app.call_from_thread(
            self._on_decrypt_done, args["tap_path"], result, coverage
        )

    def _close_cancelled_spinner(self, progress) -> None:
        """Worker thread: close a cancelled run's spinner (best effort; the UI loop may be gone)."""
        if progress is None:
            return
        try:
            self.app.call_from_thread(self._dismiss_decrypt_progress, progress)
        except Exception:
            pass

    @staticmethod
    def _zero_flow_coverage(args: dict, result):
        """``(severity, lines)`` explaining a 0-flow TLS conversion, else ``None`` (also on any failure).

        Worker thread, one tshark pass, only for 0 flows with a TLS keylog.
        """
        keylog = args.get("keylog_path")
        if getattr(result, "flow_count", 0) > 0 or not keylog:
            return None
        try:
            from friTap.offline.keylog_coverage import (
                check_keylog_coverage,
                describe,
            )
            from friTap.offline.tshark import find_tshark
            tshark = find_tshark(args.get("tshark_path"))
            return describe(check_keylog_coverage(tshark, args["pcap_path"], keylog))
        except Exception:
            return None

    @staticmethod
    def _protocol_counter(result, prefix: str, key: str) -> int:
        """``result.per_protocol[prefix][key]``, else 0."""
        per_protocol = getattr(result, "per_protocol", None) or {}
        return (per_protocol.get(prefix) or {}).get(key, 0)

    @staticmethod
    def _messaging_counter(result, key: str) -> int:
        """Sum ``per_protocol[<messaging prefix>][key]`` over all prefixes.

        A v1 flat counter (``V1_FLAT_COUNTERS``) is added only when its bucket is
        absent; on a real ``ConvertResult`` it mirrors the bucket and must not double count.
        """
        from friTap.offline.pcap_to_tap import messaging_buckets
        from friTap.offline.result_schema import V1_FLAT_COUNTERS
        total = sum(counts.get(key, 0) for _prefix, counts in messaging_buckets(result))
        per_protocol = getattr(result, "per_protocol", None) or {}
        for flat_name, prefix, bucket_key in V1_FLAT_COUNTERS:
            if bucket_key == key and prefix not in per_protocol:
                total += getattr(result, flat_name, 0)
        return total

    @classmethod
    def _degraded_stream_count(cls, result) -> int:
        """Streams skipped because capture began mid-connection (all messaging protos).

        Short/unsupported-framing streams are excluded.
        """
        return cls._messaging_counter(result, "degraded")

    @classmethod
    def _recovered_via_obf_count(cls, result) -> int:
        """Mid-stream streams opened with a memory-scanned obfuscation key (a positive outcome)."""
        return cls._messaging_counter(result, "recovered_via_obf")

    @classmethod
    def _degraded_unrecovered_count(cls, result) -> int:
        """Streams where obfuscation-key recovery ran but no key aligned.

        Distinct from ``degraded``: the fix is capturing keys concurrently or widening the search.
        """
        return cls._messaging_counter(result, "degraded_unrecovered")

    @classmethod
    def _short_stream_count(cls, result) -> int:
        """Streams too short to open; not counted as ``degraded``."""
        return cls._messaging_counter(result, "short")

    @classmethod
    def _undecryptable_record_count(cls, result) -> int:
        """Records with no matching key in the keylog (all messaging protos)."""
        return cls._messaging_counter(result, "undecryptable")

    @staticmethod
    def _e2e_only_no_transport(result) -> bool:
        """True if an E2E key was present but no transport auth key (so the E2E blobs were never reached)."""
        from friTap.offline.pcap_to_tap import messaging_buckets
        return any(bool(counts.get("e2e_only")) for _prefix, counts in messaging_buckets(result))

    @staticmethod
    def _unknown_key_ids(result) -> list:
        """Sorted hex auth_key_ids seen on the wire with no matching key (sent in the clear)."""
        from friTap.offline.pcap_to_tap import messaging_buckets
        ids: set = set()
        for _prefix, counts in messaging_buckets(result):
            ids.update(counts.get("unknown_key_ids") or {})
        return sorted(ids)

    @staticmethod
    def _coverage_message(coverage) -> Optional[str]:
        """0-flow explanation from a keylog-coverage ``(severity, lines)``."""
        if not coverage or not coverage[1]:
            return None
        severity, lines = coverage
        prefix = "Decryption produced no flows" if severity == "ok" else "Decrypted 0 flows"
        return f"{prefix}: " + " ".join(lines)

    def _on_decrypt_done(self, tap_path: str, result, coverage=None) -> None:
        """Load the produced .tap into the flow view; *coverage* explains a 0-flow result."""
        import os
        self._dismiss_decrypt_progress()
        if not self._is_live_screen():
            return
        flow_count = getattr(result, "flow_count", 0)
        if flow_count > 0:
            self.reload_replay(tap_path)
            self.app.notify(
                f"Decrypted {flow_count} flow"
                f"{'s' if flow_count != 1 else ''} -> {os.path.basename(tap_path)}",
                severity="information",
            )
            # Success can still be partial (streams missed at connection start are
            # skipped for obfuscated transports); mirror the CLI summary in friTap/offline/cli.py.
            degraded = self._degraded_stream_count(result)
            recovered = self._recovered_via_obf_count(result)
            degraded_unrecovered = self._degraded_unrecovered_count(result)
            short = self._short_stream_count(result)
            positive_notes: list = []
            warning_notes: list = []
            if recovered > 0:
                positive_notes.append(
                    f"{recovered} mid-stream Telegram stream"
                    f"{'s' if recovered != 1 else ''} recovered from "
                    f"memory-scanned obfuscation key"
                    f"{'s' if recovered != 1 else ''}."
                )
            if degraded > 0:
                warning_notes.append(
                    f"{degraded} stream{'s' if degraded != 1 else ''} started "
                    "mid-connection and could not be decrypted — messages on "
                    f"{'those' if degraded != 1 else 'that'} stream"
                    f"{'s' if degraded != 1 else ''} are missing. Re-capture from "
                    "connection start (spawn mode) to recover them."
                )
            if degraded_unrecovered > 0:
                warning_notes.append(
                    f"{degraded_unrecovered} stream"
                    f"{'s' if degraded_unrecovered != 1 else ''}: obfuscation-key "
                    "recovery attempted but no key aligned (capture the keys "
                    "concurrently / widen the search)."
                )
            if short > 0:
                warning_notes.append(
                    f"{short} short stream{'s' if short != 1 else ''} "
                    "(start gap / too little data)."
                )
            notes = positive_notes + warning_notes
            if notes:
                if warning_notes:
                    title, severity = "Partial Decryption", "warning"
                else:
                    title, severity = "Decryption Note", "information"
                self._alert("\n".join(notes), title=title, severity=severity)
            return

        # 0 flows: report the most specific cause first (a vaguer one would mask it):
        # E2E-only, undecryptable, degraded, then coverage / bare fallback.
        e2e_only = self._e2e_only_no_transport(result)
        degraded = self._degraded_stream_count(result)
        undecryptable = self._undecryptable_record_count(result)
        unknown_key_ids = self._unknown_key_ids(result)
        coverage_message = self._coverage_message(coverage)
        if e2e_only:
            message = (
                "Decrypted 0 flows: the keylog has a secret-chat (E2E) key but no "
                "MTProto transport auth key — the transport envelope can't be "
                "decrypted, so the messages inside can't be reached. Capture "
                "transport auth keys with a spawn `-k` run or `-ms` memory-scan."
            )
        elif undecryptable > 0:
            message = (
                f"Decrypted 0 flows: {undecryptable} record"
                f"{'s' if undecryptable != 1 else ''} had no matching key in the "
                "keylog (key not captured this session)."
            )
        elif degraded > 0:
            message = (
                f"Decrypted 0 flows: {degraded} stream"
                f"{'s' if degraded != 1 else ''} started mid-connection "
                "(capture began after the connection opened). Re-capture from "
                "connection start — open chats/scroll to force new connections, "
                "or use spawn mode."
            )
        elif coverage_message:
            message = coverage_message
        else:
            message = "Decryption produced no flows."

        # Unknown auth_key_ids travel in the clear: they are the search terms for a key hunt.
        if unknown_key_ids:
            shown = ", ".join(unknown_key_ids[:8])
            if len(unknown_key_ids) > 8:
                shown += f", … (+{len(unknown_key_ids) - 8} more)"
            message += (
                f" Unknown auth_key_id{'s' if len(unknown_key_ids) != 1 else ''} "
                f"seen on the wire (capture these keys): {shown}."
            )

        if os.path.isfile(tap_path):
            self.reload_replay(tap_path)
        # Multi-sentence: a dismissible modal, not a toast.
        self._alert(message, title="No Flows Decrypted", severity="warning")

    def _is_live_screen(self) -> bool:
        """False once the screen was removed (Textual never resets ``is_mounted``, so check ``is_attached``)."""
        return self.is_mounted and self.is_attached

    def _on_decrypt_error(self, message: str) -> None:
        """Report a conversion failure."""
        self._dismiss_decrypt_progress()
        if not self._is_live_screen():
            return
        self._alert(
            f"Decrypt failed: {safe_static_text(message)}",
            title="Decrypt Failed",
            severity="error",
        )

    def _show_tshark_missing_modal(self) -> None:
        """Show the 'install tshark' modal (text from friTap.offline.tshark, shared with the CLI)."""
        from friTap.offline.tshark import TSHARK_INSTALL_MESSAGE

        from ...modals.alert_modal import AlertModal
        self.app.push_screen(
            AlertModal(
                message=TSHARK_INSTALL_MESSAGE,
                title="tshark not found",
                severity="error",
            )
        )
        self._get_activity_log().log_warning(
            "tshark not found — offline decryption unavailable"
        )
