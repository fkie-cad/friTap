"""End-of-capture handling for the TUI: UI reset, ``.tap`` flush and result modals.

``SessionEndMixin`` is mixed into ``CaptureController`` and runs on the Textual
thread; the worker hands over through ``app.call_from_thread``. ``logger`` and
``CAPTURE_STOPPED_RESTART_HINT`` are read through ``friTap.tui.capture_controller``
at call time, so tests that patch them there still take effect.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from friTap.constants import build_infrastructure_display_filter
from friTap.events import ERROR_SEVERITY_ERROR, ERROR_SEVERITY_FATAL
from friTap.tui.themes import c

from .capture_results import KEYLOG_TOTAL_STAT, _pcap_has_packets
from .modals.alert_modal import AlertModal

try:
    from textual.widgets import Static
except ImportError:  # Static is only used inside a broad try block
    pass


def _controller_module():
    """``friTap.tui.capture_controller``, looked up at call time."""
    return sys.modules["friTap.tui.capture_controller"]


@dataclass
class _EndedSession:
    """What the session-end report needs, read before the AppState reset."""

    pcap: str
    protocols: list
    was_full: bool
    keylog_files: dict
    result_paths: dict
    target_display: str
    live_mode: str
    is_mobile: bool
    pcap_has_packets: bool
    pcap_empty: bool


class SessionEndMixin:
    """Session-end handling for ``CaptureController`` (Textual thread)."""

    def _on_session_ended(
        self,
        result_stats: dict[str, str] | None = None,
        generation: int | None = None,
    ) -> None:
        """Textual-thread handler for the end of a capture session.

        ``generation`` is the ending worker's generation; a stale (superseded)
        session's report is ignored. ``None`` means the current session.
        """
        if self._is_stale_session(generation):
            return
        # See restart_when_stopped.
        restart = self._restart_after_stop
        self._restart_after_stop = None
        if result_stats is None:
            result_stats = {}
        state = self._screen._get_state()
        ended = self._snapshot_ended_session(state)
        self._clear_target_and_mode(state)
        self._show_stopped_state(restart)
        self._restore_console_title()
        saved_key_count = self._release_tui_handler()
        flow_count = self._finish_flow_recording(ended)
        self._report_flow_count(flow_count, ended.result_paths)

        # Shown one at a time (push_screen is non-blocking, inline pushes would
        # overlap). Order: results/live/no-libs summary, error, decrypt offer.
        modal_queue = self._summary_modals(ended, result_stats, saved_key_count)
        error_modal = self._session_error_modal()
        if error_modal is not None:
            modal_queue.append((error_modal, None))
        self._clear_session_error()
        decrypt_offer = self._decrypt_offer(ended, restart)
        if decrypt_offer is not None:
            modal_queue.append(decrypt_offer)

        # The wizard relaunches only after the last modal, so none lands on top of it.
        self._show_modals_sequentially(modal_queue, on_complete=restart)

    def _is_stale_session(self, generation: int | None) -> bool:
        """True (and logged) when a superseded worker reports its end."""
        if generation is not None and generation != self._session_generation:
            _controller_module().logger.debug(
                "Ignoring end of stale capture session %d (current: %d)",
                generation, self._session_generation,
            )
            return True
        return False

    def _snapshot_ended_session(self, state) -> _EndedSession:
        """Read the paths, protocols and pcap status before the state reset.

        The keylog lookups need ``self._ssl_logger`` (its registry), so they
        also run before ``_ssl_logger`` is cleared.
        """
        decrypt_pcap = getattr(state, "pcap_path", "")
        decrypt_keylog = getattr(state, "keylog_path", "")
        decrypt_protocol = getattr(state, "protocol", "tls")
        # The set the write side split by (config.protocols); falls back to the
        # primary protocol when the list was never set.
        decrypt_protocols = getattr(state, "protocols", None) or [decrypt_protocol]
        decrypt_was_full = getattr(state, "full_capture", False)
        # Resolves split <stem>.<proto>.log files.
        keylog_files = self._resolve_keylog_files(decrypt_keylog, decrypt_protocols)
        # Includes memory-scan sidecars (OBF/perm auth keys), deduped against the
        # hook keylogs.
        result_paths = self._keylog_result_rows(decrypt_keylog, decrypt_protocols)
        if state.pcap_path:
            result_paths["PCAP"] = state.pcap_path
        target_display = state.target_display or state.target or "unknown"
        saved_live_mode = state.live_mode
        is_mobile = state.device_type == "usb"
        pcap_has_packets = self._ended_pcap_has_packets(decrypt_pcap)
        return _EndedSession(
            pcap=decrypt_pcap,
            protocols=decrypt_protocols,
            was_full=decrypt_was_full,
            keylog_files=keylog_files,
            result_paths=result_paths,
            target_display=target_display,
            live_mode=saved_live_mode,
            is_mobile=is_mobile,
            pcap_has_packets=pcap_has_packets,
            pcap_empty=bool(decrypt_pcap) and not pcap_has_packets,
        )

    @staticmethod
    def _ended_pcap_has_packets(decrypt_pcap: str) -> bool:
        """False when the expected pcap is missing or header-only; True if none was expected.

        A full capture can finish with only the empty pcapng header (tcpdump
        unavailable, no traffic). Mirrors _gather_result_stats' "_"-temp fallback.
        """
        if not decrypt_pcap:
            return True
        pcap_check_path = decrypt_pcap
        if not os.path.isfile(pcap_check_path):
            from friTap.pcap import temp_capture_path
            _alt = temp_capture_path(decrypt_pcap)
            if os.path.isfile(_alt):
                pcap_check_path = _alt
        return (
            _pcap_has_packets(pcap_check_path)
            if os.path.isfile(pcap_check_path)
            else False
        )

    @staticmethod
    def _clear_target_and_mode(state) -> None:
        """Clear the target and capture mode from the AppState (device info is preserved)."""
        state.target = ""
        state.target_display = ""
        state.spawn = False
        state.pcap_path = ""
        state.keylog_path = ""
        state.json_path = ""
        state.live = False
        state.live_mode = ""
        state.full_capture = False

    def _show_stopped_state(self, restart) -> None:
        """Reset the status bar and menu, enter STOPPED and log the session end."""
        status = self._screen._get_status_bar()
        status.update_capture("STOPPED")
        status.update_target("", "")
        status.capture_mode = ""

        # Batched to avoid 7 redundant rebuilds.
        menu = self._screen._get_menu_panel()
        with menu.batch_update():
            menu.capture_active = False
            menu.has_target = False
            menu.target_name = ""
            menu.target_mode = ""
            menu.current_mode = ""
            menu.keylog_path = ""
            menu.pcap_path = ""

        self._capture_mode = ""
        # Target and mode were just cleared, so Enter will not re-attach until a
        # new manual setup (a/s + 1-6) or a wizard restart.
        self._capture_state = self.STATE_STOPPED

        self._screen._get_activity_log().log_session("Capture session ended")
        if restart is None:
            self._screen._get_activity_log().log_info(
                _controller_module().CAPTURE_STOPPED_RESTART_HINT)

    def _restore_console_title(self) -> None:
        """Drop the "stop capture" hint from the title."""
        try:
            flow_list = self._screen.query_one("#flow-list")
            if flow_list.display:
                self._screen._update_flow_title()
            else:
                title = self._screen.query_one("#activity-title", Static)
                title.update(f"[bold {c('success')}]friTap Console[/]")
        except Exception:
            pass

    def _release_tui_handler(self) -> int:
        """Tear down the TUI output handler; return the key count it saw."""
        saved_key_count = self._tui_handler.key_count if self._tui_handler else 0
        if self._tui_handler is not None:
            self._tui_handler.teardown()
            self._tui_handler = None
        return saved_key_count

    def _finish_flow_recording(self, ended: _EndedSession) -> int:
        """Flush the collector, complete and close the ``.tap``; return the flow count."""
        flow_count = 0
        if self._flow_collector is not None:
            # Also hands live request contexts (--attribute-sdk) to the .tap
            # writer's sink, which stays registered until it closes.
            self._flow_collector.flush()
            flow_count = len(self._flow_collector.get_flows())

        # flush() marks flows COMPLETE without _notify(), so the TapWriter
        # callback never saw them.
        if self._tap_writer is not None and self._flow_collector is not None:
            written_ids = self._tap_writer.written_flow_ids
            for flow in self._flow_collector.get_flows():
                if flow.flow_id not in written_ids:
                    self._tap_writer.write_flow(flow)

        # stop_tap_recording() clears the writer; the late-key pass needs the path.
        reprocess_tap_path = (
            self._tap_writer.path if self._tap_writer is not None else ""
        )

        self.stop_tap_recording()

        self._maybe_reprocess_signal_late_keys(
            reprocess_tap_path, ended.pcap, ended.keylog_files, ended.protocols
        )
        return flow_count

    def _report_flow_count(self, flow_count: int, result_paths: dict) -> None:
        """Log the flow count; fall back to the legacy view when nothing was produced."""
        if flow_count > 0:
            self._screen._get_activity_log().log_info(
                f"Captured {flow_count} flow{'s' if flow_count != 1 else ''}"
            )

        # The menu is only visible in the legacy view.
        if not result_paths and flow_count == 0:
            self._screen._activate_legacy_view()

    def _summary_modals(
        self, ended: _EndedSession, result_stats: dict, saved_key_count: int,
    ) -> list:
        """The no-libraries hint, then the results or live-capture summary."""
        modal_queue: list = []

        if self._ssl_logger and not self._ssl_logger._detected_libraries:
            if not ended.result_paths:
                modal_queue.append((
                    AlertModal(
                        message="No TLS libraries were detected.\n\n"
                                "Consider enabling [bold]Library Scan[/] (press [bold]l[/] in the start screen) "
                                "to discover renamed or statically linked libraries.",
                        title="No Libraries Found",
                        severity="warning",
                    ),
                    None,
                ))

        if ended.result_paths:
            modal_queue.append((self._results_modal(ended, result_stats), None))
        # Mode 5: live auto-decrypt has no file output.
        elif ended.live_mode == "live_pcapng":
            modal_queue.append((self._live_pcapng_modal(ended, saved_key_count), None))
        # Mode 4: plaintext Wireshark also has no file output.
        elif ended.live_mode == "wireshark":
            modal_queue.append((self._live_wireshark_modal(ended), None))
        return modal_queue

    def _results_modal(self, ended: _EndedSession, result_stats: dict) -> AlertModal:
        """The Capture Results modal: outcome header plus one line per output file."""
        lines, results_severity = self._results_header(ended)
        for label, path in ended.result_paths.items():
            stat = result_stats.get(label)
            suffix = f" ({stat})" if stat else ""
            lines.append(f"  {label}: [bold]{path}[/]{suffix}")
        total = result_stats.get(KEYLOG_TOTAL_STAT)
        if total:
            lines.append(f"  {KEYLOG_TOTAL_STAT}: [bold]{total}[/]")
        return AlertModal(message="\n".join(lines), title="Capture Results", severity=results_severity)

    def _results_header(self, ended: _EndedSession) -> tuple[list[str], str]:
        """Header lines and severity: crashed, empty pcap or completed."""
        target_display = ended.target_display
        if self._session_crashed:
            lines = [
                f"Capture of [bold]{target_display}[/] did NOT complete — "
                "the target process crashed.\n",
                "Any files below are partial and may be empty:\n",
            ]
            return lines, "warning"
        if ended.pcap_empty:
            lines = [
                f"Capture of [bold]{target_display}[/] finished, but "
                "[bold]no traffic was captured[/].\n",
                "The PCAP is empty (0 packets).\n",
            ]
            if ended.is_mobile and ended.was_full:
                lines.append(
                    "On Android, full capture records traffic with on-device "
                    "[bold]tcpdump[/] — ensure the device is rooted and tcpdump "
                    "is available.\n"
                )
            return lines, "warning"
        return [f"Capture of [bold]{target_display}[/] completed.\n"], "info"

    @staticmethod
    def _live_pcapng_modal(ended: _EndedSession, saved_key_count: int) -> AlertModal:
        """Summary for live auto-decrypt (mode 5): keys are embedded in the stream."""
        target_display = ended.target_display
        key_count = saved_key_count
        key_label = f"{key_count} key{'s' if key_count != 1 else ''}" if key_count else "No keys"

        lines = [
            f"Live capture of [bold]{target_display}[/] completed.\n",
            f"[bold {c('success')}]TLS secrets extracted:[/] [bold]{key_label}[/]",
            "  Secrets are already embedded in the PCAPNG stream.\n",
            f"[bold {c('warning-amber')}]Save your capture:[/]",
            "  In Wireshark: [bold]File → Save As → .pcapng[/]\n",
            f"[bold {c('secondary')}]Note:[/] This was a full network capture.",
            "  Packets from other applications may be present.",
            "  Wireshark auto-decrypts only traffic with matching TLS keys.",
        ]
        if not ended.is_mobile:
            display_filter = build_infrastructure_display_filter()
            lines.append("")
            lines.append(f"[bold {c('success')}]Filter out Frida/ADB traffic:[/]")
            lines.append(f"  Display filter: [bold]{display_filter}[/]")
        return AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info")

    @staticmethod
    def _live_wireshark_modal(ended: _EndedSession) -> AlertModal:
        """Summary for plaintext Wireshark (mode 4)."""
        lines = [
            f"Live capture of [bold]{ended.target_display}[/] completed.\n",
            f"[bold {c('warning-amber')}]Save your capture:[/]",
            "  In Wireshark: [bold]File → Save As[/]",
        ]
        return AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info")

    def _session_error_modal(self) -> AlertModal | None:
        """The Capture Error modal for a fatal/error session failure, else None.

        Queued after the results so the capture context comes first. Parser
        warnings (ErrorEvent severity "warning") never set _session_error.
        """
        if not (self._session_error and self._session_error_severity in (
            ERROR_SEVERITY_FATAL, ERROR_SEVERITY_ERROR,
        )):
            return None
        body = self._session_error
        # So the user can attach the diagnostic log to a bug report.
        try:
            from friTap.fritap_utility import get_debug_log_path
            log_path = get_debug_log_path() or self._debug_log_path
        except Exception:
            log_path = self._debug_log_path
        if log_path:
            body = (
                f"{self._session_error}\n\n"
                f"Debug log: {log_path}\n"
                "Please attach when reporting at "
                "https://github.com/fkie-cad/friTap/issues"
            )
        return AlertModal(
            message=body,
            title="Capture Error",
            severity="error",
        )

    def _clear_session_error(self) -> None:
        """Reset the per-session error fields and drop the finished logger."""
        self._session_error = ""
        self._session_error_severity = ERROR_SEVERITY_FATAL
        self._session_error_category = None
        self._session_error_original = None
        self._ssl_logger = None

    def _decrypt_offer(self, ended: _EndedSession, restart):
        """``(DecryptConfirmModal, callback)`` when an offline decrypt makes sense, else None.

        Offered only for full captures with a pcap and keylog on disk that
        recorded traffic (empty pcaps decrypt to 0 flows). Protocol-agnostic:
        ``keylog_files`` already resolves split keylogs. Skipped when a wizard
        restart is pending, since a decrypt run would race the new wizard.
        """
        decrypt_pcap = ended.pcap
        keylog_files = ended.keylog_files
        if not (
            restart is None
            and ended.was_full
            and keylog_files
            and decrypt_pcap and os.path.isfile(decrypt_pcap)
            and ended.pcap_has_packets
        ):
            return None
        from .modals.decrypt_confirm_modal import DecryptConfirmModal

        def _on_decrypt_choice(ok: bool) -> None:
            if ok:
                # Pass the per-protocol map resolved above, not the raw base
                # keylog: re-resolving one path in start_decrypt_to_flow can
                # misroute a split capture's keylog to the TLS log (Signal
                # then decrypts 0 messages).
                self._screen.start_decrypt_to_flow_multi(
                    decrypt_pcap, keylog_files
                )

        return DecryptConfirmModal(), _on_decrypt_choice

    def _maybe_reprocess_signal_late_keys(
        self,
        tap_path: str,
        pcap_path: str,
        keylog_files: dict,
        protocols,
    ) -> None:
        """Session-end safety net: re-decode Signal offline to catch late keys.

        Live decoding misses a message whose ratchet key lands after its
        ciphertext. The offline pipeline re-reads the pcap with the complete
        keylog, so the live ``.tap`` is rewritten in place, headlessly, on a worker.

        Best-effort and never raises. No-op unless 'signal' was captured and the
        per-protocol keylog and a pcap exist on disk.
        """
        if "signal" not in (protocols or []):
            return
        if not tap_path or not pcap_path or not os.path.isfile(pcap_path):
            return
        keylog_files = keylog_files or {}
        if not keylog_files.get("signal"):
            return

        tls_keylog = keylog_files.get("tls", "")
        protocol_keylogs = {
            proto: path for proto, path in keylog_files.items() if proto != "tls"
        }

        def _reprocess() -> None:
            try:
                from friTap.offline.pcap_to_tap import pcap_to_tap
                pcap_to_tap(
                    pcap_path,
                    keylog_path=tls_keylog or None,
                    tap_path=tap_path,
                    protocol_keylogs=protocol_keylogs or None,
                    use_manifest=True,
                )
            except Exception:
                _controller_module().logger.debug(
                    "Signal late-key offline reprocess failed", exc_info=True
                )

        # Off the Textual event loop. The DecryptConfirmModal offer is a separate
        # user-driven path that writes its own .tap.
        self._screen.run_worker(_reprocess, thread=True)

    def _show_modals_sequentially(self, items: list, on_complete=None) -> None:
        """Show queued ``(screen, on_result)`` modals one at a time.

        ``push_screen`` is non-blocking, so each modal is pushed only after the
        previous one is dismissed. ``on_result`` gets the dismissed result;
        ``on_complete`` runs after the last modal (immediately if there are none).
        """
        if not items:
            if on_complete is not None:
                on_complete()
            return
        screen, on_result = items[0]
        rest = items[1:]

        def _advance(result, _on_result=on_result, _rest=rest) -> None:
            if _on_result is not None:
                try:
                    _on_result(result)
                except Exception:
                    _controller_module().logger.exception("post-capture modal callback failed")
            self._show_modals_sequentially(_rest, on_complete)

        self._screen.app.push_screen(screen, callback=_advance)
