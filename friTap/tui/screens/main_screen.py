#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main screen for friTap TUI -- single split-pane layout.

Replaces the 5-screen sequential flow with a permanent main screen.
Left panel: StatusBar + MenuPanel. Right panel: ActivityLog.
Device/process selection via modals.
"""

from __future__ import annotations

import sys
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..app import AppState

try:
    from textual.app import ComposeResult
    from textual.binding import Binding  # noqa: F401
    from textual.screen import Screen
    from textual.widgets import Header, Footer, Static
    from textual.containers import Horizontal, Vertical
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from ..widgets.activity_log import ActivityLog
    from ..widgets.status_bar import StatusBar
    from ..widgets.menu_panel import MenuPanel
    from ..widgets.flow_list import FlowListWidget
    from ..widgets.flow_detail import FlowDetailWidget
    from ..widgets.filter_bar import FilterBar
    from ..widgets.findings_list import FindingsListWidget
    from ..widgets.findings_filter_bar import FindingsFilterBar
    from ..widgets.analyzer_panel import AnalyzerPanel
    from ..widgets.analyzer_finding_detail import AnalyzerFindingDetailWidget
    from ..modals.findings_filter_modal import FindingsFilterModal, FindingFilterResult
    from friTap.analysis import Finding, Severity  # noqa: F401
    from friTap.analysis.filtering import FindingFilter, summarize
    from friTap.analysis.registry import available_analyzers, resolve_analyzers
    from ..modals.device_modal import DeviceSelectModal
    from ..modals.process_modal import ProcessSelectModal
    from ..modals.spawn_modal import SpawnInputModal
    from ..modals.help_modal import HelpScreen
    from ..modals.protocol_modal import ProtocolSelectModal
    from ..modals.filter_modal import FilterModal, FilterResult
    from ..wizard import CaptureWizard, PcapToTapWizard
    from ..capture_controller import CaptureController
    from ..mode_controller import ModeController
    from ..themes import c

    def _needs_reparse(flow, summary) -> bool:
        """Check if a flow should be re-parsed with current parser code.

        Triggers re-parse for:
        - Unknown protocol (legacy .tap files without proper detection)
        - HTTP/2 ghost flows (old code skipped SETTINGS-only control frames)
        - WebSocket TEXT flows (old code missed permessage-deflate decompression)
        """
        proto = flow.display_protocol
        if proto == "unknown":
            return True
        # HTTP/2 ghost flows: protocol detected but no request (SETTINGS-only)
        if "HTTP/2" in proto and flow.request is None:
            return True
        # HTTP/2 control frames from old .tap files: method matches but is_control_frame not set
        if "HTTP/2" in proto and flow.request is not None:
            if flow.request.method in ("SETTINGS", "PING", "GOAWAY", "WINDOW_UPDATE"):
                if not flow.request.is_control_frame:
                    return True
        # WebSocket TEXT: always re-parse to apply decompression + content detection
        # (Old .tap files stored compressed body; new parser decompresses + detects JSON)
        if proto == "WebSocket" and summary.method == "TEXT":
            return True
        return False

    class MainScreen(Screen):
        """Single-screen split-pane layout for friTap TUI."""

        BINDINGS = [
            Binding("f", "toggle_view", "Toggle View", show=False),
            Binding("slash", "focus_filter", "Filter", show=False),
            Binding("shift+escape", "clear_filter", "Clear Filter", show=False),
            Binding("shift+f", "toggle_findings_view", "Findings", show=False),
            Binding("a", "analyzer_panel", "Analyzers", show=False),
            Binding("c", "findings_quick_creds", "Creds", show=False),
            Binding("p", "findings_quick_pii", "PII", show=False),
            Binding("1", "findings_quick_critical", "Critical", show=False),
        ]

        def __init__(
            self,
            replay_file: str | None = None,
            pcap_to_tap_file: str | None = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._replay_file = replay_file
            self._pcap_to_tap_file = pcap_to_tap_file
            self._replay_filename: str | None = None
            self._replay_ctrl = None
            self._findings_cache: list | None = None
            # Monotonic token: each analyzer run / clear bumps it so a stale
            # (superseded or cleared) worker's late completion is ignored.
            self._analyzer_run_id = 0
            # Where a flow-detail view was opened from: "flow" (flow list) or
            # "finding" (analyzer finding-detail) — drives Esc back-navigation.
            self._detail_origin = "flow"
            self._wizard = CaptureWizard(self)
            self._capture = CaptureController(self)
            self._mode_ctrl = ModeController(self)

        # ----------------------------------------------------------
        # Layout
        # ----------------------------------------------------------

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="main-split"):
                with Vertical(id="left-panel"):
                    yield StatusBar(id="status-bar")
                    yield MenuPanel(id="menu-panel")
                with Vertical(id="right-panel"):
                    with Horizontal(id="activity-title-row"):
                        yield Static("", id="capture-indicator")
                        yield Static(f"[bold {c('success')}]friTap Console[/]", id="activity-title")
                        yield Static("", id="title-spacer")
                    yield FilterBar(id="filter-bar")
                    yield AnalyzerPanel(id="analyzer-panel")
                    yield ActivityLog(id="activity-log")
                    yield FlowListWidget(id="flow-list")
                    yield FlowDetailWidget(id="flow-detail")
                    yield FindingsFilterBar(id="findings-filter-bar")
                    yield FindingsListWidget(id="findings-list")
                    yield AnalyzerFindingDetailWidget(id="finding-detail")
            yield Footer()

        def on_mount(self) -> None:
            """Initialize the screen with welcome message and device info."""
            self._get_state()  # ensure state is initialized

            # Hide flow widgets and filter bar initially
            self.query_one("#filter-bar").display = False
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#findings-filter-bar").display = False
            self.query_one("#findings-list").display = False
            self.query_one("#finding-detail").display = False
            self.query_one("#analyzer-panel").display = False

            # Replay mode — skip wizard, load .tap file directly
            if self._replay_file:
                self._init_replay_mode()
                return

            # pcap-to-tap mode — this is an offline read/replay flow, not a live
            # capture, so show an empty flow view as the backdrop (instead of the
            # live-hooking console) and launch the guided conversion wizard on top
            # of it. After conversion, reload_replay repopulates the same view.
            if self._pcap_to_tap_file:
                self._activate_flow_view()
                self._start_pcap_to_tap_wizard(self._pcap_to_tap_file)
                return

            # Show welcome banner
            activity = self.query_one("#activity-log", ActivityLog)
            try:
                from friTap.about import __version__
                activity.show_welcome(version=__version__)
            except ImportError:
                activity.show_welcome()

            # Initialize status bar with local device
            status = self.query_one("#status-bar", StatusBar)
            platform_name = {"darwin": "macOS", "win32": "Windows"}.get(
                sys.platform, "Linux"
            )
            status.update_device(platform_name, "[L]")

            # Launch guided setup wizard
            self._start_wizard()

        # ----------------------------------------------------------
        # Replay mode
        # ----------------------------------------------------------

        def _init_replay_mode(self) -> None:
            """Initialize replay mode from a .tap file."""
            self.reload_replay(self._replay_file)

        def reload_replay(self, path: str) -> None:
            """Load *path* (.tap) into the running replay/flow view.

            Reusable entry point: used both for the initial replay launch and
            to swap in a freshly decrypted .tap produced from a capture.
            """
            from pathlib import Path
            from ..replay_controller import ReplayController
            from friTap.flow.models import Flow, FlowState

            self._replay_file = path
            filename = Path(path).name
            self._replay_filename = filename

            # Clear any previously loaded flows (table + backing store) so a
            # reload replaces rather than appends.
            try:
                self.query_one("#flow-list", FlowListWidget).clear_flows()
            except Exception:
                pass

            try:
                self._replay_ctrl = ReplayController(path)
                self._replay_ctrl.load()
            except Exception as e:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Failed to open {filename}:\n\n{e}",
                        title="Replay Error",
                        severity="error",
                    )
                )
                return

            # Activate flow view immediately (hides left panel + activity log)
            self._activate_flow_view()

            # Update title for replay mode
            count = self._replay_ctrl.flow_count
            try:
                title = self.query_one("#activity-title", Static)
                title.update(
                    f"[bold {c('primary')}]friTap Replay[/]  "
                    f"[dim]{filename} ({count} flow{'s' if count != 1 else ''})"
                    f" | Enter: details | /: filter | a: analyzers | w: export | q: quit[/]"
                )
            except Exception:
                pass
            self._update_capture_indicator()

            # Populate flow list from summaries
            from friTap.parsers.base import ParseResult
            from friTap.flow.reparse import reparse_flow
            flow_list = self.query_one("#flow-list", FlowListWidget)
            for summary in self._replay_ctrl.get_summaries():
                flow = Flow(
                    flow_id=summary.flow_id,
                    connection_id=summary.connection_id,
                    src_addr=summary.src_addr,
                    src_port=summary.src_port,
                    dst_addr=summary.dst_addr,
                    dst_port=summary.dst_port,
                    ssl_session_id=summary.ssl_session_id,
                    state=FlowState.COMPLETE,
                    started=summary.started,
                    ended=summary.ended,
                    transport=getattr(summary, "transport", "tls") or "tls",
                )
                has_parsed_request = (
                    summary.method or summary.url or summary.host
                    or summary.protocol not in ("unknown", "")
                )
                if has_parsed_request:
                    flow.request = ParseResult(
                        protocol=summary.protocol,
                        method=summary.method,
                        url=summary.url,
                        host=summary.host,
                        is_request=True,
                        is_complete=True,
                        is_control_frame=summary.is_control_frame,
                    )
                if summary.status_code > 0:
                    flow.response = ParseResult(
                        status_code=summary.status_code,
                        status_text=summary.status_text,
                        body_size=summary.body_size,
                        is_request=False,
                        is_complete=True,
                    )
                # Re-parse flows that can benefit from updated parsers:
                # - Unknown protocol (legacy .tap files)
                # - HTTP/2 ghost flows (old code skipped control frames)
                # - WebSocket with non-UTF-8 TEXT body (old code missed decompression)
                if summary.total_size > 0 and _needs_reparse(flow, summary):
                    full_flow = self._replay_ctrl.get_flow(summary.flow_id)
                    if full_flow is not None and reparse_flow(full_flow):
                        flow.request = full_flow.request
                        flow.response = full_flow.response
                        self._replay_ctrl.store_reparse(
                            summary.flow_id, full_flow.request, full_flow.response,
                        )

                flow._total_bytes = summary.total_size
                # Carry the layered protocol-display scalars onto the synthetic
                # (layerless) flow so FlowSummary.from_flow can recover them: the
                # synthetic flow has no layer stack, so layered_scalars_from_flow
                # would otherwise return "" and the list would show ???/—.
                flow.outer_app_protocol = summary.outer_app_protocol
                flow.inner_e2e_protocol = summary.inner_e2e_protocol
                flow.inner_summary = summary.inner_summary
                # Same rationale for the derived TL Method scalar.
                flow.flow_method = getattr(summary, "flow_method", "")
                flow_list.add_or_update_flow(flow)

        # ----------------------------------------------------------
        # Offline decrypt -> flow view
        # ----------------------------------------------------------

        def start_decrypt_to_flow(
            self, pcap: str, keylog: str, protocol: str = "tls"
        ) -> None:
            """Decrypt *pcap* with the captured *keylog* into the flow view.

            Builds per-protocol keylog arguments from the offline-decryptor
            registry (each protocol's keylog is a ``split_keylog_path`` sibling
            of the TLS keylog, passed only when it exists), then runs the
            conversion in a thread worker and reloads the resulting .tap.
            """
            args = self._build_convert_args(
                pcap=pcap, keylog=keylog, proto_keylog="",
                protocol=protocol, tap="",
            )
            if args is None:
                return
            self._launch_decrypt_worker(args)

        def start_decrypt_to_flow_multi(
            self, pcap: str, keylog_files: dict, tap: str = ""
        ) -> None:
            """Decrypt *pcap* using an already-resolved per-protocol keylog map.

            The post-capture decrypt offer passes the authoritative
            ``{protocol: keylog_path}`` map (resolved by ``active_keylog_paths``,
            the same source the Capture Results modal uses), so the single-keylog
            candidate resolution in :meth:`_build_convert_args` is bypassed. This is
            critical for multi-protocol captures (e.g. Signal, which splits the -k
            keylog into ``.tls.log`` + ``.signal.log``): re-resolving from one base
            path can misroute a protocol's keylog to the TLS log and decrypt 0
            messages.
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
            from ..modals.open_pcap_modal import OpenPcapModal

            def _on_result(result) -> None:
                if not result:
                    return
                args = self._build_convert_args(
                    pcap=result.get("pcap", ""),
                    keylog=result.get("keylog", ""),
                    proto_keylog=result.get("proto_keylog", ""),
                    protocol=result.get("protocol", "tls") or "tls",
                    tap=result.get("tap", ""),
                )
                if args is None:
                    return
                self._launch_decrypt_worker(args)

            self.app.push_screen(OpenPcapModal(), callback=_on_result)

        def _build_convert_args(
            self,
            pcap: str,
            keylog: str,
            proto_keylog: str,
            protocol: str,
            tap: str,
        ) -> dict | None:
            """Assemble keyword args for ``convert_pcap_to_tap``.

            Returns ``None`` (after notifying) when the pcap is missing.
            """
            import os
            from friTap.output.keylog_paths import split_keylog_path

            if not pcap or not os.path.isfile(pcap):
                self.app.notify(
                    f"PCAP not found: {pcap or '(empty)'}",
                    severity="error",
                )
                return None

            # TLS keylog: prefer the per-TLS split sibling if it exists.
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
                # Resolve this protocol's keylog: an explicit per-protocol path
                # (when the chosen protocol matches), else the UNSPLIT base keylog
                # when the chosen protocol matches (a single-protocol capture, e.g.
                # --protocol mtproto, writes its keys straight to the base path with
                # no `<base>.<proto>.log` sibling), else the split sibling of the
                # base TLS keylog (multi-protocol captures). Without the base-keylog
                # candidate an MTProto/Signal-only capture resolves to None and the
                # protocol decryptor is silently skipped (-> 0 flows).
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

            # signal_keylog/mtproto_keylog are convert_pcap_to_tap's back-compat
            # named args, derived from the generic map (mirrors cli.merge_manifest).
            return {
                "pcap_path": pcap,
                "keylog_path": tls_keylog,
                "tap_path": tap_path,
                "signal_keylog": protocol_keylogs.get("signal"),
                "mtproto_keylog": protocol_keylogs.get("mtproto"),
                "protocol_keylogs": protocol_keylogs or None,
                "tshark_path": None,
            }

        def _build_convert_args_multi(
            self,
            pcap: str,
            tls_keylog: str,
            protocol_keylogs: dict[str, str],
            tap: str,
        ) -> dict | None:
            """Assemble ``convert_pcap_to_tap`` kwargs from a pcap plus an explicit
            TLS keylog and a map of per-protocol (layered) keylogs.

            Unlike :meth:`_build_convert_args` (which resolves a *single* protocol
            keylog from split siblings of one base keylog), this variant takes the
            already-collected ``{protocol_name: keylog_path}`` map produced by the
            pcap-to-tap wizard, so several layered keylogs (e.g. Signal AND
            Telegram) can be supplied at once. Only entries pointing at an existing
            file are kept; a missing backend is surfaced (non-blocking) for each.

            Returns ``None`` (after notifying) when the pcap is missing.
            """
            import os

            if not pcap or not os.path.isfile(pcap):
                self.app.notify(
                    f"PCAP not found: {pcap or '(empty)'}",
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

            # signal_keylog/mtproto_keylog are convert_pcap_to_tap's back-compat
            # named args, derived from the generic map (mirrors _build_convert_args).
            return {
                "pcap_path": pcap,
                "keylog_path": resolved_tls,
                "tap_path": tap_path,
                "signal_keylog": resolved_protocols.get("signal"),
                "mtproto_keylog": resolved_protocols.get("mtproto"),
                "protocol_keylogs": resolved_protocols or None,
                "tshark_path": None,
            }

        def _warn_if_backend_missing(self, protocol: str) -> None:
            """Notify (non-blocking) if a protocol's decrypt backend is absent."""
            try:
                if protocol == "signal":
                    from friTap.offline.signal import (
                        signal_backend_available, SIGNAL_DEPENDENCY_HINT,
                    )
                    if not signal_backend_available():
                        self.app.notify(SIGNAL_DEPENDENCY_HINT, severity="warning")
                elif protocol == "mtproto":
                    from friTap.offline.mtproto import (
                        mtproto_backend_available, MTPROTO_DEPENDENCY_HINT,
                    )
                    if not mtproto_backend_available():
                        self.app.notify(MTPROTO_DEPENDENCY_HINT, severity="warning")
            except Exception:
                pass

        def _launch_decrypt_worker(self, args: dict) -> None:
            """Run the offline conversion in a thread worker."""
            self.app.notify("Decrypting captured traffic...", severity="information")
            self.run_worker(
                lambda: self._decrypt_worker(args),
                thread=True,
                exclusive=True,
                group="decrypt",
            )

        def _decrypt_worker(self, args: dict) -> None:
            """Worker body: convert the pcap, then return to the UI thread."""
            from textual.worker import get_current_worker
            from friTap.offline.pcap_to_tap import convert_pcap_to_tap

            worker = get_current_worker()
            try:
                result = convert_pcap_to_tap(**args)
            except Exception as e:  # conversion failed
                if not worker.is_cancelled:
                    self.app.call_from_thread(self._on_decrypt_error, str(e))
                return
            if worker.is_cancelled:
                return
            self.app.call_from_thread(
                self._on_decrypt_done, args["tap_path"], result
            )

        def _on_decrypt_done(self, tap_path: str, result) -> None:
            """UI-thread handler: load the produced .tap into the flow view."""
            import os
            flow_count = getattr(result, "flow_count", 0)
            if flow_count > 0:
                self.reload_replay(tap_path)
                self.app.notify(
                    f"Decrypted {flow_count} flow"
                    f"{'s' if flow_count != 1 else ''} -> {os.path.basename(tap_path)}",
                    severity="information",
                )
                # A successful decrypt can still be PARTIAL: streams whose
                # connection-start bytes were missed (capture began after the
                # connection opened) are silently skipped for obfuscated
                # transports (MTProto/Signal). Warn so the user knows messages on
                # those streams are absent and how to recover them — otherwise the
                # "Decrypted N flows" success message hides the gap.
                degraded = (
                    getattr(result, "mtproto_streams_degraded", 0)
                    + getattr(result, "signal_streams_degraded", 0)
                )
                if degraded > 0:
                    self.app.notify(
                        f"{degraded} stream{'s' if degraded != 1 else ''} started "
                        "mid-connection and could not be decrypted — messages on "
                        f"{'those' if degraded != 1 else 'that'} stream"
                        f"{'s' if degraded != 1 else ''} are missing. Re-capture from "
                        "connection start (spawn mode) to recover them.",
                        severity="warning",
                    )
                return

            # 0 flows: explain *why* instead of a bare message. Degraded streams
            # (capture started after the connection opened) are the common cause
            # for non-TLS protocols whose obfuscated transport needs the
            # connection-start bytes; undecryptable records mean the matching key
            # was not in the keylog.
            degraded = (
                getattr(result, "mtproto_streams_degraded", 0)
                + getattr(result, "signal_streams_degraded", 0)
            )
            undecryptable = (
                getattr(result, "mtproto_records_undecryptable", 0)
                + getattr(result, "signal_records_undecryptable", 0)
            )
            if degraded > 0:
                message = (
                    f"Decrypted 0 flows: {degraded} stream"
                    f"{'s' if degraded != 1 else ''} started mid-connection "
                    "(capture began after the connection opened). Re-capture from "
                    "connection start — open chats/scroll to force new connections, "
                    "or use spawn mode."
                )
            elif undecryptable > 0:
                message = (
                    f"Decrypted 0 flows: {undecryptable} record"
                    f"{'s' if undecryptable != 1 else ''} had no matching key in the "
                    "keylog (key not captured this session)."
                )
            else:
                message = "Decryption produced no flows."

            # Still load the (empty) tap if one was written, to keep the view consistent.
            if os.path.isfile(tap_path):
                self.reload_replay(tap_path)
            self.app.notify(message, severity="warning")

        def _on_decrypt_error(self, message: str) -> None:
            """UI-thread handler: report a conversion failure."""
            self.app.notify(f"Decrypt failed: {message}", severity="error")

        def _all_flows(self) -> list:
            """Every flow in the current view (replay file or live collector)."""
            if self._replay_ctrl is not None:
                return self._replay_ctrl.get_flows()
            collector = self._capture.flow_collector
            return collector.get_flows() if collector else []

        @staticmethod
        def _signal_server_endpoint(flow):
            """The (addr, port) of the service side — the lower port (e.g. 443)."""
            if flow.src_port <= flow.dst_port:
                return (flow.src_addr, flow.src_port)
            return (flow.dst_addr, flow.dst_port)

        def _signal_conversation_siblings(self, flow) -> list:
            """Signal flows of this session sharing the same chat-server endpoint.

            Signal splits one logical conversation across several TCP connections
            (outbound vs inbound, plus metadata fetches, on different local ports to
            the same chat server). One websocket multiplexes all conversations, so
            grouping by the service endpoint alone reunites them — the Message tab
            then renders one merged, time-ordered transcript. (chat_type is NOT part
            of the key: a single connection carries both 1:1 and group messages, and
            metadata-only connections have an empty chat_type.)
            """
            if getattr(flow, "transport", "") != "signal":
                return []
            key = self._signal_server_endpoint(flow)
            # Identify siblings from the cheap in-memory summaries, then load
            # only the matches as full Flows (on-demand, LRU-cached). This avoids
            # decoding EVERY flow in the .tap (chunks + bodies + layers) on every
            # detail-open just to test transport == "signal".
            if self._replay_ctrl is not None:
                sibling_ids = [
                    s.flow_id
                    for s in self._replay_ctrl.get_summaries()
                    if getattr(s, "transport", "") == "signal"
                    and self._signal_server_endpoint(s) == key
                ]
                siblings = [self._replay_ctrl.get_flow(fid) for fid in sibling_ids]
                return [f for f in siblings if f is not None]
            # Live mode: flows are already fully materialized in the collector,
            # so iterating them in memory is cheap (no disk re-read).
            collector = self._capture.flow_collector
            flows = collector.get_flows() if collector else []
            return [
                f for f in flows
                if getattr(f, "transport", "") == "signal"
                and self._signal_server_endpoint(f) == key
            ]

        def _present_flow_detail(self, flow) -> None:
            """Show the flow detail widget for a given Flow object."""
            self.query_one("#flow-list").display = False
            self.query_one("#left-panel").display = False
            self._hide_findings_widgets()
            detail = self.query_one("#flow-detail", FlowDetailWidget)
            # Reunite the Signal conversation's per-connection flows (empty for
            # non-Signal flows -> single-flow behavior) before rendering.
            try:
                detail.set_conversation_siblings(
                    self._signal_conversation_siblings(flow)
                )
            except Exception:
                detail.set_conversation_siblings([])
            detail.show_flow(flow)
            detail.display = True
            self._update_detail_title()

            def _focus_tabs():
                try:
                    inner_tabs = detail.query_one("#flow-tabs Tabs")
                    inner_tabs.focus()
                except Exception:
                    detail.focus()
                detail.scroll_to_top()

            self.call_after_refresh(_focus_tabs)

        def action_save_tap(self) -> None:
            """Show save dialog for .tap file export."""
            # In replay mode, re-export is available too
            if self._replay_ctrl is not None:
                collector_has_flows = self._replay_ctrl.flow_count > 0
            else:
                collector_has_flows = (
                    self._capture.flow_collector is not None
                    and len(self._capture.flow_collector.get_flows()) > 0
                )

            if not collector_has_flows:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message="No flows to save.\nStart a capture with flow view first.",
                        title="Save Capture",
                        severity="warning",
                    )
                )
                return

            from ..modals.save_tap_modal import SaveTapModal
            self.app.push_screen(SaveTapModal(), callback=self._on_save_tap_result)

        def _on_save_tap_result(self, path: str | None) -> None:
            """Handle the result from SaveTapModal."""
            if path is None:
                return

            if self._replay_ctrl is not None:
                # Re-export from replay: write all flows to new file
                self._export_replay_to_tap(path)
            else:
                # Live capture: wire the TapWriter to the FlowCollector
                self._capture.start_tap_recording(path)

        def _export_replay_to_tap(self, path: str) -> None:
            """Export all replay flows to a new .tap file."""
            from friTap.flow.tap_writer import TapWriter

            try:
                writer = TapWriter()
                header = self._replay_ctrl.header
                target = header.capture_target if header else ""
                writer.open(path, target=target)

                # Findings to persist: the .tap's original stored findings
                # UNIONED with anything computed this session (deduped), grouped
                # by flow. Merging — rather than writing only the session cache —
                # means re-saving never drops findings the .tap already carried.
                findings_by_flow = self._collect_export_findings()

                written_ids: set[str] = set()
                for flow in self._replay_ctrl.get_flows():
                    writer.write_flow(flow)
                    written_ids.add(flow.flow_id)
                    flow_findings = findings_by_flow.get(flow.flow_id)
                    if flow_findings:
                        writer.write_findings(flow.flow_id, flow_findings)

                # Preserve findings whose flow_id isn't among the written flows
                # (e.g. cross-flow findings with an empty flow_id).
                for fid, flow_findings in findings_by_flow.items():
                    if fid not in written_ids and flow_findings:
                        writer.write_findings(fid, flow_findings)

                writer.close()

                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Exported {writer.flow_count} flows to:\n[bold]{path}[/]",
                        title="Export Complete",
                        severity="info",
                    )
                )
            except Exception as e:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Export failed:\n{e}",
                        title="Export Error",
                        severity="error",
                    )
                )

        def _collect_export_findings(self) -> "dict[str, list]":
            """Findings to persist on export, grouped by flow_id.

            Unions the .tap's original stored findings (read straight from the
            controller, independent of the session cache) with this session's
            analyzer results, deduplicated. This keeps re-saving non-destructive
            even though the in-session view uses a replace-per-run cache.
            """
            seen: set = set()
            by_flow: dict[str, list] = {}

            def add(item) -> None:
                finding = item
                if isinstance(item, dict):
                    try:
                        finding = Finding.from_dict(item)
                    except Exception:
                        return
                sev = getattr(finding, "severity", None)
                severity = getattr(sev, "value", sev)
                key = (
                    getattr(finding, "flow_id", ""),
                    getattr(finding, "source", ""),
                    severity,
                    getattr(finding, "title", ""),
                    getattr(finding, "description", ""),
                )
                if key in seen:
                    return
                seen.add(key)
                by_flow.setdefault(getattr(finding, "flow_id", ""), []).append(finding)

            try:
                for item in self._replay_ctrl.read_all_findings():
                    add(item)
            except Exception:
                pass
            for finding in (self._findings_cache or []):
                add(finding)
            return by_flow

        # ----------------------------------------------------------
        # State helpers
        # ----------------------------------------------------------

        def _get_state(self) -> "AppState":
            """Return the shared AppState from the app."""
            return self.app.app_state

        def _get_activity_log(self) -> ActivityLog:
            return self.query_one("#activity-log", ActivityLog)

        def _get_status_bar(self) -> StatusBar:
            return self.query_one("#status-bar", StatusBar)

        def _get_menu_panel(self) -> MenuPanel:
            return self.query_one("#menu-panel", MenuPanel)

        # ----------------------------------------------------------
        # Background checks
        # ----------------------------------------------------------

        def _check_server_status(self) -> None:
            """Check frida-server status in a worker thread (USB/remote only)."""
            state = self._get_state()
            if state.device_type == "local" or not state.device_id:
                return
            try:
                from friTap.backends import get_backend
                backend = get_backend()
                device = backend.get_device(mobile=state.device_id)
                is_running = backend.check_connectivity(device)
            except Exception:
                is_running = False
            server_status = "running" if is_running else "not running"
            def _update_ui():
                status = self._get_status_bar()
                status.update_device(status.device_name, status.device_type, server_status)
                self._get_menu_panel().server_running = is_running
            self.app.call_from_thread(_update_ui)

        # ----------------------------------------------------------
        # Wizard delegation
        # ----------------------------------------------------------

        def _wizard_guard(self) -> bool:
            """Return True if wizard is active (blocks manual actions)."""
            return self._wizard.guard()

        def _start_wizard(self) -> None:
            """Launch the guided setup wizard."""
            self._wizard.start()

        def _start_pcap_to_tap_wizard(self, pcap_path: str) -> None:
            """Launch the guided pcap-to-tap conversion wizard.

            Mirrors :meth:`_start_wizard` but drives the offline conversion flow:
            confirm the pcap input, choose the output .tap, supply a TLS keylog
            and one or more per-protocol (layered) keylogs, then convert and open
            the result in the replay view.
            """
            self._pcap_to_tap_wizard = PcapToTapWizard(self)
            self._pcap_to_tap_wizard.start(pcap_path)

        @property
        def _wizard_active(self) -> bool:
            return self._wizard.active

        @_wizard_active.setter
        def _wizard_active(self, value: bool) -> None:
            self._wizard.active = value

        # ----------------------------------------------------------
        # Capture delegation
        # ----------------------------------------------------------

        @property
        def _ssl_logger(self):
            return self._capture.ssl_logger

        @property
        def _tui_handler(self):
            return self._capture.tui_handler

        @property
        def _capture_mode(self) -> str:
            return self._capture.capture_mode

        @_capture_mode.setter
        def _capture_mode(self, value: str) -> None:
            self._capture.capture_mode = value

        def _build_config(self, state):
            return self._capture.build_config(state)

        def _start_capture(self, state) -> None:
            self._capture.start_capture(state)

        def action_start_capture(self) -> None:
            self._capture.action_start_capture()

        def action_stop_capture(self) -> None:
            self._capture.action_stop_capture()

        def stop_if_capturing(self) -> None:
            """Stop capture if one is running. Also cleans up replay. Safe to call from app shutdown."""
            if self._ssl_logger and self._ssl_logger.running:
                self._capture.action_stop_capture()
            if self._replay_ctrl is not None:
                self._replay_ctrl.close()
                self._replay_ctrl = None

        def action_toggle_capture(self) -> None:
            self._capture.action_toggle_capture()

        def action_escape_action(self) -> None:
            # Analyzer finding-detail → back to the findings list (filter kept).
            if self.query_one("#finding-detail").display:
                self._back_to_findings_list()
                return
            flow_detail = self.query_one("#flow-detail")
            if flow_detail.display:
                if self._detail_origin == "finding":
                    self._restore_finding_detail()
                else:
                    self._back_to_flow_list()
                return
            # Findings list → step up the hierarchy: a filtered (category) view
            # clears back to all findings, then all findings backs to the flows.
            if self._findings_list_displayed():
                if self.query_one("#findings-list", FindingsListWidget).has_filter:
                    self.action_clear_filter()
                else:
                    self._activate_flow_view()
                return
            if self._ssl_logger and self._ssl_logger.running:
                self._capture.action_escape_action()
                return
            # Not capturing → trigger quit confirmation
            self.app.action_quit()

        # ----------------------------------------------------------
        # Device selection
        # ----------------------------------------------------------

        def action_device_select(self) -> None:
            """Open the device selection modal."""
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(device_id: Optional[str]) -> None:
                if device_id is None:
                    return
                self._apply_device_selection(device_id)

            self.app.push_screen(
                DeviceSelectModal(current_device_id=state.device_id),
                callback=_on_result,
            )

        _DEVICE_TYPE_TAGS = {"local": "[L]", "usb": "[U]"}

        _PLATFORM_MAP = {"darwin": "macos", "win32": "windows"}

        def _apply_device_selection(self, device_id: str) -> None:
            """Apply the selected device to AppState and update UI."""
            state = self._get_state()
            state.device_id = device_id

            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                state.device_name = device.name
                state.device_type = device.type if device.type in ("local", "usb") else "remote"
                type_tag = self._DEVICE_TYPE_TAGS.get(state.device_type, "[R]")

                if state.device_type == "local":
                    state.device_platform = self._PLATFORM_MAP.get(sys.platform, "linux")
                elif state.device_type == "usb":
                    try:
                        params = device.query_system_parameters()
                        os_info = params.get("os", {})
                        state.device_platform = (
                            os_info.get("id", "unknown")
                            if isinstance(os_info, dict)
                            else "unknown"
                        )
                    except Exception:
                        state.device_platform = "unknown"
                else:
                    state.device_platform = "unknown"

                status = self._get_status_bar()
                status.update_device(device.name, type_tag)
                status.server_status = ""

                self._get_activity_log().log_success(f"Device selected: {type_tag} {device.name}")

                menu = self._get_menu_panel()
                menu.server_running = (state.device_type == "local")

                if state.device_type != "local" and not self._wizard_active:
                    self.run_worker(self._check_server_status, thread=True)

            except Exception as e:
                self._get_activity_log().log_error(f"Failed to select device: {e}")

        # ----------------------------------------------------------
        # Process attach / spawn
        # ----------------------------------------------------------

        def _apply_target(self, display_name: str, frida_target: str, is_spawn: bool) -> None:
            """Apply target selection to state and update UI widgets."""
            state = self._get_state()
            mode = "spawn" if is_spawn else "attach"
            mode_tag = mode.upper()

            state.target = frida_target
            state.target_display = display_name
            state.spawn = is_spawn
            self._get_status_bar().update_target(display_name, mode_tag)
            menu = self._get_menu_panel()
            menu.has_target = True
            menu.target_name = display_name
            menu.target_mode = mode
            self._get_activity_log().log_info(
                f"Target: [bold {c('target')}]{display_name}[/] [{mode_tag}]"
            )

        def _guard_target_change(self) -> bool:
            """Return True if target change should be blocked."""
            if self._wizard_guard():
                return True
            if self._ssl_logger and self._ssl_logger.running:
                self._get_activity_log().log_warning("Stop capture before changing target.")
                return True
            return False

        def action_attach(self) -> None:
            """Open the process selection modal."""
            if self._guard_target_change():
                return

            state = self._get_state()

            def _on_result(result) -> None:
                if result is None:
                    return
                display_name, frida_target, is_pid = result
                self._apply_target(display_name, frida_target, is_spawn=False)

            self.app.push_screen(
                ProcessSelectModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_result,
            )

        def action_spawn(self) -> None:
            """Open the spawn input modal."""
            if self.query_one("#flow-detail").display:
                return
            if self._guard_target_change():
                return

            def _on_result(target: Optional[str]) -> None:
                if target is None:
                    return
                self._apply_target(target, target, is_spawn=True)

            state = self._get_state()
            self.app.push_screen(
                SpawnInputModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_result,
            )

        # ----------------------------------------------------------
        # Capture mode presets
        # ----------------------------------------------------------

        def action_set_mode_1(self) -> None:
            """Full capture (keys + pcap)."""
            self._mode_ctrl.set_mode(1)

        def action_set_mode_2(self) -> None:
            """Key extraction only."""
            self._mode_ctrl.set_mode(2)

        def action_set_mode_3(self) -> None:
            """Plaintext pcap."""
            self._mode_ctrl.set_mode(3)

        def action_set_mode_4(self) -> None:
            """Live Wireshark pipe."""
            self._mode_ctrl.set_mode(4)

        def action_set_mode_5(self) -> None:
            """Live Wireshark with auto-decrypt (PCAPNG+DSB)."""
            self._mode_ctrl.set_mode(5)

        def _apply_mode(self, mode_id: str, display: str, config: dict) -> None:
            """Apply a capture mode from the modal result."""
            state = self._get_state()
            state.keylog_path = config.get("keylog", "")
            state.pcap_path = config.get("pcap", "")
            state.live = config.get("live", False)
            state.live_mode = config.get("live_mode", "")
            state.full_capture = config.get("full_capture", False)

            self._capture_mode = mode_id
            self._get_status_bar().update_capture("IDLE", display)
            menu = self._get_menu_panel()
            menu.current_mode = mode_id
            menu.keylog_path = state.keylog_path
            menu.pcap_path = state.pcap_path
            self._get_activity_log().log_info(f"Capture mode: [bold]{display}[/]")
            if state.keylog_path:
                self._get_activity_log().log_info(f"  -> Keys: {state.keylog_path}")
            if state.pcap_path:
                self._get_activity_log().log_info(f"  -> Output: {state.pcap_path}")

        # ----------------------------------------------------------
        # Log management
        # ----------------------------------------------------------

        def action_clear_log(self) -> None:
            """Clear the activity log."""
            self._get_activity_log().clear()

        def action_copy_log(self) -> None:
            """Copy activity log to clipboard."""
            log = self._get_activity_log()
            text = log.get_plain_text()
            if text:
                self.app.copy_to_clipboard(text)
                log.log_success(f"Copied {log.get_line_count()} lines to clipboard")
            else:
                log.log_warning("Nothing to copy -- log is empty.")

        # ----------------------------------------------------------
        # Setup / server management
        # ----------------------------------------------------------

        def action_install_server(self) -> None:
            """Install frida-server on the selected device."""
            if self._wizard_guard():
                return
            state = self._get_state()
            if self._get_menu_panel().server_running:
                self._get_activity_log().log_info("frida-server is already running.")
                return
            if state.device_type == "local":
                self._get_activity_log().log_warning("Local device does not need frida-server.")
                return

            if not state.device_id:
                self._get_activity_log().log_warning("Select a device first (press [bold]d[/]).")
                return

            self._get_activity_log().log_info("Installing frida-server...")
            self.run_worker(lambda: self._do_install_server(state.device_id), thread=True)

        def _do_install_server(self, device_id: str) -> None:
            """Background worker for frida-server installation."""
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info(
                        f"Installing frida-server for {device.name} ({mgr.platform_name})..."
                    )
                )

                def _progress(msg: str) -> None:
                    self.app.call_from_thread(
                        lambda: self._get_activity_log().log_info(msg)
                    )

                mgr.install(device, callback=_progress)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info("Starting frida-server...")
                )
                mgr.start(device)

                def _on_install_success():
                    self._get_activity_log().log_success("frida-server installed and started!")
                    self._get_menu_panel().server_running = True
                    self._get_status_bar().server_status = "running"
                self.app.call_from_thread(_on_install_success)
            except Exception as e:
                def _log_install_error(err=e):
                    self._get_activity_log().log_error(f"Install failed: {err}")
                self.app.call_from_thread(_log_install_error)

        # ----------------------------------------------------------
        # Options toggles
        # ----------------------------------------------------------

        def action_verbose_toggle(self) -> None:
            """Toggle verbose mode."""
            state = self._get_state()
            state.verbose = not state.verbose
            menu = self._get_menu_panel()
            menu.verbose = state.verbose
            label = "ON" if state.verbose else "OFF"
            self._get_activity_log().log_info(f"Verbose: {label}")

        def action_experimental_toggle(self) -> None:
            """Toggle experimental mode."""
            state = self._get_state()
            # Store experimental in a simple attribute
            if not hasattr(state, '_experimental'):
                state._experimental = False
            state._experimental = not state._experimental
            menu = self._get_menu_panel()
            menu.experimental = state._experimental
            label = "ON" if state._experimental else "OFF"
            self._get_activity_log().log_info(f"Experimental: {label}")

        def action_protocol_select(self) -> None:
            """Open the protocol selection modal."""
            if self.query_one("#flow-detail").display:
                return
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(protocol: Optional[str]) -> None:
                if protocol is None:
                    return
                state.protocol = protocol
                self._get_status_bar().protocol = protocol
                self._get_activity_log().log_info(f"Protocol: {protocol.upper()}")

            self.app.push_screen(ProtocolSelectModal(), callback=_on_result)

        # ----------------------------------------------------------
        # Flow view management
        # ----------------------------------------------------------

        def _activate_flow_view(self) -> None:
            """Switch right panel to full-screen flow list view."""
            self.query_one("#activity-log").display = False
            self.query_one("#flow-detail").display = False
            self._hide_findings_widgets()
            self.query_one("#flow-list").display = True
            self.query_one("#filter-bar").display = True
            self.query_one("#left-panel").display = False
            self.query_one("#right-panel").add_class("flow-mode")
            self.query_one("#flow-list").focus()
            self._update_flow_title()

        @property
        def _mode_label(self) -> str:
            return "friTap Replay" if self._replay_ctrl else "friTap Flow View"

        def _set_title_hints(self, hint_str: str) -> None:
            """Update the activity title bar with the given hint text.

            The caller is responsible for any inline markup (e.g. [dim]).
            """
            try:
                title = self.query_one("#activity-title", Static)
                title.update(
                    f"[bold {c('primary')}]{self._mode_label}[/]  {hint_str}"
                )
            except Exception:
                pass

        def _update_flow_title(self) -> None:
            """Update the flow view title bar based on current state."""
            capturing = self._ssl_logger and self._ssl_logger.running
            hints: list[str] = [
                "[dim]Enter: flow details[/]",
                "[dim]/: filter[/]",
            ]
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if filter_bar.has_active_filter:
                    hints.append("[dim]Shift+Esc: clear filter[/]")
            except Exception:
                pass
            hints.append("[dim]a: analyzers[/]")
            hints.append("[dim]w: save .tap[/]")
            if self._replay_ctrl is None:
                hints.append("[dim]f: console view[/]")
            if capturing:
                hints.append(f"[bold {c('success')}]Esc: stop capture[/]")
            self._set_title_hints(" [dim]|[/] ".join(hints))
            self._update_capture_indicator()

        def _update_capture_indicator(self) -> None:
            """Refresh the left-pinned indicator: ▣ TAP / ● CAPTURING / ■ stopped."""
            try:
                ind = self.query_one("#capture-indicator", Static)
            except Exception:
                return

            if self._replay_ctrl is not None:
                ind.update(f"[bold {c('info')}]▣ TAP: {self._replay_filename or 'tap'}[/]")
                return

            capturing = self._ssl_logger and self._ssl_logger.running
            if capturing:
                ind.update(f"[bold {c('error')}]● CAPTURING[/]")
            else:
                ind.update("[dim]■ stopped[/]")

        def _clear_title_indicators(self) -> None:
            """Blank the left indicator and right spacer (used outside flow view)."""
            try:
                self.query_one("#capture-indicator", Static).update("")
                self.query_one("#title-spacer", Static).update("")
            except Exception:
                pass

        def _update_detail_title(self) -> None:
            """Update the title bar with detail-view hints."""
            self._clear_title_indicators()
            self._set_title_hints("[dim]Esc: back | Tab: switch tabs | p: parse | s: save body[/]")

        def _activate_legacy_view(self) -> None:
            """Switch right panel to legacy activity log view."""
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#filter-bar").display = False
            self._hide_findings_widgets()
            self.query_one("#activity-log").display = True
            self.query_one("#left-panel").display = True
            self.query_one("#right-panel").remove_class("flow-mode")
            self._clear_title_indicators()
            try:
                title = self.query_one("#activity-title", Static)
                capturing = self._ssl_logger and self._ssl_logger.running
                suffix = f"  [bold {c('success')} on {c('bg-capture')}] CAPTURING [/]" if capturing else ""
                title.update(f"[bold {c('success')}]friTap Console[/]{suffix}  [dim]press f to toggle[/]")
            except Exception:
                pass

        def _lookup_flow(self, flow_id: str):
            """Load a full Flow by id from the replay controller or live collector."""
            if self._replay_ctrl is not None:
                return self._replay_ctrl.get_flow(flow_id)
            collector = self._capture.flow_collector
            return collector.get_flow(flow_id) if collector else None

        def _show_flow_detail(self, flow_id: str) -> None:
            """Show the regular flow-detail view for a specific flow (from the flow list)."""
            flow = self._lookup_flow(flow_id)
            if not flow:
                return
            self._detail_origin = "flow"
            self._present_flow_detail(flow)

        def _back_to_flow_list(self) -> None:
            """Return from detail view to flow list."""
            self.query_one("#flow-detail").display = False
            self.query_one("#flow-list").display = True
            self.query_one("#flow-list").focus()
            self._update_flow_title()

        def on_flow_list_widget_flow_selected(self, event: FlowListWidget.FlowSelected) -> None:
            """Handle flow selection from the flow list."""
            self._show_flow_detail(event.flow_id)

        def on_flow_detail_widget_back_requested(self, event: FlowDetailWidget.BackRequested) -> None:
            """Handle back request from flow detail.

            If the flow detail was opened from a finding (via ``d``), step back
            to the analyzer finding-detail view; otherwise to the flow list.
            """
            if self._detail_origin == "finding":
                self._restore_finding_detail()
            else:
                self._back_to_flow_list()

        def _restore_finding_detail(self) -> None:
            """Return from the regular flow detail to the analyzer finding detail."""
            self._detail_origin = "finding"
            self.query_one("#flow-detail").display = False
            detail = self.query_one("#finding-detail", AnalyzerFindingDetailWidget)
            detail.display = True
            self._update_finding_detail_title()
            detail.focus()

        # ----------------------------------------------------------
        # Findings view management
        # ----------------------------------------------------------

        def _findings_list_displayed(self) -> bool:
            """Return True if the findings list is currently displayed."""
            try:
                return bool(self.query_one("#findings-list").display)
            except Exception:
                return False

        def _hide_findings_widgets(self) -> None:
            """Hide the findings list, filter bar + finding detail (no-op if not yet composed)."""
            try:
                self.query_one("#findings-list").display = False
                self.query_one("#findings-filter-bar").display = False
                self.query_one("#finding-detail").display = False
            except Exception:
                pass

        def _load_findings(self) -> list:
            """Lazily load and cache findings as Finding objects.

            Sources findings from the replay controller (offline .tap) via the
            presentation-agnostic ``read_all_findings`` passthrough.
            """
            if self._findings_cache is not None:
                return self._findings_cache

            findings: list = []
            if self._replay_ctrl is not None:
                try:
                    for item in self._replay_ctrl.read_all_findings():
                        try:
                            # read_findings() reconstructs Finding objects, but
                            # accept plain dicts too for forward-compatibility.
                            if isinstance(item, Finding):
                                findings.append(item)
                            elif isinstance(item, dict):
                                findings.append(Finding.from_dict(item))
                        except Exception:
                            continue
                except Exception:
                    findings = []

            self._findings_cache = findings
            return findings

        def _activate_findings_view(self) -> None:
            """Switch right panel to full-screen findings list view."""
            findings = self._load_findings()

            findings_list = self.query_one("#findings-list", FindingsListWidget)
            if findings_list.total_count == 0 and findings:
                findings_list.add_findings(findings)

            # Hide other right-panel views and the left panel.
            self.query_one("#activity-log").display = False
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#finding-detail").display = False
            self.query_one("#filter-bar").display = False
            self.query_one("#analyzer-panel").display = False
            self.query_one("#left-panel").display = False
            self.query_one("#right-panel").add_class("flow-mode")

            # Show findings widgets.
            self.query_one("#findings-filter-bar").display = True
            findings_list.display = True

            self._update_findings_title()
            findings_list.focus()

        def _update_findings_title(self) -> None:
            """Update the title bar with findings-view hints."""
            try:
                findings_list = self.query_one("#findings-list", FindingsListWidget)
                total = findings_list.total_count
            except Exception:
                total = 0

            if total == 0:
                hint = "[dim]No findings — re-run with --scan[/]"
            else:
                hints = [
                    f"[dim]{total} finding{'s' if total != 1 else ''}[/]",
                    "[dim]Enter: open[/]",
                    "[dim]/: filter[/]",
                    "[dim]c: creds  p: pii  1: critical[/]",
                    "[dim]Esc: back[/]",
                    "[dim]w: save[/]",
                    "[dim]shift+f: flows[/]",
                ]
                hint = " [dim]|[/] ".join(hints)
            self._set_title_hints(hint)
            self._update_capture_indicator()

        def action_toggle_findings_view(self) -> None:
            """Toggle the findings view (Shift+F)."""
            if self._findings_list_displayed():
                self._activate_flow_view()
            else:
                self._activate_findings_view()

        def _apply_findings_filter(self, flt: "FindingFilter", label: str) -> None:
            """Apply a findings filter via the findings filter bar."""
            try:
                bar = self.query_one("#findings-filter-bar", FindingsFilterBar)
                bar.apply_filter(flt, label)
            except Exception:
                pass

        def action_findings_quick_creds(self) -> None:
            """Quick filter to credential findings (c key, findings view only)."""
            if not self._findings_list_displayed():
                return
            self._apply_findings_filter(
                FindingFilter(sources=frozenset({"credentials"})), "credentials"
            )

        def action_findings_quick_pii(self) -> None:
            """Quick filter to PII findings (p key, findings view only)."""
            if not self._findings_list_displayed():
                return
            self._apply_findings_filter(
                FindingFilter(categories=frozenset({"pii"})), "pii"
            )

        def action_findings_quick_critical(self) -> None:
            """Quick filter to critical findings (1 key, findings view only)."""
            if not self._findings_list_displayed():
                return
            self._apply_findings_filter(
                FindingFilter(min_severity="critical"), "critical"
            )

        def on_findings_filter_bar_findings_filter_changed(
            self, event: "FindingsFilterBar.FindingsFilterChanged"
        ) -> None:
            """Apply the filter from the findings filter bar to the list."""
            try:
                findings_list = self.query_one("#findings-list", FindingsListWidget)
                findings_list.set_filter(event.flt)
            except Exception:
                pass

        def on_findings_list_widget_finding_selected(
            self, event: "FindingsListWidget.FindingSelected"
        ) -> None:
            """When a finding is selected, open the analyzer finding-detail view."""
            findings_list = self.query_one("#findings-list", FindingsListWidget)
            finding = findings_list.finding_at(event.index)
            if finding is None:
                return
            flow = self._lookup_flow(event.flow_id) if event.flow_id else None
            self._present_finding_detail(finding, flow)

        # ----------------------------------------------------------
        # Analyzer finding-detail view (finding-centric, with base64 decode)
        # ----------------------------------------------------------

        def _present_finding_detail(self, finding, flow) -> None:
            """Show the finding-centric detail view for a selected finding."""
            self._detail_origin = "finding"
            self.query_one("#findings-list").display = False
            self.query_one("#findings-filter-bar").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#left-panel").display = False
            self.query_one("#right-panel").add_class("flow-mode")
            detail = self.query_one("#finding-detail", AnalyzerFindingDetailWidget)
            detail.show_finding(finding, flow)
            detail.display = True
            self._update_finding_detail_title()

            def _focus():
                detail.focus()
                detail.scroll_to_top()
            self.call_after_refresh(_focus)

        def _back_to_findings_list(self) -> None:
            """Return from the finding detail to the findings list (filter preserved)."""
            self.query_one("#finding-detail").display = False
            self.query_one("#flow-detail").display = False
            self._activate_findings_view()

        def _update_finding_detail_title(self) -> None:
            """Title-bar hints for the analyzer finding-detail view."""
            self._clear_title_indicators()
            self._set_title_hints(
                "[dim]Esc: back to findings | d: full flow detail | b: base64 decode[/]"
            )

        def on_analyzer_finding_detail_widget_back_requested(
            self, event: "AnalyzerFindingDetailWidget.BackRequested"
        ) -> None:
            """Esc in the finding detail → back to the findings list."""
            self._back_to_findings_list()

        def on_analyzer_finding_detail_widget_full_detail_requested(
            self, event: "AnalyzerFindingDetailWidget.FullDetailRequested"
        ) -> None:
            """'d' in the finding detail → switch to the regular flow-detail view."""
            flow = self._lookup_flow(event.flow_id) if event.flow_id else None
            if flow is None:
                return
            self.query_one("#finding-detail").display = False
            self._detail_origin = "finding"
            self._present_flow_detail(flow)

        # ----------------------------------------------------------
        # Analyzer panel (run analyzers interactively over loaded flows)
        # ----------------------------------------------------------

        def _has_capture_flows(self) -> bool:
            """True when a live-capture flow collector holds at least one flow."""
            try:
                collector = self._capture.flow_collector
                return bool(collector and collector.get_flows())
            except Exception:
                return False

        def _analyzer_panel(self) -> "AnalyzerPanel":
            return self.query_one("#analyzer-panel", AnalyzerPanel)

        def action_analyzer_panel(self) -> None:
            """Toggle the analyzer panel ('a').

            Only meaningful when flows are loaded (replay, or a live capture with
            flows). Outside that context 'a' keeps its capture meaning (attach).
            """
            if self._replay_ctrl is None and not self._has_capture_flows():
                self.action_attach()
                return

            panel = self._analyzer_panel()
            if panel.display:
                panel.display = False
                try:
                    self.query_one("#flow-list").focus()
                except Exception:
                    pass
                return

            # The panel docks above the flow list; if we're currently in the
            # findings view, return to the flow view first so the panel isn't
            # stacked on top of the findings list.
            if self._findings_list_displayed():
                self._activate_flow_view()

            panel.set_available(available_analyzers())
            panel.reset()
            panel.display = True
            panel.focus()

        def on_analyzer_panel_run_requested(
            self, event: "AnalyzerPanel.RunRequested"
        ) -> None:
            """Run the selected analyzers over the loaded flows in a worker."""
            if not event.analyzer_names:
                self._analyzer_panel().set_progress(0, 0, label="select at least one analyzer")
                return
            names = list(event.analyzer_names)
            path = event.analyzer_path
            # Bump the run token so any in-flight worker's late completion is
            # recognised as stale and ignored.
            self._analyzer_run_id += 1
            run_id = self._analyzer_run_id
            # Dedicated group so exclusive=True only cancels a prior analyzer
            # run — NOT unrelated default-group workers (the live capture
            # session, server checks/installs).
            self.run_worker(
                lambda: self._run_analyzers_worker(names, path, run_id),
                thread=True,
                exclusive=True,
                group="analyzer",
            )

        def _run_analyzers_worker(self, names: list, analyzer_path, run_id: int) -> None:
            """Worker body: resolve analyzers, run them over flows, collect findings.

            Runs in a thread. Because thread workers cannot be force-killed, we
            poll the worker's cancellation flag and tag the result with *run_id*
            so a superseded run never overwrites a newer one's state.
            """
            from textual.worker import get_current_worker

            worker = get_current_worker()
            panel = self._analyzer_panel()
            try:
                analyzers = resolve_analyzers(",".join(names), analyzer_path=analyzer_path)
            except Exception as e:  # bad spec / unloadable plugin path
                if not worker.is_cancelled:
                    self.app.call_from_thread(panel.set_progress, 0, 0, f"error: {e}")
                return

            # Resolve the flow source. Replay loads full flows (with bodies) from
            # disk on demand; capture keeps them in the collector.
            if self._replay_ctrl is not None:
                flow_ids = [s.flow_id for s in self._replay_ctrl.get_summaries()]
                get_flow = self._replay_ctrl.get_flow
            else:
                collector = self._capture.flow_collector
                flows = list(collector.get_flows()) if collector else []
                flow_map = {f.flow_id: f for f in flows}
                flow_ids = list(flow_map)
                get_flow = flow_map.get

            total = len(flow_ids)
            findings: list = []
            for i, fid in enumerate(flow_ids, 1):
                if worker.is_cancelled:
                    return  # superseded by a newer run — drop this work
                try:
                    flow = get_flow(fid)
                except Exception:
                    flow = None
                if flow is not None:
                    for analyzer in analyzers:
                        try:
                            findings.extend(analyzer.analyze_flow(flow))
                        except Exception:
                            continue
                if i % 5 == 0 or i == total:
                    self.app.call_from_thread(panel.set_progress, i, total)

            if worker.is_cancelled:
                return
            self.app.call_from_thread(self._on_analyzers_complete, findings, run_id)

        def _on_analyzers_complete(self, findings: list, run_id: int) -> None:
            """Replace the session findings with this run's results and show counts.

            Ignores results from a stale run (one that was superseded by a newer
            run or invalidated by a Clear) so the latest action always wins.
            """
            if run_id != self._analyzer_run_id:
                return
            try:
                findings_list = self.query_one("#findings-list", FindingsListWidget)
                findings_list.clear_findings()
                findings_list.add_findings(findings)
            except Exception:
                pass
            # Replace-per-run: the findings cache mirrors exactly this run so a
            # later shift+f and the dashboard counts always agree.
            self._findings_cache = list(findings)
            try:
                self._analyzer_panel().show_dashboard(summarize(findings))
            except Exception:
                pass

        def on_analyzer_panel_chip_selected(
            self, event: "AnalyzerPanel.ChipSelected"
        ) -> None:
            """A dashboard chip drops into the findings view, pre-filtered."""
            self._analyzer_panel().display = False
            self._activate_findings_view()
            self._apply_findings_filter(event.flt, event.label)

        def on_analyzer_panel_clear_requested(
            self, event: "AnalyzerPanel.ClearRequested"
        ) -> None:
            """Clear analyzer results for this session."""
            # Invalidate any in-flight run so its late completion can't resurrect
            # cleared results, and cancel its worker to stop wasted work.
            self._analyzer_run_id += 1
            try:
                self.workers.cancel_group(self, "analyzer")
            except Exception:
                pass
            try:
                self.query_one("#findings-list", FindingsListWidget).clear_findings()
            except Exception:
                pass
            self._findings_cache = []
            self._analyzer_panel().reset()

        def on_analyzer_panel_close_requested(
            self, event: "AnalyzerPanel.CloseRequested"
        ) -> None:
            """Close the analyzer panel and return focus to the flow list."""
            self._analyzer_panel().display = False
            try:
                self.query_one("#flow-list").focus()
            except Exception:
                pass

        def action_focus_filter(self) -> None:
            """Open the filter modal (/ key)."""
            # Findings view has its own filter modal.
            if self._findings_list_displayed():
                def _on_result(result) -> None:
                    if result is None:
                        return
                    self._apply_findings_filter(result.flt, result.label)
                try:
                    self.app.push_screen(FindingsFilterModal(), callback=_on_result)
                except Exception:
                    pass
                return
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if not filter_bar.display:
                    return
                self.app.push_screen(
                    FilterModal(
                        current_text=filter_bar.filter_text,
                        active_toggles=filter_bar.active_toggles,
                    ),
                    callback=self._on_filter_result,
                )
            except Exception:
                pass

        def action_clear_filter(self) -> None:
            """Clear the active filter (Shift+Esc)."""
            # Findings view: clear the findings filter bar.
            if self._findings_list_displayed():
                try:
                    bar = self.query_one("#findings-filter-bar", FindingsFilterBar)
                    bar.clear_filter()
                except Exception:
                    pass
                return
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if not filter_bar.display:
                    return
                filter_bar.clear_filter()
            except Exception:
                pass

        def _on_filter_result(self, result: FilterResult | None) -> None:
            """Handle the result from the FilterModal."""
            if result is None:
                return
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                filter_bar.apply_result(
                    text=result.text,
                    text_engine=result.text_engine,
                    toggle_engine=result.toggle_engine,
                    active_toggles=result.active_toggles,
                )
            except Exception:
                pass

        def on_filter_bar_filter_changed(self, event: FilterBar.FilterChanged) -> None:
            """Handle filter changes from the filter bar."""
            try:
                flow_list = self.query_one("#flow-list", FlowListWidget)
                flow_list.set_filter(event.engine, event.toggle_engine)
            except Exception:
                pass
            self._update_flow_title()

        def action_toggle_view(self) -> None:
            """Toggle between legacy and flow views."""
            flow_list = self.query_one("#flow-list")
            flow_detail = self.query_one("#flow-detail")

            if flow_detail.display:
                # In detail view → back to flow list
                self._back_to_flow_list()
            elif flow_list.display:
                # In replay mode, legacy view is not available
                if self._replay_ctrl is not None:
                    return
                # In flow view → switch to legacy
                self._activate_legacy_view()
            else:
                # In legacy view → switch to flow
                self._activate_flow_view()

        def _update_flow_ui(self, flow, event_type: str) -> None:
            """Update flow list/detail widgets with a flow change (called on Textual thread)."""
            try:
                flow_list = self.query_one("#flow-list", FlowListWidget)
                if flow_list.display:
                    flow_list.add_or_update_flow(flow)
                flow_detail = self.query_one("#flow-detail", FlowDetailWidget)
                if flow_detail.display:
                    flow_detail.refresh_flow(flow)
            except Exception:
                pass

        # ----------------------------------------------------------
        # Help
        # ----------------------------------------------------------

        def action_show_help(self) -> None:
            """Show the help overlay."""
            self.app.push_screen(HelpScreen())
