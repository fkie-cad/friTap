#!/usr/bin/env python3

"""
Export: save flows to a .tap file (``w``) and the ``fritap report`` digest (``R``).

Viewer logic moved verbatim from :class:`friTap.tui.screens.main_screen.MainScreen`
(task 2.2, group 6). A plain mixin (no BINDINGS, no CSS, no compose): it relies
on the host screen for ``app``, ``notify``, ``_replay_ctrl``, ``_replay_file``,
``_findings_cache`` and the ``_has_flows`` / ``_start_live_tap_recording`` /
``_live_flow_collector`` host hooks. It holds no capture/wizard code so a
replay-only viewer screen can inherit it too.
"""

from __future__ import annotations

from friTap.analysis import Finding


class ExportMixin:
    """.tap export and report digest (host: a Textual ``Screen``)."""
    def action_save_tap(self) -> None:
        """Show save dialog for .tap file export."""
        # In replay mode, re-export is available too
        if not self._has_flows():
            from ...modals.alert_modal import AlertModal
            self.app.push_screen(
                AlertModal(
                    message=self._no_flows_to_save_message(),
                    title="Save Capture",
                    severity="warning",
                )
            )
            return

        from ...modals.save_tap_modal import SaveTapModal
        self.app.push_screen(
            SaveTapModal(directory=self._output_dir),
            callback=self._on_save_tap_result,
        )

    def _on_save_tap_result(self, path: str | None) -> None:
        """Handle the result from SaveTapModal."""
        if path is None:
            return

        if self._replay_ctrl is not None:
            # Re-export from replay: write all flows to new file
            self._export_replay_to_tap(path)
        else:
            # Live capture: wire the TapWriter to the FlowCollector
            self._start_live_tap_recording(path)

    def _export_replay_to_tap(self, path: str) -> None:
        """Export all replay flows to a new .tap file."""
        from pathlib import Path

        from friTap.flow.tap_writer import TapWriter

        from ...widgets.wire_text import safe_static_text

        if self._replay_file and Path(path).resolve() == Path(self._replay_file).resolve():
            self._alert(
                "Cannot overwrite the capture that is currently open.\n"
                "Choose a different file name.",
                title="Export Error",
                severity="error",
            )
            return

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

            # Carry the Java request contexts (--attribute-sdk) over too.
            for record in self._replay_ctrl.read_request_contexts():
                writer.write_request_context(record)

            writer.close()

            from ...modals.alert_modal import AlertModal
            self.app.push_screen(
                AlertModal(
                    message=f"Exported {writer.flow_count} flows to:\n[bold]{safe_static_text(path)}[/]",
                    title="Export Complete",
                    severity="info",
                )
            )
        except Exception as e:
            from ...modals.alert_modal import AlertModal
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

    def _has_capture_flows(self) -> bool:
        """True when a live-capture flow collector holds at least one flow."""
        try:
            collector = self._live_flow_collector()
            return bool(collector and collector.get_flows())
        except Exception:
            return False

    def action_report_digest(self) -> None:
        """Show the ``fritap report`` digest for the capture ('R').

        Opens a scrollable Report modal (hosts/endpoints/findings grouped
        per protocol, with MASVS tags and a cyclable all/security/privacy
        focus). Works for a replay (reads the ``.tap``) and for a live
        capture (digests the in-memory flows via ``scan_flows`` — no save
        required).
        """
        from friTap.analysis.digest import (
            FlowSelector,
            build_digest,
            builtin_analyzers,
            scan_flows,
        )
        from friTap.analysis.digest_render import render_markdown
        from friTap.tui.modals.report_modal import ReportModal

        replay_path = self._replay_file
        flows = None
        if not replay_path:
            if self._has_capture_flows():
                try:
                    flows = self._live_flow_collector().get_flows()
                except Exception:
                    flows = None
            if not flows:
                self.notify("Nothing to report yet — capture or open a .tap first.",
                            severity="warning")
                return

        def make_markdown(focus: str) -> str:
            if replay_path:
                digest = build_digest(replay_path, focus=focus, masvs=True,
                                      budget_tokens=6000)
            else:
                scan = scan_flows(flows, FlowSelector(),
                                  builtin_analyzers(False, focus))
                digest = build_digest("(live capture)", focus=focus, masvs=True,
                                      budget_tokens=6000, scan=scan)
            return render_markdown(digest)

        self.app.push_screen(ReportModal(make_markdown, initial="all"))
