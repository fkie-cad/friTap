#!/usr/bin/env python3

"""
Findings view: the analyzer-findings list, filter bar and finding detail.

Viewer logic moved verbatim from :class:`friTap.tui.screens.main_screen.MainScreen`
(task 2.2, group 2). A plain mixin (no BINDINGS, no CSS, no compose): it relies
on the host screen for ``query_one``, ``call_after_refresh``, ``_replay_ctrl``,
``_findings_cache``, ``_detail_origin``, ``_lookup_flow``,
``_present_flow_detail``, ``_activate_flow_view``, ``_set_title_hints``,
``_update_capture_indicator``, ``_clear_title_indicators`` and the
``_hide_host_panels`` host hook. It holds no capture/wizard code so a
replay-only viewer screen can inherit it too.
"""

from __future__ import annotations

from friTap.analysis import Finding
from friTap.analysis.filtering import FindingFilter

from ...widgets.analyzer_finding_detail import AnalyzerFindingDetailWidget
from ...widgets.findings_filter_bar import FindingsFilterBar
from ...widgets.findings_list import FindingsListWidget


class FindingsMixin:
    """Findings list / filter / finding-detail views (host: a Textual ``Screen``)."""

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
        self.query_one("#flow-list").display = False
        self.query_one("#flow-detail").display = False
        self.query_one("#finding-detail").display = False
        self.query_one("#filter-bar").display = False
        self.query_one("#analyzer-panel").display = False
        self._hide_host_panels()

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
        self._hide_host_panels()
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
