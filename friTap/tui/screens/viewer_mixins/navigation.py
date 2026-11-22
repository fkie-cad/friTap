#!/usr/bin/env python3

"""
Flow navigation: flow list <-> flow detail, title-bar hints and Esc back-navigation.

Viewer logic moved verbatim from :class:`friTap.tui.screens.main_screen.MainScreen`
(task 2.2, group 5). A plain mixin (no BINDINGS, no CSS, no compose): it relies
on the host screen for ``query_one``, ``call_after_refresh``, ``_replay_ctrl``,
``_detail_origin``, ``_update_capture_indicator``, the findings/filter helpers
(``_hide_findings_widgets``, ``_findings_list_displayed``,
``_back_to_findings_list``, ``_restore_finding_detail``, ``action_clear_filter``),
the conversation-sibling lookup (``_conversation_siblings``), the analyzer
reset (``_forget_analyzer_results``) and the
``_live_flow_collector`` / ``_hide_host_panels`` / ``_flow_title_hints`` /
``_is_capturing`` / ``_escape_running_capture`` / ``_request_close`` host hooks.
It holds no capture/wizard code so a replay-only viewer screen can inherit it too.
"""

from __future__ import annotations

import logging

from textual.widgets import Static

from ...themes import c
from ...widgets.filter_bar import FilterBar
from ...widgets.findings_list import FindingsListWidget
from ...widgets.flow_detail import FlowDetailWidget
from ...widgets.flow_list import FlowListWidget
from ...widgets.wire_text import safe_static_text

logger = logging.getLogger(__name__)


class FlowNavigationMixin:
    """Flow list/detail navigation, title hints and Esc handling (host: a Textual ``Screen``)."""

    # ``flow_id -> Flow`` the live host recorded while the flow list was hidden.
    # None for hosts without live updates (the replay-only viewer).
    _hidden_flow_updates: dict | None = None

    def _activate_flow_view(self) -> None:
        """Switch right panel to full-screen flow list view."""
        self.query_one("#flow-detail").display = False
        self._hide_findings_widgets()
        self.query_one("#flow-list").display = True
        self._apply_hidden_flow_updates()
        self.query_one("#filter-bar").display = True
        self._hide_host_panels()
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
        hints.extend(self._flow_title_hints())
        self._set_title_hints(" [dim]|[/] ".join(hints))
        self._update_capture_indicator()

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

    def _lookup_flow(self, flow_id: str):
        """Load a full Flow by id from the replay controller or live collector."""
        if self._replay_ctrl is not None:
            return self._replay_ctrl.get_flow(flow_id)
        collector = self._live_flow_collector()
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
        self._apply_hidden_flow_updates()
        self.query_one("#flow-list").focus()
        self._update_flow_title()

    def _apply_hidden_flow_updates(self) -> None:
        """Add/update the list rows of flows that changed while it was hidden."""
        pending = self._hidden_flow_updates
        if not pending:
            return
        flow_list = self.query_one("#flow-list", FlowListWidget)
        flows = list(pending.values())
        pending.clear()
        for flow in flows:
            try:
                flow_list.add_or_update_flow(flow)
            except Exception:
                logger.debug("applying a hidden flow update failed", exc_info=True)

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

    def _flow_row_resolver(self):
        """``flow_id -> row number`` of the flow list, for ``#N`` cross-references."""
        try:
            return self.query_one("#flow-list", FlowListWidget).row_number_of
        except Exception:
            return None

    def _present_flow_detail(self, flow) -> None:
        """Show the flow detail widget for a given Flow object."""
        self.query_one("#flow-list").display = False
        self._hide_host_panels()
        self._hide_findings_widgets()
        detail = self.query_one("#flow-detail", FlowDetailWidget)
        # Reunite the Signal conversation's per-connection flows (empty for
        # non-Signal flows -> single-flow behavior) before rendering.
        try:
            detail.set_conversation_siblings(
                self._conversation_siblings(flow)
            )
        except Exception:
            detail.set_conversation_siblings([])
        detail.set_row_resolver(self._flow_row_resolver())
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

    def _escape_step(self) -> bool:
        """Step out of one nested view (Esc hierarchy); True if it navigated.

        Finding detail -> findings list, flow detail -> where it was opened
        from, findings list -> all findings -> flow list. False at the top
        level (flow list / console), where nothing changes.
        """
        # Analyzer finding-detail → back to the findings list (filter kept).
        if self.query_one("#finding-detail").display:
            self._back_to_findings_list()
            return True
        flow_detail = self.query_one("#flow-detail")
        if flow_detail.display:
            if self._detail_origin == "finding":
                self._restore_finding_detail()
            else:
                self._back_to_flow_list()
            return True
        # Findings list → step up the hierarchy: a filtered (category) view
        # clears back to all findings, then all findings backs to the flows.
        if self._findings_list_displayed():
            if self.query_one("#findings-list", FindingsListWidget).has_filter:
                self.action_clear_filter()
            else:
                self._activate_flow_view()
            return True
        return False

    def action_escape_action(self) -> None:
        if self._escape_step():
            return
        if self._is_capturing():
            self._escape_running_capture()
            return
        # Not capturing → trigger quit confirmation
        self._request_close()

    # ----------------------------------------------------------
    # Source swap (reload_replay of both hosts)
    # ----------------------------------------------------------

    def _swap_in_source(self, ctrl, *, close_previous: bool) -> None:
        """Show *ctrl* (an already loaded source) in place of the current one.

        Everything shown from the previous source is forgotten BEFORE the
        swap (analyzer run + findings, detail origin, flow/findings rows) and
        the previous source is closed only AFTER it, when *close_previous*
        (the host opened it itself). The caller then re-activates the flow
        view, which also returns an open detail view to the flow list.
        """
        previous = self._replay_ctrl
        self._forget_analyzer_results()
        self._detail_origin = "flow"
        self._clear_shown_rows()
        self._replay_ctrl = ctrl
        if close_previous and previous is not ctrl:
            self._close_source(previous)

    @staticmethod
    def _open_controller(path: str):
        """A loaded ReplayController for *path* (raises when it cannot open)."""
        from friTap.flow.replay import ReplayController

        ctrl = ReplayController(path)
        ctrl.load()
        return ctrl

    def _open_source_or_alert(self, path: str, display_name: str):
        """A loaded controller for *path*, or None after an error alert.

        *display_name* is the (host-escaped) file name shown in the alert;
        the error text often repeats the path, so it is escaped here too.
        """
        try:
            return self._open_controller(path)
        except Exception as e:
            self._alert(
                f"Failed to open {display_name}:\n\n{safe_static_text(e)}",
                title="Replay Error", severity="error",
            )
            return None

    def _clear_shown_rows(self) -> None:
        """Empty the flow list (table + backing store) and the findings list."""
        if self._hidden_flow_updates:
            self._hidden_flow_updates.clear()
        try:
            self.query_one("#flow-list", FlowListWidget).clear_flows()
        except Exception:
            pass
        try:
            self.query_one("#findings-list", FindingsListWidget).clear_findings()
        except Exception:
            pass

    @staticmethod
    def _close_source(source) -> None:
        """Close *source* if it can be closed (``TapSource.close`` is optional)."""
        close = getattr(source, "close", None)
        if close is None:
            return
        try:
            close()
        except Exception:
            logger.debug("closing the replay controller failed", exc_info=True)
