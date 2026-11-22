#!/usr/bin/env python3

"""
Display filter: the ``/`` filter modal, Shift+Esc clear and the filter bar.

Viewer logic moved verbatim from :class:`friTap.tui.screens.main_screen.MainScreen`
(task 2.2, group 4). A plain mixin (no BINDINGS, no CSS, no compose): it relies
on the host screen for ``query_one``, ``app``, ``_update_flow_title`` and the
findings-view helpers (``_findings_list_displayed``, ``_apply_findings_filter``
from :class:`FindingsMixin`). It holds no capture/wizard code so a replay-only
viewer screen can inherit it too.

The file is named ``display_filter`` (not ``filter``) so it never reads as the
``filter`` builtin.
"""

from __future__ import annotations

from ...modals.filter_modal import FilterModal, FilterResult
from ...modals.findings_filter_modal import FindingsFilterModal
from ...widgets.filter_bar import FilterBar
from ...widgets.findings_filter_bar import FindingsFilterBar
from ...widgets.flow_list import FlowListWidget


class FilterMixin:
    """Flow-list / findings display filter (host: a Textual ``Screen``)."""

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
            flow_list = self.query_one("#flow-list", FlowListWidget)
            self.app.push_screen(
                FilterModal(
                    current_text=filter_bar.filter_text,
                    active_toggles=filter_bar.active_toggles,
                    match_counter=flow_list.count_matches,
                    row_count=lambda: flow_list.total_count,
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
