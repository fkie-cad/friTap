#!/usr/bin/env python3

"""Replay-only defaults for the viewer host hooks, plus shared title markup.

A plain mixin placed LAST among the viewer mixins (before ``Screen``) in
:class:`~friTap.tui.screens.main_screen.MainScreen` and
:class:`~friTap.tui.screens.tap_viewer.TapViewerScreen`. A host with a live capture
overrides them via the MRO. Hooks without a neutral default (``_request_close``,
``_flow_title_hints``, ``_update_capture_indicator``, ``_get_activity_log``,
``reload_replay``) stay host-provided (``tests/unit/test_viewer_host_contract.py``).
"""

from __future__ import annotations

import logging
from typing import Callable

from ...themes import c

logger = logging.getLogger(__name__)


class ViewerHostDefaults:
    """Capture-free host-hook defaults (host: a Textual ``Screen`` with ``_replay_ctrl``)."""

    # Directory offered by the save dialogs; ``None`` means the cwd.
    _output_dir = None


    def _is_capturing(self) -> bool:
        """No live capture without a capture host."""
        return False

    def _live_flow_collector(self):
        """No live FlowCollector without a capture host."""
        return None

    def _divert_analyzer_key(self) -> bool:
        """'a' always means analyzers (a capture host may divert it to attach)."""
        return False

    def _escape_running_capture(self) -> None:
        """Unreachable while ``_is_capturing`` is False."""
        logger.debug("no running capture to stop")

    def _start_live_tap_recording(self, path: str) -> None:
        """Unreachable without a live collector: saving exports the loaded replay."""
        logger.debug("no live capture to record to %s", path)

    def _hide_host_panels(self) -> None:
        """No console log or left panel to hide."""

    def _has_flows(self) -> bool:
        """True when the loaded .tap has at least one flow."""
        return self._replay_ctrl is not None and self._replay_ctrl.flow_count > 0

    def _analyzer_flow_ids_and_getter(self) -> tuple[list, Callable]:
        """``(flow_ids, get_flow)`` over the loaded .tap (empty without one)."""
        ctrl = self._replay_ctrl
        if ctrl is None:
            return [], lambda _flow_id: None
        return [s.flow_id for s in ctrl.get_summaries()], ctrl.get_flow

    def _no_flows_to_save_message(self) -> str:
        """Alert text shown when saving with no flows loaded."""
        return "No flows to save."

    def _alert(
        self, message: str, title: str = "", severity: str = "warning",
    ) -> None:
        """Push a dismissible AlertModal (not a toast) so multi-line explanations stay until dismissed."""
        from ...modals.alert_modal import AlertModal
        self.app.push_screen(
            AlertModal(message=message, title=title, severity=severity)
        )


    @staticmethod
    def _replay_banner_markup(filename: str, count: int, hints: str) -> str:
        """Initial replay banner: ``friTap Replay  <file> (<n> flows)<hints>``."""
        return (
            f"[bold {c('primary')}]friTap Replay[/]  "
            f"[dim]{filename} ({count} flow{'s' if count != 1 else ''})"
            f"{hints}[/]"
        )

    @staticmethod
    def _tap_indicator_markup(filename) -> str:
        """Left-pinned ``▣ TAP: <file>`` indicator of a loaded .tap."""
        return f"[bold {c('info')}]▣ TAP: {filename or 'tap'}[/]"
