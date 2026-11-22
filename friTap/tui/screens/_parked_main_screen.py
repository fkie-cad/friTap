"""Parked, not wired in: the ``_all_flows`` helper relocated out of
:class:`friTap.tui.screens.main_screen.MainScreen` (it had no callers).

No active screen imports it. To re-activate, add ``ParkedAllFlowsMixin`` to the screen's
bases (``class MainScreen(ParkedAllFlowsMixin, Screen)``) and call ``self._all_flows()``;
it reads the host's ``_replay_ctrl`` and ``_capture``.
"""

from __future__ import annotations


class ParkedAllFlowsMixin:
    """Parked ``_all_flows`` accessor (see module docstring); needs the host's ``_replay_ctrl`` and ``_capture``."""

    def _all_flows(self) -> list:
        """Every flow in the current view (replay file or live collector)."""
        if self._replay_ctrl is not None:
            return self._replay_ctrl.get_flows()
        collector = self._capture.flow_collector
        return collector.get_flows() if collector else []
