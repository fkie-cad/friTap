"""PARKED / NOT-YET-WIRED TUI code — retained for possible future use.

This module holds the ``_all_flows`` helper relocated out of
:class:`friTap.tui.screens.main_screen.MainScreen`. It had no callers (dead
code) but is preserved here in case a future view needs a single accessor for
"every flow in the current view" across both replay and live-capture modes.

It is intentionally NOT imported by any active screen, so it cannot affect the
running UI. It is kept verbatim (logic + comments preserved) as a *mixin* so
that ``self`` semantics are preserved: it references the host screen's
``_replay_ctrl`` and ``_capture`` attributes, which remain defined on
``MainScreen``.

HOW TO RE-ACTIVATE
------------------
Add this mixin to the screen's bases, e.g.::

    from friTap.tui.screens._parked_main_screen import ParkedAllFlowsMixin

    class MainScreen(ParkedAllFlowsMixin, Screen):
        ...

Then call ``self._all_flows()``. The mixin resolves ``self._replay_ctrl`` and
``self._capture`` from the host screen at runtime.
"""

from __future__ import annotations


class ParkedAllFlowsMixin:
    """Parked ``_all_flows`` accessor (see module docstring).

    Mix into a ``MainScreen``-like screen to re-activate. Relies on the host
    providing ``_replay_ctrl`` and ``_capture`` attributes.
    """

    def _all_flows(self) -> list:
        """Every flow in the current view (replay file or live collector)."""
        if self._replay_ctrl is not None:
            return self._replay_ctrl.get_flows()
        collector = self._capture.flow_collector
        return collector.get_flows() if collector else []
