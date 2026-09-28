"""Shared TUI test doubles for the Telegram flow-detail / conversation tests.

Widgets are built via ``__new__`` with fake RichLogs, so no Textual app runs.
"""

from __future__ import annotations

from tests.unit._render_helpers import RenderingFakeLog

_LOG_NAMES = ("_request_log", "_response_log", "_detail_log", "_message_log")


def make_flow_detail_widget(siblings=(), *, processing=None, log_width: int = 120, **extra):
    """A ``FlowDetailWidget`` with rendering fake logs; *extra* sets more attributes."""
    from friTap.tui.widgets.flow_detail import FlowDetailWidget

    widget = FlowDetailWidget.__new__(FlowDetailWidget)
    for name in _LOG_NAMES:
        setattr(widget, name, RenderingFakeLog(width=log_width))
    widget._raw_request = widget._raw_response = False
    widget._active_processing = processing
    widget._segment_offsets = []
    widget._conversation_siblings = list(siblings)
    for name, value in extra.items():
        setattr(widget, name, value)
    return widget


class FakeReplay:
    """A ``ReplayController`` stand-in that records which flows were loaded."""

    def __init__(self, flows, summaries=None):
        self._flows = {f.flow_id: f for f in flows}
        self._summaries = list(self._flows.values()) if summaries is None else summaries
        self.loaded_ids = []

    def get_summaries(self):
        return list(self._summaries)

    def get_flow(self, flow_id):
        self.loaded_ids.append(flow_id)
        return self._flows.get(flow_id)
