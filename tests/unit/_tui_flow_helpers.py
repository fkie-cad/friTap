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

    def load(self):
        pass

    def get_summaries(self):
        return list(self._summaries)

    @property
    def flow_count(self):
        return len(self._summaries)

    def get_flow(self, flow_id):
        self.loaded_ids.append(flow_id)
        return self._flows.get(flow_id)

    def get_flows(self):
        return list(self._flows.values())

    @property
    def header(self):
        return None

    def store_reparse(self, flow_id, request, response, clear_trailing=False):
        pass

    def read_all_findings(self):
        return []

    def read_request_contexts(self):
        return []


def make_flow(flow_id, dst_port=443, *, src_port=12345, dst_addr="93.184.216.34"):
    """A COMPLETE ``Flow`` between 10.0.0.1 and *dst_addr* (shared .tap fixture)."""
    from friTap.flow.models import Flow, FlowState

    return Flow(
        flow_id=flow_id, connection_id=flow_id, src_addr="10.0.0.1",
        src_port=src_port, dst_addr=dst_addr, dst_port=dst_port,
        state=FlowState.COMPLETE,
    )


def write_tap(path, flows, *, target="test", findings=None):
    """Write *flows* (then *findings*, a ``{flow_id: [Finding]}`` map) to *path*; returns *path*."""
    from friTap.flow.tap_writer import TapWriter

    writer = TapWriter()
    writer.open(str(path), target=target)
    for flow in flows:
        writer.write_flow(flow)
    for flow_id, flow_findings in (findings or {}).items():
        writer.write_findings(flow_id, flow_findings)
    writer.close()
    return path
