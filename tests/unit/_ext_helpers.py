"""Shared fakes for the extension / offline-discovery tests."""

from __future__ import annotations


class FakeEntryPoint:
    """Minimal ``importlib.metadata.EntryPoint`` stand-in: ``name`` and ``load()``."""

    def __init__(self, name, target=None, exc=None):
        self.name, self._target, self._exc = name, target, exc

    def load(self):
        if self._exc:
            raise self._exc
        return self._target


def decoder_widget(decoder: str):
    """A FlowDetailWidget stub with just the state ``_render_body`` reads."""
    from friTap.tui.modals.body_processing_modal import BodyProcessingResult
    from friTap.tui.widgets.flow_detail import FlowDetailWidget

    widget = FlowDetailWidget.__new__(FlowDetailWidget)
    widget._active_processing = BodyProcessingResult(decoder=decoder)
    widget._current_flow = None
    widget._segment_offsets = []
    return widget
