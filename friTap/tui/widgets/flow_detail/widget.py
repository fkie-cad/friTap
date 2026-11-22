"""The flow-detail widget: compose, flow selection and tab dispatch.

Content rendering lives in the mixins it inherits (one concern per module).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape as _markup_escape
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import RichLog, Static, TabbedContent, TabPane

from friTap.tui.modals.body_processing_modal import BodyProcessingResult
from friTap.tui.themes import c
from friTap.tui.widgets import flow_detail as _fd

from .actions import ActionsMixin
from .body import BodyMixin
from .conversation_data import ConversationDataMixin
from .conversation_render import ConversationRenderMixin
from .detail_tabs import DetailTabsMixin
from .header import HeaderMixin
from .helpers import (
    _BYTE_TAB_IDS,
    _BYTE_TAB_POOL_SIZE,
    _OHTTP_PROVIDER_ID,
    _OHTTP_TITLE,
    _TAB_BYTES_PREFIX,
    _TAB_DETAIL,
    _TAB_EXT_PREFIX,
    _TAB_LAYERS,
    _TAB_MESSAGE,
    _TAB_OHTTP,
    _TAB_REQUEST,
    _TAB_RESPONSE,
    _escape_bracket_label,
    _extension_pane_id,
    _log,
)
from .layers import LayersMixin
from .optional_tabs import OptionalTabsMixin
from .tl_pane import TlMessagePaneMixin

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class FlowDetailWidget(
    OptionalTabsMixin,
    ActionsMixin,
    HeaderMixin,
    TlMessagePaneMixin,
    DetailTabsMixin,
    LayersMixin,
    ConversationRenderMixin,
    ConversationDataMixin,
    BodyMixin,
    Vertical,
):
    """Tabbed detail view for a single flow.

    Tabs: Request | Response | Detail
    Shortcuts: p=parse r=reset s=save h=hex
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=False),
        Binding("p", "open_body_processing", "Parse", show=False),
        Binding("r", "processing_reset", "Reset", show=False),
        Binding("s", "save_body", "Save Body", show=False),
        Binding("h", "toggle_raw_hex", "Hex View", show=False),
        Binding("n", "next_segment", "Next Segment", show=False),
        Binding("N", "prev_segment", "Prev Segment", show=False),
        Binding("x", "open_explorer", "Explorer", show=False),
        Binding("bracketleft", "prev_layer", "Prev Layer", show=False),
        Binding("bracketright", "next_layer", "Next Layer", show=False),
        Binding("l", "toggle_layer_view", "Raw layers", show=False),
    ]

    class BackRequested(Message):
        """Emitted when user wants to go back to flow list."""
        pass

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._current_flow = None
        self._extra_tabs: list = []  # TabProvider instances
        self._active_processing: BodyProcessingResult | None = None
        #: ``ProtobufView.mode`` of the last protobuf decode, for the pipeline label.
        self._last_protobuf_mode: str | None = None
        self._pre_modal_processing: BodyProcessingResult | None = None
        self._raw_request: bool = False
        self._raw_response: bool = False
        self._skip_tab_event: bool = False
        # Other flows of the same logical conversation (e.g. Signal splits
        # directions across TCP connections); the Message tab merges them.
        self._conversation_siblings: list = []
        # flow_id -> visible row number (set by the screen); drives "#N" refs.
        self._row_resolver = None
        self._last_explorer_result = None  # ExplorerResult from last explorer session
        # Widget refs assigned in compose().
        self._header_widget: Static | None = None
        self._tabs: TabbedContent | None = None
        self._request_log: RichLog | None = None
        self._response_log: RichLog | None = None
        self._detail_log: RichLog | None = None
        self._message_log: RichLog | None = None
        self._layers_log: RichLog | None = None
        # Byte-tab pool: RichLogs by pane id, and the layer each visible pane shows.
        self._byte_logs: dict[str, RichLog] = {}
        self._byte_tab_layers: dict = {}
        # OHTTP inner pane log, and extension detail tabs as (pane_id, spec)
        # with their RichLogs and last rendered content (set per flow).
        self._ohttp_log: RichLog | None = None
        self._ext_tabs: list = []
        self._ext_logs: dict[str, RichLog] = {}
        self._ext_content: dict = {}
        # Last applied visibility per optional pane (OHTTP + extensions), so
        # a live refresh only touches the tab bar when visibility changes.
        self._optional_tab_visible: dict[str, bool] = {}
        # Extension render throttle: change key + layer signature of the
        # last render (key None = never rendered), time of the last
        # refresh-driven render (0.0 = none since selection), pending re-check.
        self._ext_render_key: tuple | None = None
        self._ext_layer_sig = None
        self._ext_rendered_at = 0.0
        self._ext_recheck_timer = None
        self._segment_offsets: list[int] = []  # RichLog line offsets for n/N navigation
        self._current_layer_idx: int = 0
        self._layer_view: dict[int, str] = {}  # layer index -> "hex" | "parsed"

    def register_tab(self, provider) -> None:
        """Register a plugin TabProvider for an extra tab."""
        self._extra_tabs.append(provider)

    def set_conversation_siblings(self, flows) -> None:
        """Set the other flows of the current conversation (call before
        :meth:`show_flow`); empty or None means single-flow."""
        self._conversation_siblings = list(flows or [])

    def compose(self):
        self._header_widget = Static("", id="flow-detail-header")
        yield self._header_widget
        tab_titles = ["Request", "Response", "Detail", "Message", "Layers"]
        tab_titles += [f"Bytes {i}" for i in range(_BYTE_TAB_POOL_SIZE)]
        tab_titles.append(_OHTTP_TITLE)
        self._ext_tabs = self._collect_extension_tabs()
        tab_titles += [_escape_bracket_label(str(spec.label)) for _, spec in self._ext_tabs]
        for tab_provider in self._plugin_tab_providers():
            tab_titles.append(tab_provider.title)

        # Widget IDs also referenced in friTap/tui/css/fritap.tcss
        self._request_log = RichLog(id="request-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._response_log = RichLog(id="response-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._detail_log = RichLog(id="detail-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._message_log = RichLog(id="message-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._layers_log = RichLog(id="layers-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._byte_logs = {
            pane_id: RichLog(id=f"{pane_id}-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            for pane_id in _BYTE_TAB_IDS
        }
        self._ohttp_log = RichLog(id="ohttp-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
        self._ext_logs = {
            pane_id: RichLog(id=f"{pane_id}-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            for pane_id, _ in self._ext_tabs
        }

        with TabbedContent(*tab_titles, id="flow-tabs") as self._tabs:
            with TabPane("Request", id=_TAB_REQUEST):
                yield self._request_log
            with TabPane("Response", id=_TAB_RESPONSE):
                yield self._response_log
            with TabPane("Detail", id=_TAB_DETAIL):
                yield self._detail_log
            with TabPane("Message", id=_TAB_MESSAGE):
                yield self._message_log
            with TabPane("Layers", id=_TAB_LAYERS):
                yield self._layers_log
            for i, pane_id in enumerate(_BYTE_TAB_IDS):
                with TabPane(f"Bytes {i}", id=pane_id):
                    yield self._byte_logs[pane_id]
            with TabPane(_OHTTP_TITLE, id=_TAB_OHTTP):
                yield self._ohttp_log
            for pane_id, spec in self._ext_tabs:
                with TabPane(_escape_bracket_label(str(spec.label)), id=pane_id):
                    yield self._ext_logs[pane_id]
            for tab_provider in self._plugin_tab_providers():
                with TabPane(tab_provider.title, id=f"tab-{tab_provider.tab_id}"):
                    yield RichLog(id=f"{tab_provider.tab_id}-log", wrap=True, highlight=True, markup=True, auto_scroll=False)

    def on_mount(self) -> None:
        """Hide the byte-tab pool, OHTTP and extension panes until a flow needs them."""
        for pane_id in _BYTE_TAB_IDS:
            self._set_byte_tab_visible(pane_id, False)
        for pane_id in (_TAB_OHTTP, *(pane_id for pane_id, _ in self._ext_tabs)):
            self._set_byte_tab_visible(pane_id, False)
            self._optional_tab_visible[pane_id] = False

    @staticmethod
    def _collect_extension_tabs() -> list:
        """``(pane_id, spec)`` per registered extension detail tab."""
        from friTap.extensions import get_detail_tabs

        try:
            specs = get_detail_tabs()
        except Exception:
            _log.exception("flow detail: reading extension detail tabs failed")
            return []
        used: set = set()
        return [(_extension_pane_id(spec.id, used), spec) for spec in specs]

    def _plugin_tab_providers(self) -> list:
        """Registered TabProviders, minus OHTTP (now a built-in pane)."""
        return [p for p in self._extra_tabs
                if getattr(p, "tab_id", None) != _OHTTP_PROVIDER_ID]

    def _reset_view_state(self) -> None:
        self._raw_request = False
        self._raw_response = False
        self._active_processing = None
        self._last_protobuf_mode = None
        self._current_layer_idx = 0
        self._layer_view = {}

    def show_flow(self, flow: "Flow") -> None:
        """Display *flow*; only the auto-selected tab renders now, others on activation."""
        if self._current_flow is not flow:
            self._reset_view_state()
        self._current_flow = flow
        self._reset_extension_render_state()
        self._update_header(flow)
        try:
            self._update_tab_labels(self._tabs, flow)
            self._skip_tab_event = True
            self._auto_select_tab(self._tabs, flow)
            self._skip_tab_event = False
            self._render_tab_safely(flow, self._tabs.active)
        except Exception:
            self._skip_tab_event = False

    def scroll_to_top(self) -> None:
        """Scroll the active tab's RichLog to the top.

        Call from ``call_after_refresh`` after the widget becomes visible
        so Textual has completed layout and scroll positions stick.
        """
        try:
            log = self._log_for_tab(self._tabs.active)
            if log:
                log.scroll_home(animate=False)
        except Exception:
            pass

    @staticmethod
    def _auto_select_tab(tabs: TabbedContent, flow: "Flow") -> None:
        """Select the first tab that has meaningful data."""
        if _fd._flow_has_messages(flow):
            tabs.active = _TAB_MESSAGE
        elif flow.has_request_data:
            tabs.active = _TAB_REQUEST
        elif flow.has_response_data:
            tabs.active = _TAB_RESPONSE
        else:
            tabs.active = _TAB_DETAIL

    def _update_tab_labels(self, tabs: TabbedContent, flow: "Flow") -> None:
        """Dim tab labels for tabs without data; mark raw-hex tabs."""
        label_map = {
            _TAB_REQUEST: ("Request", flow.has_request_data, self._raw_request),
            _TAB_RESPONSE: ("Response", flow.has_response_data, self._raw_response),
            _TAB_DETAIL: ("Detail", True, False),
            _TAB_MESSAGE: ("Message", _fd._flow_has_messages(flow), False),
            _TAB_LAYERS: ("Layers", bool(getattr(flow, "layers", None)), False),
        }
        for pane_id, (name, has_data, is_raw) in label_map.items():
            try:
                tab = tabs.get_tab(pane_id)
                label = name if has_data else f"{name} [dim]\u00b7[/]"
                if is_raw:
                    label += f" [bold {c('warning')}][HEX][/]"
                tab.label = label
            except Exception:
                pass
        self._update_byte_tabs(flow)
        self._update_optional_tabs(flow)

    def _render_tab(self, flow: "Flow", tab_id: str) -> None:
        """Render a single tab by its pane ID."""
        if tab_id == _TAB_REQUEST:
            self._update_request(flow)
        elif tab_id == _TAB_RESPONSE:
            self._update_response(flow)
        elif tab_id == _TAB_DETAIL:
            self._update_detail(flow)
        elif tab_id == _TAB_MESSAGE:
            self._render_message_tab(flow)
        elif tab_id == _TAB_LAYERS:
            self._render_layers_tab(flow)
        elif tab_id.startswith(_TAB_BYTES_PREFIX):
            self._render_byte_tab_by_id(tab_id)
        elif tab_id == _TAB_OHTTP:
            self._render_ohttp_tab(flow)
        elif tab_id.startswith(_TAB_EXT_PREFIX):
            self._render_extension_tab(tab_id)
        else:
            self._update_extra_tabs(flow)

    def refresh_flow(self, flow: "Flow") -> None:
        """Re-render only the visible tab if the given flow is currently displayed."""
        if self._current_flow is None or self._current_flow.flow_id != flow.flow_id:
            return
        self._current_flow = flow
        self._update_header(flow)
        try:
            self._update_tab_labels(self._tabs, flow)
            self._render_tab_safely(flow, self._tabs.active)
        except Exception:
            self.show_flow(flow)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Re-render the newly visible tab to ensure fresh content."""
        if self._skip_tab_event or self._current_flow is None:
            return
        self._render_tab_safely(self._current_flow, event.pane.id)

    def _render_tab_safely(self, flow: "Flow", tab_id: str) -> None:
        """Render *tab_id*; a render failure shows an error line instead of crashing.

        Content is attacker-controlled traffic, so a parse/markup error must
        never reach Textual's event loop and end a live capture.
        """
        try:
            self._render_tab(flow, tab_id)
        except Exception as exc:
            _log.exception("flow detail: rendering tab %s failed", tab_id)
            self._write_render_error(tab_id, exc)

    def _log_for_tab(self, tab_id: str):
        """The RichLog backing *tab_id*, or None for plugin/unknown tabs."""
        log_map = {
            _TAB_REQUEST: self._request_log,
            _TAB_RESPONSE: self._response_log,
            _TAB_DETAIL: self._detail_log,
            _TAB_MESSAGE: getattr(self, "_message_log", None),
            _TAB_LAYERS: getattr(self, "_layers_log", None),
            **getattr(self, "_byte_logs", {}),
            _TAB_OHTTP: getattr(self, "_ohttp_log", None),
            **getattr(self, "_ext_logs", {}),
        }
        return log_map.get(tab_id)

    def _write_render_error(self, tab_id: str, exc: Exception) -> None:
        """Show a render failure as an escaped error line on the tab's log."""
        log = self._log_for_tab(tab_id)
        if log is None:
            return
        try:
            log.write(f"[bold {c('error')}]\u26a0 Could not render this view: "
                      f"{_markup_escape(f'{type(exc).__name__}: {exc}')}[/]")
        except Exception:
            _log.exception("flow detail: writing the render error failed")
