"""Flow detail widget -- tabbed view showing request, response, and connection details.

:class:`FlowDetailWidget` (``widget.py``) composes the tabs and dispatches
rendering to one mixin per concern: ``detail_tabs`` (Request/Response/Detail),
``tl_pane``, ``header`` (header line, raw hex, trailing data), ``layers``,
``conversation_data`` + ``conversation_render`` (Message tab), ``optional_tabs``
(byte tabs, OHTTP, extension tabs), ``actions`` (key bindings) and ``body``
(decoders). Free helpers live in ``helpers``.

``time``, ``_EXT_RERENDER_INTERVAL``, ``_EXTENSION_DECODER_MAX_LINES``,
``_extension_layer_signature`` and ``_flow_has_messages`` are read through this
package at call time, so patching them here affects every submodule.
"""

from __future__ import annotations

import time  # noqa: F401 - read as _fd.time by optional_tabs

try:
    from textual.binding import Binding  # noqa: F401
    from textual.containers import Vertical  # noqa: F401
    from textual.message import Message  # noqa: F401
    from textual.widgets import RichLog, Static, TabbedContent, TabPane  # noqa: F401
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.widgets.hexdump import (  # noqa: F401 - re-exported
    _is_text,
    format_hexdump_lines,
)

#: Most lines shown from one (third-party) extension body decoder.
_EXTENSION_DECODER_MAX_LINES = 5000

from .helpers import (  # noqa: E402, F401
    _MAX_SAVE_SUFFIX,
    _candidate_save_names,
    _get_header,
    _GuardedRenderable,
    _log,
    _safe_wire_text,
    _visible_controls,
    _write_capped_decoder_lines,
    save_without_overwrite,
)

if TEXTUAL_AVAILABLE:
    # Extension render() is third-party code, so live refreshes re-run it at
    # most once per interval per flow; one deferred re-check catches the final state.
    _EXT_RERENDER_INTERVAL = 1.0

    from .helpers import (  # noqa: F401
        _BYTE_TAB_IDS,
        _BYTE_TAB_POOL_SIZE,
        _INVALID_ID_CHARS,
        _MESSAGE_LAYER_NAMES,
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
        _extension_change_key,
        _extension_layer_signature,
        _extension_pane_id,
        _fingerprint_or_unique,
        _flow_has_messages,
        _flow_has_ohttp,
        _flow_is_signal,
        _flow_message_layer,
        _flow_signal_layer,
        _safe_layer,
    )
    from .widget import FlowDetailWidget  # noqa: F401
