"""Free helpers of the flow-detail widget: tab ids, flow predicates,
the extension render fingerprint, save-without-overwrite and guarded renderables.
"""

from __future__ import annotations

import itertools
import logging
import os
import re

from rich.measure import Measurement
from rich.pretty import Pretty
from rich.protocol import is_renderable
from rich.text import Text

from friTap.tui.themes import c
from friTap.tui.widgets import flow_detail as _fd
from friTap.tui.widgets.wire_text import safe_wire_text, visible_controls

# One logger for the whole package, named after it (tests attach to this name).
_log = logging.getLogger("friTap.tui.widgets.flow_detail")

# Wire-derived text helpers (see friTap.tui.widgets.wire_text).
_visible_controls = visible_controls
_safe_wire_text = safe_wire_text


#: Highest `` (n)`` suffix tried before giving up on finding a free save name.
_MAX_SAVE_SUFFIX = 9999


class _GuardedRenderable:
    """A third-party renderable whose measure/render errors cannot crash the app.

    ``RichLog`` defers writes until its size is known (a hidden pane's first
    activation) and renders them later in ``on_resize``, outside any caller
    ``try``; a failure there shows an error line in place of the content.
    """

    def __init__(self, inner, label: str) -> None:
        self._inner = inner if is_renderable(inner) else Pretty(inner)
        self._label = label

    def __rich_console__(self, console, options):
        try:
            segments = list(console.render(self._inner, options))
        except Exception as exc:
            yield self._error_text(exc)
            return
        yield from segments

    def __rich_measure__(self, console, options):
        try:
            return Measurement.get(console, options, self._inner)
        except Exception as exc:
            return Measurement.get(console, options, self._error_text(exc))

    def _error_text(self, exc: Exception) -> Text:
        """Log *exc* and describe it as literal (never markup-parsed) text."""
        _log.error("flow detail: extension tab %r content failed to render",
                   self._label, exc_info=exc)
        return Text(f"\u26a0 Could not render extension tab {self._label}: "
                    f"{type(exc).__name__}: {exc}", style=f"bold {c('error')}")


def _write_capped_decoder_lines(log, lines) -> None:
    """Write decoder *lines* as plain text, at most ``_EXTENSION_DECODER_MAX_LINES``.

    A third-party decoder may return a huge (or endless) iterable; anything
    past the cap is replaced by one truncation note.
    """
    shown = 0
    for line in itertools.islice(lines, _fd._EXTENSION_DECODER_MAX_LINES + 1):
        if shown == _fd._EXTENSION_DECODER_MAX_LINES:
            log.write(Text(f"\u2026 truncated after {shown:,} lines", style="dim"))
            return
        log.write(Text(str(line)))
        shown += 1


def _candidate_save_names(filename: str):
    """``name.ext``, then ``name (1).ext``, ``name (2).ext``, ..."""
    yield filename
    stem, ext = os.path.splitext(filename)
    for n in range(1, _MAX_SAVE_SUFFIX + 1):
        yield f"{stem} ({n}){ext}"


def save_without_overwrite(directory: str, filename: str, data: bytes) -> str:
    """Write *data* to a new file in *directory*; never replace an existing one.

    *filename* may come from a server ``Content-Disposition`` header, so an
    existing file (or symlink) of that name is left untouched and a
    `` (n)`` suffix is added instead. ``O_EXCL`` makes the check atomic.
    Returns the path written; raises ``FileExistsError`` if no name is free.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for name in _candidate_save_names(filename):
        path = os.path.join(directory, name)
        try:
            fd = os.open(path, flags, 0o666)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
    raise FileExistsError(f"no free file name for {filename!r} in {directory}")


def _get_header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup, returns lowercased value or ``""``."""
    for key, val in headers.items():
        if key.lower() == name:
            return val.lower()
    return ""


# Tab pane IDs are plain strings to avoid str-enum repr issues with Textual.
_TAB_REQUEST = "tab-request"
_TAB_RESPONSE = "tab-response"
_TAB_DETAIL = "tab-detail"
_TAB_MESSAGE = "tab-message"
_TAB_LAYERS = "tab-layers"
# Fixed pool of per-layer byte panes ("Decrypted TLS (98 bytes)", ...),
# hidden until a flow has >= 2 decrypted layers. A fixed pool shown/hidden
# via TabbedContent.show_tab/hide_tab avoids async add_pane/remove_pane races.
_TAB_BYTES_PREFIX = "tab-bytes-"
_BYTE_TAB_POOL_SIZE = 4
_BYTE_TAB_IDS = tuple(f"{_TAB_BYTES_PREFIX}{i}" for i in range(_BYTE_TAB_POOL_SIZE))
# OHTTP inner pane: composed up front and shown only for flows carrying
# decrypted OHTTP data (same show/hide pattern as the byte-tab pool).
_TAB_OHTTP = "tab-ohttp"
_OHTTP_TITLE = "OHTTP Inner"
# Legacy TabProvider id of OhttpTabProvider; the built-in pane supersedes it.
_OHTTP_PROVIDER_ID = "ohttp"
# Extension detail tabs (friTap.extensions.get_detail_tabs) are composed up
# front under this id prefix and shown only when spec.render(flow) is not None.
_TAB_EXT_PREFIX = "tab-ext-"
_INVALID_ID_CHARS = re.compile(r"[^A-Za-z0-9_-]")

def _extension_change_key(flow) -> tuple:
    """Cheap (O(1)) fingerprint of *flow* for the extension render throttle.

    Counts, state and the identity of parse results and attribution (these
    are replaced, not mutated). Byte-independent changes are caught by
    :func:`_extension_layer_signature`. Read via getattr because a host
    TapSource may pass a Flow-like object without the private counters.
    """
    return (getattr(flow, "flow_id", None), id(flow),
            len(getattr(flow, "chunks", ()) or ()),
            getattr(flow, "_total_bytes", None), getattr(flow, "state", None),
            id(getattr(flow, "request", None)), id(getattr(flow, "response", None)),
            id(getattr(flow, "ohttp_inner_request", None)),
            id(getattr(flow, "ohttp_inner_response", None)),
            id(getattr(flow, "attribution", None)))

def _extension_layer_signature(flow) -> tuple:
    """The flow list's :func:`layer_signature` of *flow* (walks all layers)."""
    from friTap.tui.widgets.flow_list import layer_signature

    return layer_signature(flow)

def _fingerprint_or_unique(compute, flow):
    """``compute(flow)``, or a fresh object (never equal: always re-render) if it raises."""
    try:
        return compute(flow)
    except Exception:
        _log.debug("extension change fingerprint failed; re-rendering", exc_info=True)
        return object()

def _extension_pane_id(spec_id, used: set) -> str:
    """A valid, unique Textual id for extension tab *spec_id* (prefixed)."""
    base = _TAB_EXT_PREFIX + (_INVALID_ID_CHARS.sub("_", str(spec_id)) or "tab")
    pane_id, n = base, 2
    while pane_id in used:
        pane_id, n = f"{base}-{n}", n + 1
    used.add(pane_id)
    return pane_id

def _flow_has_ohttp(flow) -> bool:
    """True if *flow* carries a decrypted OHTTP inner request or response."""
    return (getattr(flow, "ohttp_inner_request", None) is not None
            or getattr(flow, "ohttp_inner_response", None) is not None)

def _flow_signal_layer(flow):
    """Return a flow's parsed Signal layer (non-mutating), or None."""
    try:
        return flow.layer("signal")
    except Exception:
        return None

def _flow_is_signal(flow) -> bool:
    """True if *flow* has a Signal layer carrying parsed messages."""
    layer = _flow_signal_layer(flow)
    return bool(layer is not None and getattr(layer, "messages", None))

# Message-bearing layers, innermost (E2E) last so a Telegram Secret-Chat
# layer is preferred over the carrier MTProto transport when both exist.
_MESSAGE_LAYER_NAMES = ("signal", "mtproto", "telegram_e2e")

def _flow_message_layer(flow):
    """The innermost Signal / MTProto / Telegram-E2E layer carrying parsed
    ``messages``, or None."""
    chosen = None
    for name in _MESSAGE_LAYER_NAMES:
        try:
            layer = flow.layer(name)
        except Exception:
            layer = None
        if layer is not None and getattr(layer, "messages", None):
            chosen = layer
    return chosen

def _escape_bracket_label(text: str) -> str:
    """Escape every ``[`` so Textual markup keeps labels like ``TLS[RC4]``.

    Rich's ``escape`` only guards lowercase-led tags; Textual's ``Static``
    markup also consumes ``[RC4]`` / ``[Signal]``.
    """
    return text.replace("[", "\\[")

def _safe_layer(flow, name: str):
    """Non-mutating ``flow.layer(name)`` lookup; None when absent/unsupported."""
    try:
        return flow.layer(name)
    except Exception:
        return None

def _flow_has_messages(flow) -> bool:
    """True if any Signal / MTProto / Telegram-E2E layer carries messages."""
    return _flow_message_layer(flow) is not None
