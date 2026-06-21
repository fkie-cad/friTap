"""Shared display logic for Flow and FlowSummary.

Free functions that compute display strings from any object whose
``request`` / ``response`` attributes conform to :class:`ParseLike`.
Both :class:`~friTap.flow.models.Flow` and
:class:`~friTap.flow.models.FlowSummary` delegate their ``display_*``
properties here so the formatting logic exists in exactly one place.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


_LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1", "localhost"})


# ---------------------------------------------------------------------------
# Structural type shared by ParseResult and _ParseStub
# ---------------------------------------------------------------------------

@runtime_checkable
class ParseLike(Protocol):
    """Minimal attribute contract for parsed request/response metadata.

    Both ``ParseResult`` (full parser output) and ``_ParseStub``
    (lightweight summary stub) satisfy this protocol.
    """
    protocol: str
    method: str
    url: str
    host: str
    status_code: int
    status_text: str
    content_type: str
    body_size: int


@runtime_checkable
class FlowLike(Protocol):
    """Attribute contract for protocol display from a Flow/FlowSummary."""
    request: Optional[ParseLike]
    response: Optional[ParseLike]
    detected_protocol: str


# ---------------------------------------------------------------------------
# Display free functions
# ---------------------------------------------------------------------------

def display_protocol(flow: FlowLike) -> str:
    if flow.request is not None and flow.request.protocol:
        return flow.request.protocol
    if flow.response is not None and flow.response.protocol:
        return flow.response.protocol
    if flow.detected_protocol:
        return flow.detected_protocol
    return "unknown"


# Ordered layer-name lists shared by the layered display path and the
# FlowSummary scalars (models.py / tap_format.py). OUTER picks the first app
# layer present; INNER picks the innermost E2E layer present.
#
# ``mtproto`` is BOTH a candidate inner E2E (a plain cloud MTProto flow has only
# an mtproto layer) AND a candidate outer carrier (a Telegram secret chat rides
# its ``telegram_e2e`` layer INSIDE the mtproto transport). The carrier list
# below lets ``display_protocol_layered`` recognise that genuine nesting so it
# renders ``MTProto[Telegram-E2E]`` while a bare cloud flow stays ``MTProto``.
OUTER_APP_LAYER_NAMES = ("http1", "http2", "http3", "websocket")
INNER_E2E_LAYER_NAMES = ("signal", "mtproto", "telegram_e2e")

# Carriers that can wrap a distinct inner E2E layer (outer[inner] nesting).
# ``mtproto`` carries ``telegram_e2e``; the app layers above carry signal/mtproto.
_CARRIER_FOR_INNER = {
    "telegram_e2e": "mtproto",
}


def _layer_display_name(layer_name: str) -> str:
    """Return the human display string for a protocol-layer NAME."""
    from friTap.constants import LAYER_DISPLAY_NAMES

    return LAYER_DISPLAY_NAMES.get(layer_name, "")


def display_protocol_layered(flow) -> str:
    """Compose a layered ``outer-app[inner-E2E]`` protocol string.

    OUTER is the display name of the first app layer present (in order
    ``http1, http2, http3, websocket``); INNER is the display name of the
    innermost E2E layer present (in order ``signal, mtproto, telegram_e2e``).

    * both present and different -> ``f"{outer}[{inner}]"`` (e.g. ``HTTP/2[Signal]``)
    * only inner -> ``inner``
    * only outer -> ``outer``
    * neither -> fall back to :func:`display_protocol`

    Accepts either a full ``Flow`` (has ``.layers`` to iterate) or a
    ``FlowSummary`` (no ``.layers``; reads the ``outer_app_protocol`` /
    ``inner_e2e_protocol`` scalars).
    """
    if hasattr(flow, "layers"):
        outer = ""
        inner = ""
        present = set()
        for layer in flow.layers:
            present.add(getattr(layer, "name", getattr(layer, "_name", "")))
        for name in OUTER_APP_LAYER_NAMES:
            if name in present:
                outer = _layer_display_name(name)
                break
        for name in INNER_E2E_LAYER_NAMES:
            if name in present:
                inner = _layer_display_name(name)
        # ^ keep scanning so the INNERMOST present E2E layer wins.
        # When the innermost E2E layer rides inside a protocol carrier that is
        # ALSO present (e.g. telegram_e2e inside mtproto), promote that carrier
        # to the outer slot so genuine nesting renders as ``Outer[Inner]``.
        if not outer:
            inner_name = next(
                (n for n in reversed(INNER_E2E_LAYER_NAMES) if n in present), ""
            )
            carrier = _CARRIER_FOR_INNER.get(inner_name, "")
            if carrier and carrier in present:
                outer = _layer_display_name(carrier)
    else:
        outer = getattr(flow, "outer_app_protocol", "") or ""
        inner = getattr(flow, "inner_e2e_protocol", "") or ""

    if outer and inner:
        return f"{outer}[{inner}]" if outer != inner else outer
    if inner:
        return inner
    if outer:
        return outer
    return display_protocol(flow)


def layered_scalars_from_flow(flow) -> tuple:
    """Compute ``(outer_app_protocol, inner_e2e_protocol, inner_summary)``.

    Uses the NON-mutating ``flow.layer(name)`` lookup (never attribute access,
    which would materialize an empty layer) so a summary stays a pure read.
    Shared by both FlowSummary implementations for offline/live parity.
    """
    outer = ""
    for name in OUTER_APP_LAYER_NAMES:
        if flow.layer(name) is not None:
            outer = _layer_display_name(name)
            break
    inner = ""
    inner_name = ""
    for name in INNER_E2E_LAYER_NAMES:
        if flow.layer(name) is not None:
            inner = _layer_display_name(name)
            inner_name = name
    # ^ keep scanning so the INNERMOST present E2E layer wins.
    # Promote a protocol carrier (e.g. mtproto wrapping telegram_e2e) to the
    # outer slot when present, so the stored summary scalars reproduce the
    # ``Outer[Inner]`` nesting offline. A bare cloud flow has no such carrier
    # and keeps an empty outer (renders as the plain inner protocol).
    if not outer and inner_name:
        carrier = _CARRIER_FOR_INNER.get(inner_name, "")
        if carrier and flow.layer(carrier) is not None:
            outer = _layer_display_name(carrier)

    inner_summary = ""
    signal_layer = flow.layer("signal")
    if signal_layer is not None:
        kind = "group" if getattr(signal_layer, "chat_type", "") == "group" else "1:1"
        count = getattr(signal_layer, "message_count", 0) or 0
        if count > 0:
            inner_summary = f"{kind} · {count} msg" + ("s" if count != 1 else "")
        else:
            inner_summary = kind
    return outer, inner, inner_summary


def display_method(request: Optional[ParseLike]) -> str:
    if request is not None and request.method:
        return request.method
    return ""


# Layer names whose ``messages`` carry a per-item ``method`` (TL operation name)
# that can stand in for the HTTP-style Method column. Innermost (E2E) last so a
# secret-chat method wins over the carrier transport when both exist.
_METHOD_LAYER_NAMES = ("mtproto", "telegram_e2e")

# Method-classification buckets, highest display priority first. A chat method
# (the operation that carries the actual conversation) outranks a meaningful RPC,
# which outranks an updates push, which outranks pure service traffic. The match
# is a case-insensitive substring test against the TL ``method`` name, so both
# bare ("sendMessage") and namespaced ("messages.sendMessage") forms classify.
_CHAT_METHOD_HINTS = (
    "sendmessage", "updatenewmessage", "updatenewchannelmessage",
    "sendencrypted", "message",
)
_UPDATE_METHOD_HINTS = ("update",)
_SERVICE_METHOD_HINTS = (
    "msgs_ack", "msg_ack", "ack", "ping", "pong", "new_session_created",
    "msg_container", "future_salts", "gzip_packed", "salt",
)


def _classify_method(method: str) -> int:
    """Rank a TL method name for Method-column priority (higher == preferred).

    4 chat operation · 3 meaningful RPC · 2 updates push · 1 service · 0 unknown.
    """
    if not method:
        return 0
    low = method.lower()
    if any(h in low for h in _CHAT_METHOD_HINTS):
        return 4
    if any(h in low for h in _UPDATE_METHOD_HINTS):
        return 2
    if any(h in low for h in _SERVICE_METHOD_HINTS):
        return 1
    return 3  # a named, non-service RPC (e.g. users.getUsers, getHistory)


def method_from_messages(flow) -> str:
    """Derive a flow's primary TL Method from its message-bearing layers.

    Scans the ``method`` field of each entry in any MTProto / Telegram-E2E layer
    and returns the highest-priority operation name (chat > RPC > updates >
    service). Reads every field defensively: entries may be missing ``method``
    (older/partly-enriched dicts), in which case they contribute nothing. Returns
    ``""`` when no layer carries a usable method.

    Accepts either a full ``Flow`` (``flow.layer(name)`` lookup) — a ``FlowSummary``
    has no layers and uses the stored scalar instead.
    """
    layer_lookup = getattr(flow, "layer", None)
    if not callable(layer_lookup):
        return ""
    best_method = ""
    best_rank = 0
    for name in _METHOD_LAYER_NAMES:
        try:
            layer = layer_lookup(name)
        except Exception:
            layer = None
        if layer is None:
            continue
        for entry in (getattr(layer, "messages", None) or []):
            try:
                method = (entry.get("method") or "").strip()
            except AttributeError:
                continue
            if not method:
                continue
            rank = _classify_method(method)
            if rank > best_rank:
                best_rank = rank
                best_method = method
    return best_method


def display_method_layered(flow) -> str:
    """Method-column string preferring a derived TL method, else the HTTP method.

    For a full ``Flow`` this derives the primary TL operation from the layer
    messages (see :func:`method_from_messages`); when absent it falls back to the
    request's HTTP method. For a ``FlowSummary`` (no layers) it uses the stored
    ``flow_method`` scalar, then the HTTP method. Returns ``""`` when nothing is
    known (the flow list renders that as ``-``).
    """
    scalar = getattr(flow, "flow_method", "") or ""
    if scalar:
        return scalar
    derived = method_from_messages(flow)
    if derived:
        return derived
    http = display_method(getattr(flow, "request", None))
    if http:
        return http
    # The tap_format FlowSummary carries the HTTP method as a flat scalar
    # (no nested ``request`` object), so fall back to that shape too.
    if getattr(flow, "request", None) is None:
        return getattr(flow, "method", "") or ""
    return ""


def display_host(
    request: Optional[ParseLike],
    dst_addr: str,
    dst_port: int,
) -> str:
    if request is not None and request.host:
        url = request.url
        if url and url != "/":
            return f"{request.host}{url}"
        return request.host
    return f"{dst_addr}:{dst_port}" if dst_addr else ""


def display_status(response: Optional[ParseLike]) -> str:
    if response is not None and response.status_code > 0:
        return f"{response.status_code} {response.status_text}".strip()
    return ""


def display_size(
    response: Optional[ParseLike],
    total_bytes: int,
) -> str:
    from friTap.flow.models import format_byte_size

    total = 0
    if response is not None:
        total = response.body_size
    if total == 0:
        total = total_bytes
    return format_byte_size(total)


def display_source(src_addr: str, src_port: int) -> str:
    if src_addr in _LOOPBACK_ADDRS:
        return f":{src_port}"
    return f"{src_addr}:{src_port}" if src_addr else ""


def display_connection(
    request: Optional[ParseLike],
    response: Optional[ParseLike],
    src_addr: str,
    src_port: int,
    dst_addr: str,
    dst_port: int,
    host: str = "",
) -> str:
    """Directional connection string: src -> dst, src <- dst, or src <-> dst."""
    src = f":{src_port}" if src_addr in _LOOPBACK_ADDRS else f"{src_addr}:{src_port}"
    dst = host or display_host(request, dst_addr, dst_port)
    has_req = request is not None
    has_resp = response is not None
    if has_req and has_resp:
        arrow = "\u21c4"
    elif has_resp and not has_req:
        arrow = "\u2190"
    else:
        arrow = "\u2192"
    return f"{src} {arrow} {dst}"
