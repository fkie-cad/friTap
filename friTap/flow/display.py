"""Shared display logic for Flow and FlowSummary.

Free functions computing display strings from any object whose ``request`` /
``response`` conform to :class:`ParseLike`; both classes delegate their
``display_*`` properties here.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from friTap.flow.layer_registry import (
    carrier_for_inner,
    inner_e2e_layer_names,
    message_transport_names,
)

_LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1", "localhost"})


@runtime_checkable
class ParseLike(Protocol):
    """Attribute contract for parsed request/response metadata (``ParseResult`` and ``_ParseStub``)."""
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


def display_protocol(flow: FlowLike) -> str:
    if flow.request is not None and flow.request.protocol:
        return flow.request.protocol
    if flow.response is not None and flow.response.protocol:
        return flow.response.protocol
    if flow.detected_protocol:
        return flow.detected_protocol
    return "unknown"


# Ordered layer-name lists shared by the layered display path and the FlowSummary
# scalars. OUTER picks the first app layer present; INNER the innermost E2E layer.
# ``mtproto`` is both a candidate inner E2E (plain cloud flow) and a candidate outer
# carrier (a secret chat's ``telegram_e2e`` rides inside it), so nesting renders
# ``MTProto[Telegram-E2E]`` while a bare cloud flow stays ``MTProto``.
OUTER_APP_LAYER_NAMES = ("http1", "http2", "http3", "websocket")
# Derived from descriptors with an ``inner_e2e_rank``, ordered by it.
INNER_E2E_LAYER_NAMES = inner_e2e_layer_names()

# Carriers that can wrap a distinct inner E2E layer (outer[inner]), derived from
# the descriptors' ``carrier`` field (e.g. TLS[RC4]).
_CARRIER_FOR_INNER = carrier_for_inner()


def _carrier_display_names() -> dict:
    """Display names for carrier-only layers absent from LAYER_DISPLAY_NAMES.

    Local on purpose: LAYER_DISPLAY_NAMES feeds the display-filter vocabulary, which must not gain ``tls``.
    """
    from friTap.constants import PROTOCOL_TLS

    return {"tls": PROTOCOL_TLS}


def layer_display_name(layer_name: str) -> str:
    """Return the human display string for a protocol-layer NAME."""
    from friTap.constants import LAYER_DISPLAY_NAMES

    name = LAYER_DISPLAY_NAMES.get(layer_name, "")
    return name or _carrier_display_names().get(layer_name, "")


def display_protocol_layered(flow) -> str:
    """Compose a layered ``outer-app[inner-E2E]`` protocol string.

    OUTER is the first app layer present, INNER the innermost E2E layer present:
    both and different -> ``outer[inner]``; one -> that one; neither ->
    :func:`display_protocol`. Accepts a full ``Flow`` or a ``FlowSummary`` (reads
    the ``outer_app_protocol`` / ``inner_e2e_protocol`` scalars).
    """
    if hasattr(flow, "layers"):
        outer = ""
        inner = ""
        present = set()
        for layer in flow.layers:
            present.add(getattr(layer, "name", getattr(layer, "_name", "")))
        for name in OUTER_APP_LAYER_NAMES:
            if name in present:
                outer = layer_display_name(name)
                break
        for name in INNER_E2E_LAYER_NAMES:
            if name in present:
                inner = layer_display_name(name)
        # (keeps scanning: the innermost E2E layer wins). If its carrier is also
        # present (telegram_e2e inside mtproto), promote the carrier to outer.
        if not outer:
            inner_name = next(
                (n for n in reversed(INNER_E2E_LAYER_NAMES) if n in present), ""
            )
            carrier = _CARRIER_FOR_INNER.get(inner_name, "")
            if carrier and carrier in present:
                outer = layer_display_name(carrier)
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

    Uses the non-mutating ``flow.layer(name)`` (attribute access would materialize
    an empty layer). Shared by both FlowSummary implementations for offline/live parity.
    """
    outer = ""
    for name in OUTER_APP_LAYER_NAMES:
        if flow.layer(name) is not None:
            outer = layer_display_name(name)
            break
    inner = ""
    inner_name = ""
    for name in INNER_E2E_LAYER_NAMES:
        if flow.layer(name) is not None:
            inner = layer_display_name(name)
            inner_name = name
    # Keep scanning (innermost E2E wins); promote a present carrier (mtproto around
    # telegram_e2e) to outer so stored scalars reproduce ``Outer[Inner]`` offline.
    if not outer and inner_name:
        carrier = _CARRIER_FOR_INNER.get(inner_name, "")
        if carrier and flow.layer(carrier) is not None:
            outer = layer_display_name(carrier)

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


# Telegram layer names (cloud MTProto, then Secret-Chat E2E) in registry order
# (``layer_pipeline.MESSAGE_TRANSPORTS`` is the unordered set).
TELEGRAM_LAYER_NAMES = message_transport_names()
# Layers whose ``messages`` carry a per-item TL ``method`` usable as the Method
# column; innermost (E2E) last so a secret-chat method wins over its carrier.
_METHOD_LAYER_NAMES = TELEGRAM_LAYER_NAMES

# Method-classification buckets, highest priority first: chat > meaningful RPC >
# updates push > service. Case-insensitive substring match on the TL ``method``,
# so bare and namespaced ("messages.sendMessage") names both classify.
_CHAT_METHOD_HINTS = (
    "sendmessage", "updatenewmessage", "updatenewchannelmessage",
    "sendencrypted", "message",
)
_UPDATE_METHOD_HINTS = ("update",)
_SERVICE_METHOD_HINTS = (
    "msgs_ack", "msg_ack", "ack", "ping", "pong", "new_session_created",
    "msg_container", "future_salts", "gzip_packed", "salt",
)


def classify_method(method: str) -> int:
    """Rank a TL method name for Method-column priority: 4 chat, 3 RPC, 2 updates, 1 service, 0 unknown."""
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
    """Derive a flow's primary TL Method from its MTProto / Telegram-E2E layer messages.

    Returns the highest-priority operation name (chat > RPC > updates > service),
    ``""`` when none. Entries missing ``method`` contribute nothing. A
    ``FlowSummary`` has no layers and uses the stored scalar instead.
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
            rank = classify_method(method)
            if rank > best_rank:
                best_rank = rank
                best_method = method
    return best_method


def display_method_layered(flow) -> str:
    """Method-column string: stored ``flow_method`` scalar, else derived TL method, else HTTP method; ``""`` when unknown."""
    scalar = getattr(flow, "flow_method", "") or ""
    if scalar:
        return scalar
    derived = method_from_messages(flow)
    if derived:
        return derived
    http = display_method(getattr(flow, "request", None))
    if http:
        return http
    # tap_format FlowSummary stores the HTTP method as a flat scalar, not a nested ``request``.
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


def is_message_transport(flow) -> bool:
    """True when *flow* rides a message-stream transport (MTProto / Secret Chat), where an HTTP status is meaningless.

    Same names as ``layer_pipeline.MESSAGE_TRANSPORTS`` (both derive from the
    layer registry), so ``layer_pipeline`` need not be imported.
    """
    return (getattr(flow, "transport", "") or "") in TELEGRAM_LAYER_NAMES


def display_status_for(flow) -> str:
    """Flow-aware status string: ``""`` for message transports, else HTTP status."""
    if is_message_transport(flow):
        return ""
    return getattr(flow, "display_status", "") or ""


def has_parsed_side(flow, side: str) -> bool:
    """True when *flow* carries a parsed ``request``/``response`` (*side*).

    Also works on the flat ``tap_format.FlowSummary`` (no parse objects; records ``has_request``/``has_response``).
    """
    if getattr(flow, side, None) is not None:
        return True
    return bool(getattr(flow, f"has_{side}", False))


def message_direction_status(flow) -> str:
    """``sent`` / ``recv`` / ``sent+recv`` from the parsed request/response, ``""`` when neither."""
    has_sent = has_parsed_side(flow, "request")
    has_recv = has_parsed_side(flow, "response")
    if has_sent and has_recv:
        return "sent+recv"
    if has_sent:
        return "sent"
    if has_recv:
        return "recv"
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
    literal_direction: bool = False,
) -> str:
    """Directional connection string (``->``, ``<-``, ``<->``).

    With *literal_direction* (per-packet message transports) src/dst already are the
    packet's real endpoints, so the arrow is always ``->``.
    """
    src = f":{src_port}" if src_addr in _LOOPBACK_ADDRS else f"{src_addr}:{src_port}"
    dst = host or display_host(request, dst_addr, dst_port)
    has_req = request is not None
    has_resp = response is not None
    if literal_direction:
        arrow = "\u2192"
    elif has_req and has_resp:
        arrow = "\u21c4"
    elif has_resp and not has_req:
        arrow = "\u2190"
    else:
        arrow = "\u2192"
    return f"{src} {arrow} {dst}"
