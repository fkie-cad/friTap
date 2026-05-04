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


def display_method(request: Optional[ParseLike]) -> str:
    if request is not None and request.method:
        return request.method
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
