"""Field registry: maps Wireshark-like filter names to Flow/DataCanonical accessors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.schemas.canonical import DataCanonical


@dataclass(frozen=True)
class FieldDef:
    """Definition of a filterable field."""
    name: str
    value_type: str  # "str", "int", "float", "bool"
    accessor: Callable[["Flow"], Any]
    canonical_accessor: Callable[["DataCanonical"], Any] | None = None
    is_dual: bool = False
    dual_partner: str = ""  # name of the other field in the dual pair


def _safe_attr(obj: Any, *attrs: str, default: Any = None) -> Any:
    """Safely traverse nested attributes, returning default on None/missing."""
    current = obj
    for attr in attrs:
        if current is None:
            return default
        current = getattr(current, attr, None)
    return current if current is not None else default


# -- Flow accessors ----------------------------------------------------------

def _flow_src_addr(flow: "Flow") -> str | None:
    return flow.src_addr or None


def _flow_dst_addr(flow: "Flow") -> str | None:
    return flow.dst_addr or None


def _flow_src_port(flow: "Flow") -> int | None:
    return flow.src_port if flow.src_port else None


def _flow_dst_port(flow: "Flow") -> int | None:
    return flow.dst_port if flow.dst_port else None


def _flow_http_method(flow: "Flow") -> str | None:
    return _safe_attr(flow, "request", "method")


def _flow_http_uri(flow: "Flow") -> str | None:
    return _safe_attr(flow, "request", "url")


def _flow_http_host(flow: "Flow") -> str | None:
    return _safe_attr(flow, "request", "host")


def _flow_http_status(flow: "Flow") -> int | None:
    code = _safe_attr(flow, "response", "status_code")
    return code if code and code > 0 else None


def _flow_http_content_type(flow: "Flow") -> str | None:
    ct = _safe_attr(flow, "response", "content_type")
    if not ct:
        ct = _safe_attr(flow, "request", "content_type")
    return ct or None


def _flow_http_content_length(flow: "Flow") -> int | None:
    size = _safe_attr(flow, "response", "body_size")
    return size if size and size > 0 else None


def _flow_protocol(flow: "Flow") -> str | None:
    proto = flow.display_protocol
    return proto if proto and proto != "unknown" else None


def _flow_state(flow: "Flow") -> str | None:
    return flow.state.value if flow.state else None


def _flow_duration(flow: "Flow") -> float | None:
    d = flow.duration
    return d if d and d > 0 else None


def _flow_size(flow: "Flow") -> int | None:
    return flow._total_bytes if flow._total_bytes > 0 else None


def _flow_has_request(flow: "Flow") -> bool:
    return flow.request is not None


def _flow_has_response(flow: "Flow") -> bool:
    return flow.response is not None


def _flow_tls_session_id(flow: "Flow") -> str | None:
    return flow.ssl_session_id or None


def _flow_ohttp_present(flow: "Flow") -> bool:
    return (flow.ohttp_inner_request is not None
            or flow.ohttp_inner_response is not None)


# -- Protocol existence accessors --------------------------------------------

def _flow_is_http(flow: "Flow") -> bool:
    return flow.request is not None or flow.response is not None


def _flow_is_http2(flow: "Flow") -> bool:
    return flow.display_protocol.lower() == "http/2"


def _flow_is_http3(flow: "Flow") -> bool:
    return flow.display_protocol.lower() == "http/3"


def _flow_is_tls(flow: "Flow") -> bool:
    return bool(flow.ssl_session_id)


def _flow_is_ssh(flow: "Flow") -> bool:
    return flow.display_protocol.lower() == "ssh"


def _flow_is_ipsec(flow: "Flow") -> bool:
    return flow.display_protocol.lower() == "ipsec"


# -- DataCanonical accessors -------------------------------------------------

def _canonical_src_addr(event: "DataCanonical") -> str | None:
    return event.src.addr if event.src.addr else None


def _canonical_dst_addr(event: "DataCanonical") -> str | None:
    return event.dst.addr if event.dst.addr else None


def _canonical_src_port(event: "DataCanonical") -> int | None:
    return event.src.port if event.src.port else None


def _canonical_dst_port(event: "DataCanonical") -> int | None:
    return event.dst.port if event.dst.port else None


def _canonical_protocol(event: "DataCanonical") -> str | None:
    return event.protocol if event.protocol else None


# -- Registry ----------------------------------------------------------------

FIELD_REGISTRY: dict[str, FieldDef] = {}

_FIELD_DEFS: list[tuple] = [
    # (name, type, flow_accessor, canonical_accessor, is_dual, dual_partner)
    # Network
    ("ip.src", "str", _flow_src_addr, _canonical_src_addr, False, ""),
    ("ip.dst", "str", _flow_dst_addr, _canonical_dst_addr, False, ""),
    ("ip.addr", "str", _flow_src_addr, _canonical_src_addr, True, "ip.dst"),
    ("tcp.srcport", "int", _flow_src_port, _canonical_src_port, False, ""),
    ("tcp.dstport", "int", _flow_dst_port, _canonical_dst_port, False, ""),
    ("tcp.port", "int", _flow_src_port, _canonical_src_port, True, "tcp.dstport"),
    # HTTP
    ("http.request", "bool", _flow_has_request, None, False, ""),
    ("http.request.method", "str", _flow_http_method, None, False, ""),
    ("http.request.uri", "str", _flow_http_uri, None, False, ""),
    ("http.host", "str", _flow_http_host, None, False, ""),
    ("http.response", "bool", _flow_has_response, None, False, ""),
    ("http.response.code", "int", _flow_http_status, None, False, ""),
    ("http.content_type", "str", _flow_http_content_type, None, False, ""),
    ("http.content_length", "int", _flow_http_content_length, None, False, ""),
    # Protocol
    ("http", "bool", _flow_is_http, None, False, ""),
    ("http2", "bool", _flow_is_http2, None, False, ""),
    ("http3", "bool", _flow_is_http3, None, False, ""),
    ("frame.protocol", "str", _flow_protocol, _canonical_protocol, False, ""),
    # Flow
    ("flow.state", "str", _flow_state, None, False, ""),
    ("flow.duration", "float", _flow_duration, None, False, ""),
    ("flow.size", "int", _flow_size, None, False, ""),
    ("flow.has_request", "bool", _flow_has_request, None, False, ""),
    ("flow.has_response", "bool", _flow_has_response, None, False, ""),
    # TLS
    ("tls", "bool", _flow_is_tls, None, False, ""),
    ("tls.session_id", "str", _flow_tls_session_id, None, False, ""),
    # OHTTP
    ("ohttp.present", "bool", _flow_ohttp_present, None, False, ""),
    # Other protocols
    ("ssh", "bool", _flow_is_ssh, None, False, ""),
    ("ipsec", "bool", _flow_is_ipsec, None, False, ""),
]

for _name, _type, _accessor, _canon, _dual, _partner in _FIELD_DEFS:
    FIELD_REGISTRY[_name] = FieldDef(
        name=_name,
        value_type=_type,
        accessor=_accessor,
        canonical_accessor=_canon,
        is_dual=_dual,
        dual_partner=_partner,
    )

# Set of fields available on DataCanonical (for headless filtering)
CANONICAL_FIELDS = frozenset(
    name for name, fdef in FIELD_REGISTRY.items()
    if fdef.canonical_accessor is not None
)


def get_field(name: str) -> FieldDef | None:
    """Look up a field definition by name."""
    return FIELD_REGISTRY.get(name)


def all_field_names() -> list[str]:
    """Return all registered field names, sorted."""
    return sorted(FIELD_REGISTRY.keys())


def is_canonical_only(expression_fields: set[str]) -> bool:
    """Return True if all fields in the set are available on DataCanonical."""
    return expression_fields.issubset(CANONICAL_FIELDS)


def is_field_prefix(name: str) -> bool:
    """Return True if *name* is a strict prefix of any registered field name.

    E.g. ``is_field_prefix("http.resp")`` is True because ``http.response``
    and ``http.response.code`` exist.  Exact matches return False.
    """
    if name in FIELD_REGISTRY:
        return False
    return any(field.startswith(name) and len(field) > len(name)
               for field in FIELD_REGISTRY)
