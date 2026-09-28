"""Field registry: maps Wireshark-like filter names to Flow/DataCanonical accessors."""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Callable

from .layer_fields import (
    LayerFieldSpec,
    all_methods,
    extract_filter_attrs_from_flow,
    layer_field_names,
    layer_field_spec,
    lookup_attr,
)
from .protocols import (
    PROTOCOL_ALIASES,
    aliases_for,
    canonical_protocols,
    flow_has_ohttp,
    known_protocol_names,
    protocol_equivalents,
    protocol_labels,
    protocol_members,
    protocol_prefix_matches,
    split_layered_label,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.schemas.canonical import DataCanonical


@dataclass(frozen=True)
class FieldDef:
    """Definition of a filterable field.

    ``multi`` fields return a tuple of values; comparisons use Wireshark's
    multi-occurrence rule (any value matches; ``!=`` means no value equals).
    ``needs_context`` fields are called as ``accessor(obj, ctx)`` where *ctx*
    is the optional evaluation context passed to ``FilterEngine.matches``.
    ``operand_equivalents`` (optional) maps an ``==``/``!=`` operand to the
    lowercase set of values that count as equal to it; the parser precomputes
    it once (e.g. ``protocol == "HTTP/1.0"`` also equals ``http1``).
    ``description`` is the one-line text of the generated filter help.
    """
    name: str
    value_type: str  # "str", "int", "float", "bool", "bytes"
    accessor: Callable[..., Any]
    canonical_accessor: Callable[["DataCanonical"], Any] | None = None
    is_dual: bool = False
    dual_partner: str = ""  # name of the other field in the dual pair
    multi: bool = False
    needs_context: bool = False
    operand_equivalents: Callable[[str], frozenset[str]] | None = None
    description: str = ""


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
    """The flow's single display-protocol label.

    No registry field uses it any more: ``protocol`` / ``frame.protocol`` are
    backed by the multi-valued :func:`_flow_protocol_labels`.
    """
    proto = flow.display_protocol
    return proto if proto and proto != "unknown" else None


def _flow_state(flow: "Flow") -> str | None:
    # A tap_format FlowSummary stores the state as a plain string.
    state = flow.state
    return getattr(state, "value", state) if state else None


def _flow_duration(flow: "Flow") -> float | None:
    d = flow.duration
    return d if d and d > 0 else None


def _flow_size(flow: "Flow") -> int | None:
    # A tap_format FlowSummary carries ``total_size`` instead of ``_total_bytes``.
    total = getattr(flow, "_total_bytes", None)
    if total is None:
        total = getattr(flow, "total_size", 0)
    return total if total and total > 0 else None


def _has_parsed_side(obj: Any, side: str) -> bool:
    """True if *obj* has a parsed request/response.

    A full ``Flow`` exposes ``request``/``response`` objects; the tap_format
    ``FlowSummary`` has no such attribute, only ``has_request`` /
    ``has_response`` booleans, which serve as the fallback.
    """
    if getattr(obj, side, None) is not None:
        return True
    return bool(getattr(obj, f"has_{side}", False))


def _flow_has_request(flow: "Flow") -> bool:
    return _has_parsed_side(flow, "request")


def _flow_has_response(flow: "Flow") -> bool:
    return _has_parsed_side(flow, "response")


def _flow_tls_session_id(flow: "Flow") -> str | None:
    return flow.ssl_session_id or None


def _flow_ohttp_present(flow: "Flow") -> bool:
    # Shared with FlowSummary.from_flow / canonical_protocols(): also honours
    # the ``has_ohttp`` flag of a tap_format FlowSummary, which has no
    # ``ohttp_inner_*`` attributes (direct access raised AttributeError).
    return flow_has_ohttp(flow)


# -- Precomputed per-flow filter data ----------------------------------------
#
# FlowSummary rows carry ``filter_attrs`` / ``protocols`` computed once at
# build time; a full Flow computes them on demand. NEVER probe a Flow with
# ``getattr(flow, "<layer name>")``: Flow.__getattr__ auto-creates layers.

_EMPTY_ATTRS: Mapping[str, tuple] = {}


def _flow_filter_attrs(obj: Any) -> Mapping[str, tuple]:
    """Per-protocol filter attributes (precomputed if present, else derived)."""
    attrs = getattr(obj, "filter_attrs", None)
    if attrs:
        return attrs
    if getattr(obj, "layers", None):
        return extract_filter_attrs_from_flow(obj)
    return _EMPTY_ATTRS


def _flow_protocols(obj: Any) -> frozenset[str]:
    """Canonical protocol names (precomputed if present, else derived)."""
    protocols = getattr(obj, "protocols", None)
    if isinstance(protocols, frozenset) and protocols:
        return protocols
    return canonical_protocols(obj)


def _has_any_protocol(obj: Any, members: frozenset[str]) -> bool:
    return bool(members & _flow_protocols(obj))


def _unique(values: Any) -> tuple:
    """Dedupe (order-preserving), dropping None / empty strings."""
    return tuple(dict.fromkeys(v for v in values if v is not None and v != ""))


# -- Protocol existence accessors --------------------------------------------
#
# One mechanism for every protocol predicate: the static rows below, the
# ``telegram.e2e`` alias and the dynamic ``<protocol>`` / ``protocol.<name>``
# fields all test membership in the flow's canonical protocol set. Only real
# protocols count: MTProto, WebSocket, Signal ... flows also carry
# request/response parse results, so their presence proves nothing about HTTP.

def _protocol_accessor(name: str, members: frozenset[str]) -> Callable[[Any], bool]:
    def _accessor(obj: Any) -> bool:
        return _has_any_protocol(obj, members)

    _accessor.__name__ = f"_flow_is_{name.replace('.', '_')}"
    return _accessor


def _protocol_predicate(name: str) -> Callable[[Any], bool]:
    """Predicate for a canonical protocol name or a static alias (``http``)."""
    return _protocol_accessor(name, PROTOCOL_ALIASES.get(name, frozenset({name})))


_flow_is_http = _protocol_predicate("http")
_flow_is_http1 = _protocol_predicate("http1")
_flow_is_http2 = _protocol_predicate("http2")
_flow_is_http3 = _protocol_predicate("http3")
# canonical_protocols() adds "tls" for any flow with an ssl_session_id.
_flow_is_tls = _protocol_predicate("tls")
_flow_is_ssh = _protocol_predicate("ssh")
_flow_is_ipsec = _protocol_predicate("ipsec")
_flow_is_telegram_e2e = _protocol_predicate("telegram_e2e")


# -- Generic multi-valued accessors ------------------------------------------

def _display_label(getter_name: str, obj: Any) -> str:
    """One raw display label of *obj* ("" when unknown or on error)."""
    from friTap.flow import display  # lazy: keeps ``import friTap.filter`` light

    try:
        label = getattr(display, getter_name)(obj)
    except Exception:  # noqa: BLE001 — a filter accessor must never raise
        return ""
    return label if label and label != "unknown" else ""


@lru_cache(maxsize=512)
def _protocol_labels_for(protocols: frozenset[str], layered: str,
                         plain: str) -> tuple[str, ...]:
    """Canonical names, matching aliases and display labels (and their parts)."""
    labels = [*sorted(protocols), *aliases_for(protocols)]
    for label in (layered, plain):
        if label:
            labels.append(label)
            labels.extend(split_layered_label(label))
    return _unique(labels)


def _flow_protocol_labels(obj: Any) -> tuple[str, ...]:
    """Every protocol label of a flow: canonical names, aliases, display labels.

    Lets ``protocol == "mtproto"``, ``protocol == telegram`` and
    ``protocol contains "HTTP/2"`` all work through plain any-match semantics.
    """
    return _protocol_labels_for(_flow_protocols(obj),
                                _display_label("display_protocol_layered", obj),
                                _display_label("display_protocol", obj))


def _str_attr(obj: Any, attr: str) -> str:
    value = getattr(obj, attr, "")
    return value if isinstance(value, str) else ""


def _derived_tl_method(obj: Any) -> str:
    from friTap.flow import display  # lazy: keeps ``import friTap.filter`` light

    try:
        return display.method_from_messages(obj)
    except Exception:  # noqa: BLE001 — a filter accessor must never raise
        return ""


def _flow_methods(obj: Any) -> tuple[str, ...]:
    """Every real method on a flow: TL methods and HTTP methods.

    Sources: the stored ``flow_method`` scalar, the TL method derived from
    live layers, ``request``/``response.method``, the flat HTTP-method scalar
    ``method`` of the tap_format FlowSummary and every TL method in the filter
    attributes. Display-only text (the E2E ``inner_summary`` such as
    ``"1:1 · 3 msgs"`` the flow list shows in an empty Method cell) is never a
    method, so it is excluded even if a scalar happens to carry it.
    """
    summary = _str_attr(obj, "inner_summary")
    methods = _unique([
        _str_attr(obj, "flow_method"),
        _derived_tl_method(obj),
        _safe_attr(obj, "request", "method"),
        _safe_attr(obj, "response", "method"),
        _str_attr(obj, "method"),
        *all_methods(_flow_filter_attrs(obj)),
    ])
    return tuple(m for m in methods if not summary or m != summary)


def _flow_transport(flow: "Flow") -> str | None:
    return getattr(flow, "transport", "") or None


def _flow_info(flow: "Flow") -> str | None:
    summary = getattr(flow, "inner_summary", "")
    if not summary and callable(getattr(flow, "layer", None)):
        from friTap.flow import display  # lazy: keeps ``import friTap.filter`` light

        summary = display.layered_scalars_from_flow(flow)[2]
    return summary or None


def _flow_process(flow: "Flow") -> str | None:
    return getattr(flow, "process_name", "") or None


def _scalar_plus_layer_attr(scalar_attr: str, layer_field: str) -> Callable[[Any], tuple]:
    """Multi accessor: a summary scalar united with the layer attribute."""
    def _accessor(obj: Any) -> tuple:
        return _unique([_str_attr(obj, scalar_attr),
                        *lookup_attr(_flow_filter_attrs(obj), layer_field)])

    _accessor.__name__ = f"_flow_{scalar_attr}"
    return _accessor


def _flow_frame_text(flow: "Flow", ctx: Any = None) -> bytes | None:
    """Searchable content bytes from the evaluation context.

    Contract: ``ctx.text_for(obj)`` returns the flow's decrypted content as
    LOWERCASED bytes (or None); ``contains`` relies on that.
    """
    if ctx is None:
        return None
    return ctx.text_for(flow)


# -- DataCanonical accessors -------------------------------------------------

def _canonical_src_addr(event: "DataCanonical") -> str | None:
    return event.src.addr if event.src.addr else None


def _canonical_dst_addr(event: "DataCanonical") -> str | None:
    return event.dst.addr if event.dst.addr else None


def _canonical_src_port(event: "DataCanonical") -> int | None:
    return event.src.port if event.src.port else None


def _canonical_dst_port(event: "DataCanonical") -> int | None:
    return event.dst.port if event.dst.port else None


def _canonical_protocol(event: "DataCanonical") -> tuple[str, ...] | None:
    """Raw event protocol plus its canonical name and matching aliases.

    Headless events carry a single raw label (``"telegram"``, ``"tls"`` ...);
    expanding it lets ``protocol == telegram`` / ``protocol == mtproto`` work
    exactly like on flows.
    """
    return protocol_labels(event.protocol) or None


# -- Registry ----------------------------------------------------------------

FIELD_REGISTRY: dict[str, FieldDef] = {}


def _protocol_labels_field(name: str, description: str) -> FieldDef:
    """``protocol`` and its alias ``frame.protocol``: multi-valued, layer-aware."""
    return FieldDef(name=name, value_type="str", accessor=_flow_protocol_labels,
                    canonical_accessor=_canonical_protocol, multi=True,
                    operand_equivalents=protocol_equivalents,
                    description=description)


_FIELD_DEFS: list[FieldDef] = [
    # Network
    FieldDef(name="ip.src", value_type="str", accessor=_flow_src_addr,
             canonical_accessor=_canonical_src_addr, description="Source IP address"),
    FieldDef(name="ip.dst", value_type="str", accessor=_flow_dst_addr,
             canonical_accessor=_canonical_dst_addr, description="Destination IP address"),
    FieldDef(name="ip.addr", value_type="str", accessor=_flow_src_addr,
             canonical_accessor=_canonical_src_addr, is_dual=True, dual_partner="ip.dst",
             description="Source or destination IP (dual)"),
    FieldDef(name="tcp.srcport", value_type="int", accessor=_flow_src_port,
             canonical_accessor=_canonical_src_port, description="Source port"),
    FieldDef(name="tcp.dstport", value_type="int", accessor=_flow_dst_port,
             canonical_accessor=_canonical_dst_port, description="Destination port"),
    FieldDef(name="tcp.port", value_type="int", accessor=_flow_src_port,
             canonical_accessor=_canonical_src_port, is_dual=True, dual_partner="tcp.dstport",
             description="Source or destination port (dual)"),
    # HTTP
    FieldDef(name="http.request", value_type="bool", accessor=_flow_has_request,
             description="Request exists"),
    FieldDef(name="http.request.method", value_type="str", accessor=_flow_http_method,
             description="HTTP method (GET, POST, ...)"),
    FieldDef(name="http.request.uri", value_type="str", accessor=_flow_http_uri,
             description="Request path and query"),
    FieldDef(name="http.host", value_type="str", accessor=_flow_http_host,
             description="Host header"),
    FieldDef(name="http.response", value_type="bool", accessor=_flow_has_response,
             description="Response exists"),
    FieldDef(name="http.response.code", value_type="int", accessor=_flow_http_status,
             description="HTTP status code"),
    FieldDef(name="http.content_type", value_type="str", accessor=_flow_http_content_type,
             description="Content-Type header"),
    FieldDef(name="http.content_length", value_type="int", accessor=_flow_http_content_length,
             description="Response body size"),
    # Protocol
    FieldDef(name="http", value_type="bool", accessor=_flow_is_http,
             description="HTTP/1.x, HTTP/2 or HTTP/3 traffic (request or response)"),
    FieldDef(name="http1", value_type="bool", accessor=_flow_is_http1,
             description="HTTP/1.x flow"),
    FieldDef(name="http2", value_type="bool", accessor=_flow_is_http2,
             description="HTTP/2 traffic"),
    FieldDef(name="http3", value_type="bool", accessor=_flow_is_http3,
             description="HTTP/3 traffic"),
    _protocol_labels_field(
        "frame.protocol",
        'Same as protocol; accepts labels ("HTTP/1.x", "HTTP/2") or names (http1, http2)'),
    # Flow
    FieldDef(name="flow.state", value_type="str", accessor=_flow_state,
             description="Flow state (active, complete)"),
    FieldDef(name="flow.duration", value_type="float", accessor=_flow_duration,
             description="Duration in seconds"),
    FieldDef(name="flow.size", value_type="int", accessor=_flow_size,
             description="Total bytes transferred"),
    FieldDef(name="flow.has_request", value_type="bool", accessor=_flow_has_request,
             description="Has request data"),
    FieldDef(name="flow.has_response", value_type="bool", accessor=_flow_has_response,
             description="Has response data"),
    # TLS
    FieldDef(name="tls", value_type="bool", accessor=_flow_is_tls,
             description="TLS flow (TLS transport or session ID present)"),
    FieldDef(name="tls.session_id", value_type="str", accessor=_flow_tls_session_id,
             description="TLS session identifier"),
    # OHTTP
    FieldDef(name="ohttp.present", value_type="bool", accessor=_flow_ohttp_present,
             description="OHTTP inner request/response present"),
    # Other protocols
    FieldDef(name="ssh", value_type="bool", accessor=_flow_is_ssh,
             description="SSH traffic"),
    FieldDef(name="ipsec", value_type="bool", accessor=_flow_is_ipsec,
             description="IPSec traffic"),
    # Generic
    _protocol_labels_field("protocol",
                           "Every protocol of the flow (layered), e.g. telegram"),
    FieldDef(name="method", value_type="str", accessor=_flow_methods, multi=True,
             description="TL/RPC methods of the flow, e.g. upload.getFile"),
    FieldDef(name="transport", value_type="str", accessor=_flow_transport,
             description="Transport (tcp, udp, ...)"),
    FieldDef(name="info", value_type="str", accessor=_flow_info,
             description="The Info column text"),
    FieldDef(name="process", value_type="str", accessor=_flow_process,
             description="Process name that produced the flow"),
    FieldDef(name="tls.sni", value_type="str",
             accessor=_scalar_plus_layer_attr("tls_sni", "tls.sni"), multi=True,
             description="Server Name Indication"),
    FieldDef(name="tls.alpn", value_type="str",
             accessor=_scalar_plus_layer_attr("tls_alpn", "tls.alpn"), multi=True,
             description="Negotiated ALPN"),
    FieldDef(name="frame", value_type="bytes", accessor=_flow_frame_text,
             needs_context=True,
             description="Decrypted content; use with contains"),
    FieldDef(name="telegram.e2e", value_type="bool", accessor=_flow_is_telegram_e2e,
             description="Telegram Secret Chat (end-to-end) traffic, same as telegram_e2e"),
]

FIELD_REGISTRY.update((fdef.name, fdef) for fdef in _FIELD_DEFS)

# Set of fields available on DataCanonical (for headless filtering)
CANONICAL_FIELDS = frozenset(
    name for name, fdef in FIELD_REGISTRY.items()
    if fdef.canonical_accessor is not None
)


# -- Dynamic fields (protocol predicates + per-layer attributes) --------------

PROTOCOL_FIELD_PREFIX = "protocol."

_DYNAMIC_CACHE: dict[str, FieldDef] = {}


def _protocol_field(name: str, members: frozenset[str]) -> FieldDef:
    return FieldDef(name=name, value_type="bool",
                    accessor=_protocol_accessor(name, members))


def _layer_attr_field(name: str, spec: LayerFieldSpec) -> FieldDef:
    key = spec.field

    def _accessor(obj: Any) -> tuple:
        return lookup_attr(_flow_filter_attrs(obj), key)

    return FieldDef(name=name, value_type=spec.value_type, accessor=_accessor,
                    multi=True, description=spec.description)


def _resolve_dynamic(name: str) -> FieldDef | None:
    """Synthesize a FieldDef for a protocol name/alias or a layer field."""
    if name.startswith(PROTOCOL_FIELD_PREFIX):
        members = protocol_members(name[len(PROTOCOL_FIELD_PREFIX):])
        return _protocol_field(name, members) if members else None
    spec = layer_field_spec(name)
    if spec is not None:
        return _layer_attr_field(name, spec)
    members = protocol_members(name)
    return _protocol_field(name, members) if members else None


def get_field(name: str) -> FieldDef | None:
    """Look up a field definition by name (case-insensitive).

    Static registry fields win; otherwise a protocol predicate
    (``telegram``, ``protocol.signal``) or a per-layer field
    (``mtproto.dc_id``) is synthesized and memoized.
    """
    if not isinstance(name, str):
        return None
    key = name.strip().lower()
    static = FIELD_REGISTRY.get(key)
    if static is not None:
        return static
    cached = _DYNAMIC_CACHE.get(key)
    if cached is not None:
        return cached
    dynamic = _resolve_dynamic(key)
    if dynamic is not None:
        _DYNAMIC_CACHE[key] = dynamic
    return dynamic


def dynamic_field_names() -> list[str]:
    """Protocol names, ``protocol.<name>`` forms and per-layer field names."""
    protocols = known_protocol_names()
    names = set(protocols)
    names.update(PROTOCOL_FIELD_PREFIX + p for p in protocols)
    names.update(layer_field_names())
    return sorted(names - set(FIELD_REGISTRY))


def all_field_names() -> list[str]:
    """Return every valid field name (static + dynamic), sorted."""
    return sorted(set(FIELD_REGISTRY) | set(dynamic_field_names()))


def is_canonical_only(expression_fields: set[str]) -> bool:
    """Return True if all fields in the set are available on DataCanonical."""
    return not non_canonical_fields(expression_fields)


def non_canonical_fields(expression_fields: set[str]) -> list[str]:
    """Return the fields of the set that have no DataCanonical accessor, sorted.

    Headless mode evaluates filters against single data events, so these
    fields always evaluate to "absent" there.
    """
    return sorted({f.lower() for f in expression_fields} - CANONICAL_FIELDS)


def is_field_prefix(name: str) -> bool:
    """Return True if *name* is a strict prefix of any valid field name.

    Case-insensitive and aware of dynamic names: ``is_field_prefix("http.resp")``
    and ``is_field_prefix("TELE")`` are True. Exact matches return False.
    """
    key = name.strip().lower()
    if not key or get_field(key) is not None:
        return False
    return any(field.startswith(key) and len(field) > len(key)
               for field in all_field_names())


_MAX_DID_YOU_MEAN = 3


def _alias_first(names: list[str]) -> list[str]:
    return sorted(names, key=lambda n: (n not in PROTOCOL_ALIASES, n))


def did_you_mean(name: str, limit: int = _MAX_DID_YOU_MEAN) -> list[str]:
    """Close valid field names for an unknown *name*, best first.

    Order: protocol-name prefix matches (aliases such as ``telegram`` first),
    then field-name prefix matches, then fuzzy (difflib) matches.
    """
    key = name.strip().lower()
    if not key:
        return []
    names = all_field_names()
    candidates = _alias_first(protocol_prefix_matches(key))
    candidates += [n for n in names if n.startswith(key) and n != key]
    candidates += difflib.get_close_matches(key, names, n=limit)
    return list(dict.fromkeys(candidates))[:limit]
