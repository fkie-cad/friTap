"""Protocol vocabulary for the display filter.

One normalizer maps every protocol label friTap produces (parser protocol
strings such as ``"HTTP/1.1"``, layer names such as ``"telegram_e2e"``, the
layered display label ``"HTTP/2[Signal]"``, transport hints such as
``"quic"``) onto the canonical protocol-layer NAMES of
:mod:`friTap.flow.layer_registry`. The filter engine then asks one question —
:func:`flow_has_protocol` — and gets the same answer for a live ``Flow``, a
``FlowSummary`` and a replay-built row that only carries scalar labels.

The known-name list is derived from the layer registry on every call, so
plugin layers registered after import are included.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Iterable

from friTap.constants import LAYER_DISPLAY_NAMES

# Labels that carry no protocol information.
_EMPTY_LABELS = frozenset({"", "unknown"})

# Real remaps the reverse LAYER_DISPLAY_NAMES table and the parser-protocol
# mapping (``app_layer_name``) do not cover. Keys are lowercase; any other
# label normalizes to itself (lowercased), so identity entries are not needed.
_EXTRA_LABELS: dict[str, str] = {
    "http1.1": "http1",
    "http1.0": "http1",
    # Telegram keylog/transport events are tagged "telegram"; the transport
    # they describe is MTProto.
    "telegram": "mtproto",
    "quic_unprocessed": "quic",
}

# User-facing group names that expand to several canonical protocols.
PROTOCOL_ALIASES: dict[str, frozenset[str]] = {
    "telegram": frozenset({"mtproto", "telegram_e2e"}),
    "tg": frozenset({"mtproto", "telegram_e2e"}),
    "e2e": frozenset({"telegram_e2e"}),
    "secretchat": frozenset({"telegram_e2e"}),
    "ws": frozenset({"websocket"}),
    "http": frozenset({"http1", "http2", "http3"}),
}

# Names that are valid filter terms even though no layer is registered for them.
# ``bhttp`` (RFC 9292 Binary HTTP, the inner payload of an OHTTP exchange) is
# kept as its own name; canonical_protocols() additionally implies "ohttp".
_EXTRA_KNOWN_NAMES = frozenset({"ohttp", "bhttp", "tcp", "udp", "tls", "quic"})

# Protocols whose presence implies another one.
_IMPLIED_PROTOCOLS: dict[str, str] = {"bhttp": "ohttp"}

_LAYER_LABEL_SPLIT = re.compile(r"[\[\]]")

# Parser protocol strings ("HTTP/1.1", "HTTP/1.0" ...) start with this prefix.
_PARSER_HTTP_PREFIX = "http/"


def _reverse_display_names() -> dict[str, str]:
    """Map each lowercase layer display string back to its layer name."""
    return {display.lower(): name for name, display in LAYER_DISPLAY_NAMES.items()}


_LABEL_TO_CANONICAL: dict[str, str] = {**_reverse_display_names(), **_EXTRA_LABELS}


def _parser_protocol_name(key: str) -> str | None:
    """Layer name of a versioned HTTP parser string such as ``"http/1.1"``."""
    if not key.startswith(_PARSER_HTTP_PREFIX):
        return None
    # Lazy: friTap.flow pulls in the collector/parsers, which a headless
    # ``import friTap.filter`` must not pay for.
    from friTap.flow.layer_pipeline import app_layer_name

    return app_layer_name(key)


@lru_cache(maxsize=1024)
def _canonical_for_key(key: str) -> str:
    return _LABEL_TO_CANONICAL.get(key) or _parser_protocol_name(key) or key


def normalize_protocol(label: str | None) -> str | None:
    """Return the canonical protocol name for *label*, or None if empty.

    Unknown labels are returned lowercased and stripped so plugin protocols
    still compare equal regardless of case.
    """
    if not isinstance(label, str):
        return None
    key = label.strip().lower()
    if key in _EMPTY_LABELS:
        return None
    return _canonical_for_key(key)


def split_layered_label(label: str | None) -> list[str]:
    """Split a layered label such as ``"HTTP/2[Signal]"`` into its parts.

    Returns the non-empty parts outermost first; a plain label yields a
    single-element list and an empty/None label yields ``[]``.
    """
    if not isinstance(label, str):
        return []
    return [part.strip() for part in _LAYER_LABEL_SPLIT.split(label) if part.strip()]


def normalize_labels(labels: Iterable[Any]) -> set[str]:
    """Normalize every (possibly layered) label, dropping empty results."""
    result: set[str] = set()
    for label in labels:
        for part in split_layered_label(label):
            canonical = normalize_protocol(part)
            if canonical:
                result.add(canonical)
    return result


def _layer_names(obj: Any) -> list[str]:
    """Return the names of the object's live layer stack (empty if none)."""
    layers = getattr(obj, "layers", None) or ()
    return [getattr(layer, "name", "") for layer in layers]


def _parsed_protocol(obj: Any, side: str) -> str:
    parsed = getattr(obj, side, None)
    return getattr(parsed, "protocol", "") if parsed is not None else ""


def _scalar_labels(obj: Any) -> list[Any]:
    """Collect every scalar protocol label the object exposes."""
    return [
        getattr(obj, "outer_app_protocol", ""),
        getattr(obj, "inner_e2e_protocol", ""),
        getattr(obj, "transport", ""),
        getattr(obj, "detected_protocol", ""),
        _parsed_protocol(obj, "request"),
        _parsed_protocol(obj, "response"),
        getattr(obj, "display_protocol_layered", ""),
    ]


def _precomputed_protocols(obj: Any) -> set[str]:
    precomputed = getattr(obj, "protocols", None)
    if isinstance(precomputed, frozenset) and precomputed:
        return set(precomputed)
    return set()


def flow_has_ohttp(obj: Any) -> bool:
    """True when *obj* carries an OHTTP inner request/response (or the flag)."""
    return bool(
        getattr(obj, "ohttp_inner_request", None) is not None
        or getattr(obj, "ohttp_inner_response", None) is not None
        or getattr(obj, "has_ohttp", False)
    )


def _collect_protocols(obj: Any, extra_labels: Iterable[Any]) -> set[str]:
    result = _precomputed_protocols(obj)
    result |= normalize_labels(extra_labels)
    result |= normalize_labels(_layer_names(obj))
    result |= normalize_labels(_scalar_labels(obj))
    if flow_has_ohttp(obj):
        result.add("ohttp")
    if getattr(obj, "ssl_session_id", ""):
        result.add("tls")
    for present, implied in _IMPLIED_PROTOCOLS.items():
        if present in result:
            result.add(implied)
    return result


def canonical_protocols(obj: Any, extra_labels: Iterable[Any] = ()) -> frozenset[str]:
    """Return every canonical protocol name present on a Flow-like object.

    Works on a full ``Flow``, a ``FlowSummary`` or any duck-typed object;
    missing attributes are treated as absent. *extra_labels* adds labels the
    object cannot expose itself (e.g. a flat tap summary's layer names); they
    take part in the implied-protocol rules. Never raises.
    """
    if obj is None:
        return frozenset()
    try:
        return frozenset(_collect_protocols(obj, extra_labels))
    except Exception:  # noqa: BLE001 — a filter predicate must never raise
        return frozenset()


def _registry_names() -> frozenset[str]:
    try:
        from friTap.flow.layer_registry import get_registry

        return get_registry().names()
    except Exception:  # noqa: BLE001 — fall back to the static vocabulary
        return frozenset(LAYER_DISPLAY_NAMES)


def known_protocol_names() -> list[str]:
    """Return every valid protocol filter term, sorted.

    Union of the registered layer names, the alias keys and the extra
    non-layer names. Computed per call so late plugin registrations appear.
    """
    names = set(_registry_names()) | set(PROTOCOL_ALIASES) | _EXTRA_KNOWN_NAMES
    return sorted(names)


def protocol_members(name: str | None) -> frozenset[str] | None:
    """Return the canonical protocols *name* stands for, or None if unknown."""
    if not isinstance(name, str):
        return None
    key = name.strip().lower()
    if key in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[key]
    canonical = normalize_protocol(key)
    if canonical and canonical in known_protocol_names():
        return frozenset({canonical})
    return None


def flow_has_protocol(obj: Any, name: str | None) -> bool:
    """Return True when *obj* carries *name* (a protocol or alias)."""
    members = protocol_members(name)
    if not members:
        return False
    return bool(members & canonical_protocols(obj))


def protocol_equivalents(operand: str | None) -> frozenset[str]:
    """Lowercase values that count as equal to a protocol ``==`` *operand*.

    The raw operand (case-insensitive, so layered display labels such as
    ``"HTTP/2[Signal]"`` still match verbatim), its canonical name and, for
    an alias, its member protocols: ``"HTTP/1.0"`` -> ``{"http/1.0",
    "http1"}``, ``"telegram"`` -> ``{"telegram", "mtproto", "telegram_e2e"}``.
    """
    if not isinstance(operand, str) or not operand.strip():
        return frozenset()
    raw = operand.strip().lower()
    result = {raw}
    canonical = normalize_protocol(raw)
    if canonical:
        result.add(canonical)
    result |= protocol_members(raw) or frozenset()
    return frozenset(result)


def aliases_for(protocols: Iterable[str]) -> tuple[str, ...]:
    """Alias names (``telegram``, ``http``, ``ws`` ...) with a member in *protocols*, sorted."""
    present = frozenset(protocols)
    return tuple(sorted(alias for alias, members in PROTOCOL_ALIASES.items()
                        if members & present))


@lru_cache(maxsize=256)
def protocol_labels(label: str | None) -> tuple[str, ...]:
    """Every filter label of one raw protocol *label* (headless events).

    The raw label, its canonical name and the aliases containing that name,
    deduped in that order: ``"telegram_e2e"`` -> ``("telegram_e2e",
    "e2e", "secretchat", "telegram", "tg")``. Empty/None yields ``()``.
    """
    if not isinstance(label, str) or not label.strip():
        return ()
    canonical = normalize_protocol(label)
    labels = [label.strip()]
    if canonical:
        labels.append(canonical)
        labels += aliases_for((canonical,))
    return tuple(dict.fromkeys(labels))


def protocol_prefix_matches(prefix: str | None) -> list[str]:
    """Return known names starting with *prefix* (case-insensitive), minus exact.

    Used for "did you mean" hints, e.g. ``"TELE"`` -> ``["telegram"]``.
    """
    if not isinstance(prefix, str) or not prefix.strip():
        return []
    key = prefix.strip().lower()
    return [n for n in known_protocol_names() if n.startswith(key) and n != key]


__all__ = [
    "PROTOCOL_ALIASES",
    "aliases_for",
    "canonical_protocols",
    "flow_has_ohttp",
    "flow_has_protocol",
    "known_protocol_names",
    "normalize_labels",
    "normalize_protocol",
    "protocol_equivalents",
    "protocol_labels",
    "protocol_members",
    "protocol_prefix_matches",
    "split_layered_label",
]
