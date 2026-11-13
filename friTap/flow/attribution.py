"""Transport vs originator attribution model for a flow (``Flow.attribution``).

Pure functions and constants only -- no collector state. The model separates
**which module carried a flow** (the transport: free and certain) from **who
caused it** (the originator: uncertain, so it carries a confidence)::

    {"transport": {"module": str, "kind": <KINDS>},
     "originator": {"sdk", "vendor", "category"}  | absent,
     "confidence": <CONFIDENCE>                    | absent,
     "source": <SOURCES>                           | absent,
     "bucket": <BUCKETS>                           | absent,
     "mixed": True                                 | absent}

Confidence rules (P2):

* a directly joined caller stack gives ``native-stack`` -- ``high`` only on a
  :data:`SYNCHRONOUS_KINDS` transport (the stack is captured on the caller's
  own thread), ``medium`` on every other kind, including Chromium-family ones
  (that stack is from the shared network thread), ``other``, an empty kind and
  overlay-added kinds;
* a flow that inherits its connection's originator gives
  ``connection-fallback``, always ``low`` -- never ``high``.
* a matched Java request context (:mod:`friTap.flow.request_context_join`) gives
  ``java-request`` (high, or medium when picked among different SDKs) or ``context``
  (WebView subresource, at most medium). Stronger claims replace weaker ones (:func:`claim_rank`).

A transport kind is any slug (:data:`KIND_PATTERN`): a signature overlay
(``FRITAP_SDK_SIGNATURES``) may add kinds beyond the shipped :data:`KINDS`.

``friTap.analysis.attribution.sdk`` imports this module (for
:func:`module_basename`), so the classifier is imported lazily inside
:func:`transport_attribution` to avoid an import cycle.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Callable, Optional

from friTap.caller_stack_shapes import COMPACT_TEXT_LIMIT, capped_text

#: Shipped transport kinds (``attribution.transport.kind``) -- documentation
#: only: an overlay may add more, so a kind is validated by :data:`KIND_PATTERN`.
KINDS = frozenset({
    "chrome", "webview", "cronet", "gms-cronet", "httpengine", "flutter",
    "libsignal", "electron", "cef", "other",
})
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE = frozenset({CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW})
SOURCE_JAVA_REQUEST = "java-request"
SOURCE_NATIVE_STACK = "native-stack"
SOURCE_CONNECTION_FALLBACK = "connection-fallback"
SOURCE_CONTEXT = "context"
SOURCES = frozenset({
    SOURCE_JAVA_REQUEST, SOURCE_NATIVE_STACK, SOURCE_CONNECTION_FALLBACK, SOURCE_CONTEXT,
})
BUCKET_CHROMIUM_INTERNAL = "chromium-internal"
BUCKET_CACHE = "cache"  # cached request context, no flow
BUCKETS = frozenset({BUCKET_CHROMIUM_INTERNAL, BUCKET_CACHE})
#: Transports whose caller stacks come from a shared network thread.
CHROMIUM_FAMILY_KINDS = frozenset({
    "chrome", "webview", "cronet", "gms-cronet", "httpengine", "electron", "cef",
})
#: Transports whose caller stacks are captured on the caller's own thread
#: (the request is issued synchronously), so a directly joined stack names the
#: real originator: the only kinds whose ``native-stack`` claim is ``high``.
SYNCHRONOUS_KINDS = frozenset({"libsignal"})
#: Kind for a TLS module the classifier does not know.
OTHER_KIND = "other"
#: Shape of a valid transport kind: a lower-case slug.
KIND_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

#: Keys of one originator-claim group; merged together, never piecemeal.
_ORIGINATOR_KEYS = ("originator", "confidence", "source")
_ORIGINATOR_FIELDS = ("sdk", "vendor", "category")
_ENUM_KEYS = {"confidence": CONFIDENCE, "source": SOURCES, "bucket": BUCKETS}
#: Precedence weights of :func:`claim_rank` (unknown/absent values weigh 0).
_CONFIDENCE_RANK = {CONFIDENCE_LOW: 1, CONFIDENCE_MEDIUM: 2, CONFIDENCE_HIGH: 3}
_SOURCE_RANK = {
    SOURCE_CONNECTION_FALLBACK: 1, SOURCE_NATIVE_STACK: 2,
    SOURCE_CONTEXT: 3, SOURCE_JAVA_REQUEST: 4,
}
#: Sources of a per-request (Java request context) claim.
REQUEST_SOURCES = frozenset({SOURCE_JAVA_REQUEST, SOURCE_CONTEXT})


def module_basename(module: str) -> str:
    """Basename of *module* for ``/`` and ``\\`` separated paths."""
    return str(module or "").replace("\\", "/").rsplit("/", 1)[-1]


def transport_attribution(module: str, path: str = "", process_name: str = "",
                          package_name: str = "") -> Optional[dict]:
    """``{"module", "kind"}`` for the TLS module that carried a flow.

    A module the classifier does not know is still a transport, of kind
    ``other``. ``None`` for an empty module.
    """
    if not module:
        return None
    from friTap.analysis.attribution.sdk import classify_transport
    classified = classify_transport(module, path, process_name, package_name)
    return classified or {"module": module_basename(module), "kind": OTHER_KIND}


def flow_originator(flow) -> Any:
    """The SDK a flow is attributed to: ``attribution.originator``, else ``flow.sdk``.

    The two-tier originator (the SDK that issued the request) wins over the
    older single-tier ``flow.sdk``, but only when it names an SDK (a dict with
    a non-empty string ``sdk``); a nameless originator never shadows
    ``flow.sdk``. The result is raw: callers normalise it.
    """
    originator = _flow_attribution(flow).get("originator")
    if isinstance(originator, dict) and _has_sdk_name(originator):
        return originator
    return getattr(flow, "sdk", None)


def _has_sdk_name(originator: dict) -> bool:
    """``True`` when *originator* carries a non-empty string ``sdk``."""
    name = originator.get("sdk")
    return isinstance(name, str) and bool(name.strip())


def sdk_name(originator) -> Optional[str]:
    """The ``sdk`` name of an originator dict (see :func:`_has_sdk_name`), else ``None``."""
    if isinstance(originator, dict) and _has_sdk_name(originator):
        return originator["sdk"]
    return None


def flow_transport_kind(flow) -> Optional[str]:
    """``attribution.transport.kind`` of *flow* as a non-empty string, or ``None``."""
    transport = _flow_attribution(flow).get("transport")
    if not isinstance(transport, dict):
        return None
    kind = transport.get("kind")
    return kind if isinstance(kind, str) and kind else None


def chromium_internal_candidate(flow) -> bool:
    """Cheap pre-check for :func:`chromium_internal_update`: no bucket,
    Chromium-family transport, no originator."""
    if _flow_attribution(flow).get("bucket"):
        return False
    return flow_transport_kind(flow) in CHROMIUM_FAMILY_KINDS and not flow_originator(flow)


def chromium_internal_update(flow, host: str) -> Optional[dict]:
    """``{"bucket": "chromium-internal"}`` for an unattributed Chromium-family
    flow to a listed internal host, else ``None``."""
    if not chromium_internal_candidate(flow):
        return None
    return chromium_internal_host_update(host)


def chromium_internal_host_update(host: str) -> Optional[dict]:
    """The host half of :func:`chromium_internal_update`, for callers that already
    passed :func:`chromium_internal_candidate`."""
    if not host or not _chromium_internal_host_check()(host):
        return None
    return {"bucket": BUCKET_CHROMIUM_INTERNAL}


@functools.cache
def _chromium_internal_host_check() -> Callable[[str], bool]:
    """``is_chromium_internal_host`` of the classifier, imported once on first
    use: friTap.analysis imports this module, so it cannot be imported at
    module level (see the module docstring)."""
    from friTap.analysis.attribution.sdk import is_chromium_internal_host
    return is_chromium_internal_host


def _flow_attribution(flow) -> dict:
    """*flow*'s ``attribution`` dict, or ``{}`` when absent or malformed."""
    attribution = getattr(flow, "attribution", None)
    return attribution if isinstance(attribution, dict) else {}


def direct_attribution(sdk: dict, transport_kind: str) -> dict:
    """Originator claim of a directly joined caller stack (``native-stack``).

    ``high`` only on a :data:`SYNCHRONOUS_KINDS` transport, whose stack is
    captured on the caller's own thread; ``medium`` on every other kind
    (Chromium-family, ``other``, empty or overlay-added), whose stack may come
    from a shared network thread.
    """
    confidence = (CONFIDENCE_HIGH if transport_kind in SYNCHRONOUS_KINDS
                  else CONFIDENCE_MEDIUM)
    return {"originator": dict(sdk), "source": SOURCE_NATIVE_STACK,
            "confidence": confidence}


def inherited_attribution(sdk: dict) -> dict:
    """Originator claim of a flow inheriting its connection's originator.

    Always ``connection-fallback`` / ``low``: never ``high``.
    """
    return {"originator": dict(sdk), "source": SOURCE_CONNECTION_FALLBACK,
            "confidence": CONFIDENCE_LOW}


def request_attribution(sdk: dict, confidence: str, source: str) -> dict:
    """Originator claim of a matched Java request context.

    *source* must be ``java-request`` or ``context``; a ``context`` claim is
    capped at ``medium`` (it is inherited from the owning WebView load).
    """
    if source not in REQUEST_SOURCES:
        raise ValueError(f"not a request-context source: {source!r}")
    if confidence not in CONFIDENCE:
        raise ValueError(f"unknown confidence: {confidence!r}")
    if source == SOURCE_CONTEXT and confidence == CONFIDENCE_HIGH:
        confidence = CONFIDENCE_MEDIUM
    return {"originator": dict(sdk), "source": source, "confidence": confidence}


def claim_rank(claim: Optional[dict]) -> tuple:
    """Precedence of an originator claim as ``(confidence, source)`` weights.

    Compared as a tuple: confidence first (high > medium > low), the source
    breaks ties (java-request > context > native-stack > connection-fallback).
    A missing or nameless originator ranks ``(0, 0)``, below every claim.
    """
    if not isinstance(claim, dict) or not claim.get("originator"):
        return (0, 0)
    return (_CONFIDENCE_RANK.get(claim.get("confidence"), 0),
            _SOURCE_RANK.get(claim.get("source"), 0))


def merge_attribution(existing: Optional[dict], update: dict) -> dict:
    """Merge *update* into a copy of *existing* without clobbering.

    The transport is kept when already set; an existing originator claim
    (originator + confidence + source) is replaced only by a strictly
    stronger one (:func:`claim_rank`), never by an equal or weaker one; a
    missing bucket is filled; ``mixed`` only ever turns on. A
    ``chromium-internal`` bucket never coexists with an originator: it is
    dropped once one is present (it means "no SDK issued this").
    """
    merged = dict(existing or {})
    if "transport" in update and "transport" not in merged:
        merged["transport"] = update["transport"]
    if update.get("originator") and (
            not merged.get("originator") or claim_rank(update) > claim_rank(merged)):
        for key in _ORIGINATOR_KEYS:
            merged.pop(key, None)
            if key in update:
                merged[key] = update[key]
    if "bucket" in update and "bucket" not in merged:
        merged["bucket"] = update["bucket"]
    if merged.get("originator") and merged.get("bucket") == BUCKET_CHROMIUM_INTERNAL:
        del merged["bucket"]
    if update.get("mixed") is True:
        merged["mixed"] = True
    return merged


def sanitize_attribution(value) -> Optional[dict]:
    """Re-bound an untrusted ``attribution`` (e.g. read from a ``.tap``).

    Keeps whitelisted keys only, drops enum values outside their sets and kinds
    that are not slugs, requires strings (escaped and capped at
    :data:`~friTap.caller_stack_shapes.COMPACT_TEXT_LIMIT`, like
    ``caller_stack``), keeps ``mixed`` only when it is
    ``True``. ``None`` when nothing survives.
    """
    if not isinstance(value, dict):
        return None
    clean: dict = {}
    transport = _sanitize_transport(value.get("transport"))
    if transport:
        clean["transport"] = transport
    originator = _sanitize_originator(value.get("originator"))
    if originator:
        clean["originator"] = originator
    for key, allowed in _ENUM_KEYS.items():
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate in allowed:
            clean[key] = candidate
    if value.get("mixed") is True:
        clean["mixed"] = True
    return clean or None


def _bounded_string(value) -> Optional[str]:
    """*value* escaped and capped like ``caller_stack`` text when a string, else ``None``."""
    return capped_text(value, COMPACT_TEXT_LIMIT) if isinstance(value, str) else None


def _sanitize_transport(value) -> Optional[dict]:
    """``{"module", "kind"}`` with string fields and a slug kind, else ``None``."""
    if not isinstance(value, dict):
        return None
    transport = {}
    module = _bounded_string(value.get("module"))
    if module is not None:
        transport["module"] = module
    kind = value.get("kind")
    if isinstance(kind, str) and KIND_PATTERN.fullmatch(kind):
        transport["kind"] = kind
    return transport or None


def _sanitize_originator(value) -> Optional[dict]:
    """``{"sdk", "vendor", "category"}`` keeping string fields only, else ``None``.

    ``None`` too when no non-empty ``sdk`` name survives: a nameless
    originator is dropped entirely rather than kept as vendor/category only.
    """
    if not isinstance(value, dict):
        return None
    originator = {}
    for field in _ORIGINATOR_FIELDS:
        text = _bounded_string(value.get(field))
        if text is not None:
            originator[field] = text
    return originator if _has_sdk_name(originator) else None
