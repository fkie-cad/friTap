"""Join Java request contexts (``request_context`` events) onto flows.

Events are folded per ``req_id`` and matched to a flow by (method, canonical URL)
and host receive time; host + time alone never yields a claim.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote, urlsplit

from friTap.caller_stack_shapes import REQUEST_CONTEXT_URL_LIMIT, strict_int

from .attribution import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    SOURCE_CONTEXT,
    SOURCE_JAVA_REQUEST,
    claim_rank,
    request_attribution,
    sdk_name,
)
from .replay import _LRUCache

#: Live contexts kept at most; past it the least recently seen is finalized.
MAX_LIVE_CONTEXTS = 4096
#: Finalize a context this many host seconds after its ``end``.
ENDED_CONTEXT_TTL = 120.0
#: Finalize a context this many host seconds after its last event when no ``end`` arrives.
IDLE_CONTEXT_TTL = 300.0
#: A context may start this much later than its flow's first request chunk
#: (host receive jitter between the two independent agent messages).
MATCH_SLACK_SECONDS = 2.0
#: A flow's first request chunk must follow its context start within this window.
MATCH_WINDOW_SECONDS = 60.0
#: WebView owner map bound (webview_id -> owning webview_load req_id).
MAX_WEBVIEW_OWNERS = 256
#: Request keys indexed per context at most (start URL + redirect hops, a hop
#: under up to two methods).
MAX_INDEXED_KEYS = 33
#: Request keys compare only this canonical-URL prefix. Decoding ``%XX`` shrinks text up to 3x,
#: so a router-cut context URL always canonicalizes to at least a third of the raw cut.
REQUEST_KEY_URL_LIMIT = REQUEST_CONTEXT_URL_LIMIT // 3

#: Request-context lifecycle points.
EVENT_START = "start"
EVENT_REDIRECT = "redirect"
EVENT_RESPONSE = "response"
EVENT_END = "end"
EVENT_WEBVIEW_LOAD = "webview_load"
EVENT_WEBVIEW_REQUEST = "webview_request"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
#: Kept unescaped when re-escaping. ``'`` is not: Chromium escapes it in https queries, Java may send it raw.
_SAFE_URL_CHARS = "!$&()*+,;=:@/?%"
_METHOD_PATTERN = re.compile(r"^[A-Za-z]{1,16}$")

#: ``(METHOD, canonical URL)``.
RequestKey = tuple


def _canonical_escapes(text: str) -> str:
    """Decode unreserved escapes, upper-case the rest, escape unsafe characters; delimiters are never decoded."""
    def fix(match: re.Match) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else "%" + match.group(1).upper()
    return quote(_PERCENT_ESCAPE.sub(fix, text), safe=_SAFE_URL_CHARS)


def _canonical_authority(parts) -> Optional[str]:
    """Lower-cased host plus a non-default port, or ``None`` when invalid."""
    host = (parts.hostname or "").rstrip(".")
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS[parts.scheme.lower()]:
        return f"{host}:{port}"
    return host


def normalize_request_key(url, method="GET") -> Optional[RequestKey]:
    """GURL-like ``(METHOD, canonical URL)`` key of an absolute http(s) URL, else ``None``.

    Lower-cases scheme and host, drops userinfo, default port and fragment, canonicalizes
    escapes and cuts the URL to :data:`REQUEST_KEY_URL_LIMIT`.
    """
    if not isinstance(url, str) or not url:
        return None
    method = _request_method(method)
    if method is None:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    authority = _canonical_authority(parts)
    if authority is None:
        return None
    path = _canonical_escapes(parts.path or "/")
    query = "?" + _canonical_escapes(parts.query) if parts.query else ""
    canonical_url = f"{scheme}://{authority}{path}{query}"
    return method, canonical_url[:REQUEST_KEY_URL_LIMIT]


def _request_method(method) -> Optional[str]:
    """Upper-cased *method* (``GET`` when empty), ``None`` unless a token of letters."""
    method = method if isinstance(method, str) and method else "GET"
    return method.upper() if _METHOD_PATTERN.fullmatch(method) else None


def absolute_request_url(target: str, authority: str, scheme: str = "https") -> str:
    """The absolute URL of an HTTP request line / pseudo-header target.

    An absolute-form *target* is returned as is; an origin-form one (``/p?q``)
    is prefixed with *scheme* and *authority*. ``""`` when neither works
    (e.g. ``*`` or a missing authority).
    """
    target = target or ""
    if target.lower().startswith(("http://", "https://")):
        return target
    if not target.startswith("/") or not authority:
        return ""
    return f"{scheme}://{authority}{target}"


@dataclass
class RequestContext:
    """Every lifecycle point of one Java-level request, folded by ``req_id``.

    ``t_start`` / ``t_end`` and ``url_times`` are HOST receive times.
    ``url_times`` maps each indexed canonical URL (start URL and redirect
    hops) to the time it was learned; ``consumed_urls`` holds those already
    matched to a flow.
    """

    req_id: str
    kind: str = EVENT_START  # start | webview_load | webview_request
    stack_kind: str = ""
    url: str = ""
    method: str = "GET"
    frames: list = field(default_factory=list)
    thread: str = ""
    redirects: list = field(default_factory=list)
    status: Optional[int] = None
    protocol: str = ""
    cached: Optional[bool] = None
    error: str = ""
    webview_id: str = ""
    main_frame: Optional[bool] = None
    t_start: Optional[float] = None
    t_end: Optional[float] = None
    last_seen: float = 0.0
    originator: Optional[dict] = None
    owner_id: str = ""  # owning webview_load req_id (webview_request only)
    url_times: dict = field(default_factory=dict)
    indexed_keys: list = field(default_factory=list)
    consumed_urls: set = field(default_factory=set)
    matched_flow_ids: list = field(default_factory=list)
    claim: Optional[dict] = None  # strongest claim this context gave a flow

    @property
    def ended(self) -> bool:
        return self.t_end is not None

    def to_record(self) -> dict:
        """The ``.tap`` REC_REQUEST_CONTEXT dict (bounded again by the writer)."""
        record = {
            "req_id": self.req_id, "stack_kind": self.stack_kind, "url": self.url,
            "method": self.method, "frames": list(self.frames), "thread": self.thread,
            "redirects": list(self.redirects), "status": self.status,
            "protocol": self.protocol, "cached": self.cached, "error": self.error,
            "webview_id": self.webview_id, "main_frame": self.main_frame,
            "t_start": self.t_start, "t_end": self.t_end,
            "matched_flow_ids": list(self.matched_flow_ids),
        }
        if self.claim:
            record.update(self.claim)
        elif self.originator:
            record["originator"] = dict(self.originator)
        if self.cached and not self.matched_flow_ids:
            record["bucket"] = "cache"
        return {key: value for key, value in record.items() if value not in (None, "")}


@dataclass(frozen=True)
class RequestMatch:
    """A context matched to a flow; ``claim`` is ``None`` for an unclassified one."""

    context: RequestContext
    claim: Optional[dict]


class RequestContextStore:
    """Bounded, TTL-expired store of :class:`RequestContext` with a key index.

    *classify* maps Java frames to ``{sdk, vendor, category}`` or ``None``. Callers pass the
    host time (*now*); evicted contexts are returned for persisting.
    """

    def __init__(self, classify: Callable[[list], Optional[dict]],
                 max_contexts: int = MAX_LIVE_CONTEXTS) -> None:
        self._classify = classify
        self._max_contexts = max_contexts
        self._contexts: OrderedDict[str, RequestContext] = OrderedDict()
        # key -> req_ids in insertion order (a dict used as an ordered set).
        self._index: dict[RequestKey, dict[str, None]] = {}
        self._webview_owners: _LRUCache = _LRUCache(maxsize=MAX_WEBVIEW_OWNERS)

    def __len__(self) -> int:
        return len(self._contexts)

    # -- ingest -----------------------------------------------------------

    def ingest(self, event, now: float) -> tuple[list[RequestKey], list[RequestContext]]:
        """Fold one RequestContextEvent in.

        Returns ``(new_keys, finished)``: the request keys this event indexed
        (so the caller can retry recently unmatched flows) and the contexts it
        pushed out of the bound.
        """
        req_id = getattr(event, "req_id", "")
        if not req_id:
            return [], []
        received = float(getattr(event, "timestamp", now) or now)
        context, finished = self._context_for(req_id, event, received)
        context.last_seen = received
        self._contexts.move_to_end(req_id)
        new_keys = self._apply_event(context, event, received)
        return new_keys, finished

    def _context_for(self, req_id: str, event, received: float):
        """The live context of *req_id*, created (and the bound enforced) if new."""
        context = self._contexts.get(req_id)
        if context is not None:
            return context, []
        finished = []
        while len(self._contexts) >= self._max_contexts:
            finished.append(self._remove(next(iter(self._contexts))))
        context = RequestContext(req_id=req_id, t_start=received)
        self._contexts[req_id] = context
        return context, finished

    def _apply_event(self, context: RequestContext, event, received: float) -> list:
        point = getattr(event, "event", "")
        self._absorb_common(context, event)
        if point in (EVENT_START, EVENT_WEBVIEW_LOAD, EVENT_WEBVIEW_REQUEST):
            return self._apply_start(context, event, point, received)
        if point == EVENT_REDIRECT:
            return self._apply_redirect(context, event, received)
        if point == EVENT_RESPONSE:
            self._apply_response(context, event)
        elif point == EVENT_END:
            self._apply_response(context, event)
            context.t_end = received
        return []

    @staticmethod
    def _absorb_common(context: RequestContext, event) -> None:
        """Fill identity fields the first time an event carries them."""
        for attr in ("stack_kind", "thread", "webview_id"):
            value = getattr(event, attr, "") or ""
            if value and not getattr(context, attr):
                setattr(context, attr, value)
        method = getattr(event, "method", "") or ""
        if method and getattr(event, "event", "") != EVENT_REDIRECT:
            context.method = method.upper()
        error = getattr(event, "error", "") or ""
        if error:
            context.error = error

    def _apply_start(self, context: RequestContext, event, point: str,
                     received: float) -> list:
        context.kind = point
        context.t_start = received
        url = getattr(event, "url", "") or ""
        if url:
            context.url = url
        frames = list(getattr(event, "frames", None) or [])
        if frames:
            context.frames = frames
            context.originator = self._classify(frames)
        main_frame = getattr(event, "main_frame", None)
        if isinstance(main_frame, bool):
            context.main_frame = main_frame
        if point == EVENT_WEBVIEW_LOAD and context.webview_id:
            self._webview_owners[context.webview_id] = context.req_id
        if point == EVENT_WEBVIEW_LOAD and not getattr(event, "method", ""):
            return []  # loadDataWithBaseURL: owner only, its base URL is never fetched
        key = normalize_request_key(url, context.method)
        if point == EVENT_WEBVIEW_REQUEST:
            self._link_owner(context)
            # The owner's load already stands for its own main-frame request.
            if key is not None and self._is_owner_navigation(context, key[1]):
                return []
        return self._index_key(context, key, received)

    def _apply_redirect(self, context: RequestContext, event, received: float) -> list:
        """A ``redirect`` point: the new URL joins the chain and the index.

        The hop is indexed under the redirect's method (else the context's)
        and under ``GET``, since 301/302/303 may turn a POST into a GET.
        """
        url = getattr(event, "url", "") or ""
        if not url or url in context.redirects:
            return []
        context.redirects.append(url)
        hop = normalize_request_key(url)
        if hop is None:
            return []
        keys = []
        for method in dict.fromkeys(((getattr(event, "method", "") or context.method), "GET")):
            method = _request_method(method)
            if method is not None:
                keys += self._index_key(context, (method, hop[1]), received)
        return keys

    @staticmethod
    def _apply_response(context: RequestContext, event) -> None:
        status = strict_int(getattr(event, "status", None))
        if status is not None:
            context.status = status
        protocol = getattr(event, "negotiated_protocol", "") or ""
        if protocol:
            context.protocol = protocol
        cached = getattr(event, "cached", None)
        if isinstance(cached, bool):
            context.cached = cached

    def _index_key(self, context: RequestContext, key: Optional[RequestKey],
                   received: float) -> list:
        """Index *key* under *context*; returns ``[key]`` when newly indexed."""
        if key is None or len(context.indexed_keys) >= MAX_INDEXED_KEYS:
            return []
        context.url_times.setdefault(key[1], received)
        if key in context.indexed_keys:
            return []
        context.indexed_keys.append(key)
        if key[1] in context.consumed_urls:
            return []  # a consumed URL never matches again, so it stays out of the index
        self._index.setdefault(key, {})[context.req_id] = None
        return [key]

    # -- WebView ownership ------------------------------------------------

    def _link_owner(self, context: RequestContext) -> None:
        """Give a ``webview_request`` its owning load and, when its own frames
        name nobody, the owner's originator. The owner is kept alive by it: a
        long-lived WebView keeps fetching, so its load must not idle out."""
        owner = self._owner_of(context)
        if owner is None:
            return
        context.owner_id = owner.req_id
        if context.originator is None:
            context.originator = owner.originator
        self._refresh_owner(owner, context.last_seen)

    def _refresh_owner(self, owner: RequestContext, seen: float) -> None:
        """Mark *owner* (and its WebView mapping) as seen at host time *seen*."""
        owner.last_seen = max(owner.last_seen, seen)
        self._contexts.move_to_end(owner.req_id)
        if owner.webview_id in self._webview_owners:
            self._webview_owners.move_to_end(owner.webview_id)

    def _owner_of(self, context: RequestContext) -> Optional[RequestContext]:
        webview_id = context.webview_id or ""
        # Plain lookup: _LRUCache.get would also refresh a stale mapping.
        owner_id = self._webview_owners[webview_id] if webview_id in self._webview_owners else ""
        owner = self._contexts.get(owner_id) if owner_id else None
        return owner if owner is not None and owner is not context else None

    # -- matching ---------------------------------------------------------

    def match(self, key: Optional[RequestKey], flow_time: float,
              flow_id: str) -> Optional[RequestMatch]:
        """Match the flow *flow_id* (request *key*, first request chunk at host
        time *flow_time*) to a context, consuming that context's URL.

        ``None`` when no unconsumed context with that exact key started within
        ``[flow_time - MATCH_WINDOW_SECONDS, flow_time + MATCH_SLACK_SECONDS]``
        (host + time alone is never a match).
        """
        if key is None:
            return None
        candidates = self._candidates(key, flow_time)
        if not candidates:
            return None
        chosen = candidates[0]  # the ordinal: oldest unconsumed candidate
        self._consume(chosen, key[1])
        if flow_id not in chosen.matched_flow_ids:
            chosen.matched_flow_ids.append(flow_id)
        claim = self._claim_for(chosen, candidates, key[1])
        if claim is not None and (chosen.claim is None
                                  or claim_rank(claim) > claim_rank(chosen.claim)):
            chosen.claim = claim
        return RequestMatch(context=chosen, claim=claim)

    def _candidates(self, key: RequestKey, flow_time: float) -> list[RequestContext]:
        """Unconsumed contexts indexed under *key* in the time window, oldest first."""
        found = []
        for req_id in self._index.get(key, ()):
            context = self._contexts.get(req_id)
            if context is None or key[1] in context.consumed_urls:
                continue
            started = context.url_times.get(key[1], context.t_start)
            if started is None:
                continue
            if started <= flow_time + MATCH_SLACK_SECONDS and \
                    flow_time - started <= MATCH_WINDOW_SECONDS:
                found.append((started, context))
        found.sort(key=lambda pair: pair[0])  # stable: insertion order on ties
        return [context for _, context in found]

    def _claim_for(self, chosen: RequestContext, candidates: list,
                   canonical_url: str) -> Optional[dict]:
        """Claim for *chosen*: ``java-request``, high when every candidate names one SDK, else
        medium; a WebView subresource inherits its owner's originator as ``context``/medium."""
        if not sdk_name(chosen.originator):
            return None
        if chosen.kind == EVENT_WEBVIEW_REQUEST and not self._is_owner_navigation(
                chosen, canonical_url):
            if not chosen.owner_id:
                return None
            return request_attribution(chosen.originator, CONFIDENCE_MEDIUM, SOURCE_CONTEXT)
        names = {sdk_name(context.originator) for context in candidates}
        confidence = CONFIDENCE_HIGH if len(names) == 1 else CONFIDENCE_MEDIUM
        return request_attribution(chosen.originator, confidence, SOURCE_JAVA_REQUEST)

    def _consume(self, context: RequestContext, canonical_url: str) -> None:
        """Mark *canonical_url* matched for *context* and unindex it there."""
        context.consumed_urls.add(canonical_url)
        for key in context.indexed_keys:
            if key[1] == canonical_url:
                self._drop_from_index(key, context.req_id)

    def _is_owner_navigation(self, context: RequestContext, canonical_url: str) -> bool:
        """A main-frame ``webview_request`` of its owner's own URL is the load itself;
        other webview_requests are context-only."""
        if context.main_frame is not True or not context.owner_id:
            return False
        owner = self._contexts.get(context.owner_id)
        return owner is not None and canonical_url in owner.url_times

    # -- expiry -----------------------------------------------------------

    def expire(self, now: float) -> list[RequestContext]:
        """Remove and return the contexts whose TTL ran out at host time *now*."""
        expired = [req_id for req_id, context in self._contexts.items()
                   if self._is_expired(context, now)]
        return [self._remove(req_id) for req_id in expired]

    @staticmethod
    def _is_expired(context: RequestContext, now: float) -> bool:
        if context.ended:
            return now - context.t_end > ENDED_CONTEXT_TTL
        return now - context.last_seen > IDLE_CONTEXT_TTL

    def drain(self) -> list[RequestContext]:
        """Remove and return every live context (capture stop / clear)."""
        drained = [self._remove(req_id) for req_id in list(self._contexts)]
        self._webview_owners.clear()
        return drained

    def _remove(self, req_id: str) -> RequestContext:
        context = self._contexts.pop(req_id)
        for key in context.indexed_keys:
            self._drop_from_index(key, req_id)
        return context

    def _drop_from_index(self, key: RequestKey, req_id: str) -> None:
        bucket = self._index.get(key)
        if bucket and req_id in bucket:
            del bucket[req_id]
            if not bucket:
                del self._index[key]
