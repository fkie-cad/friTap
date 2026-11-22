"""Load the Java request-context sidecar (``--attribute-sdk``) for offline replay.

A live ``-f -k --attribute-sdk`` capture writes the contexts with
:class:`~friTap.output.request_context_sidecar.RequestContextSidecar` and lists
the file under the manifest's ``request_contexts`` key. The file is untrusted,
so each row is re-validated like an agent message; bad rows are skipped, never raised.
"""

from __future__ import annotations

import logging
import math
from typing import Iterable, Optional

from friTap.events import RequestContextEvent

logger = logging.getLogger(__name__)


def load_request_contexts(path: Optional[str]) -> list[RequestContextEvent]:
    """The sidecar's events at *path*, oldest first; ``[]`` when unusable.

    Each event's ``timestamp`` is the agent's ``t_ms`` in seconds when present
    (the device clock tcpdump stamps the packets with), else the stored host time.
    """
    from friTap.output.request_context_sidecar import read_request_context_rows

    if not path:
        return []
    events, skipped = [], 0
    try:
        for raw in read_request_context_rows(path):
            event = _validated(raw)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    except OSError as error:
        logger.warning("Could not read request-context sidecar %s: %s", path, error)
        return []
    if skipped:
        logger.warning("Skipped %d malformed request-context row(s) in %s", skipped, path)
    events.sort(key=lambda event: event.timestamp)
    return events


def replay_request_contexts(events: Iterable[RequestContextEvent], sink) -> int:
    """Hand each event to *sink* (e.g. ``FlowCollector.on_request_context``); count delivered."""
    delivered = 0
    for event in events:
        try:
            sink(event)
            delivered += 1
        except Exception:  # noqa: BLE001 - one bad context must not stop the conversion
            logger.debug("request-context replay failed", exc_info=True)
    return delivered


def _validated(row: dict) -> Optional[RequestContextEvent]:
    """The event *row* describes, coerced like the router does, or ``None`` when invalid."""
    from friTap.message_router import REQUEST_CONTEXT_EVENTS, request_context_fields

    event, req_id = row.get("event"), row.get("req_id")
    if not isinstance(event, str) or event not in REQUEST_CONTEXT_EVENTS:
        return None
    if not isinstance(req_id, str) or not req_id:
        return None
    fields = request_context_fields(row)
    timestamp = _replay_timestamp(fields["t_ms"], row.get("timestamp"))
    if timestamp is None:
        return None
    protocol = row.get("protocol")
    return RequestContextEvent(
        timestamp=timestamp, event=event,
        protocol=protocol[:32] if isinstance(protocol, str) and protocol else "tls",
        **fields)


def _replay_timestamp(t_ms, stored) -> Optional[float]:
    """``t_ms`` in seconds when usable, else the stored finite timestamp, else ``None``."""
    if t_ms is not None and t_ms > 0:
        return t_ms / 1000.0
    if isinstance(stored, (int, float)) and not isinstance(stored, bool) and math.isfinite(stored):
        return float(stored)
    return None
