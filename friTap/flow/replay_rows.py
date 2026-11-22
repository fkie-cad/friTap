"""Display rows for replaying a decoded ``.tap`` capture.

Non-TUI seam: turns each tap summary of a replay controller into a synthetic
:class:`~friTap.flow.models.Flow` plus its list-row ``FlowSummary``, re-parsing
flows that benefit from the current parsers.
"""

from __future__ import annotations

from collections.abc import Iterator

from friTap.constants import PROTOCOL_MTPROTO, PROTOCOL_TELEGRAM_E2E
from friTap.flow.display import is_message_transport
from friTap.flow.models import Flow, FlowState, FlowSummary

# Protocols yielded by the pinned TL parser (see ParserRegistry.pin_transport).
TL_PINNED_PROTOCOLS = frozenset({PROTOCOL_MTPROTO, PROTOCOL_TELEGRAM_E2E})


def is_tl_pinned_flow(flow) -> bool:
    """True for a flow riding a decrypted-TL (pinned-parser) transport."""
    return is_message_transport(flow)


def is_received_message_summary(flow, summary) -> bool:
    """True for a one-packet message-stream row that was *received* (summary has a response side only).

    The synthetic flow then carries a response stub, not a request stub, or Status
    would show every received MTProto / Secret-Chat packet as ``sent``. Legacy paired taps keep request-first.
    """
    return (is_message_transport(flow)
            and bool(getattr(summary, "has_response", False))
            and not getattr(summary, "has_request", False))


def needs_tl_reparse(flow) -> bool:
    """A TL-transport flow whose stored parse came from blind byte sniffing."""
    if not is_tl_pinned_flow(flow):
        return False
    parsed = [r for r in (flow.request, flow.response) if r is not None]
    if not parsed:
        return True
    return any(r.protocol not in TL_PINNED_PROTOCOLS for r in parsed)


def needs_reparse(flow, summary) -> bool:
    """True if a flow should be re-parsed with current parsers: unknown protocol, HTTP/2 ghost or
    unflagged control frames, WebSocket TEXT (permessage-deflate), or MTProto / Telegram-E2E flows
    not parsed by their pinned TL parser (old code sniffed them as e.g. a WebSocket PING).
    """
    if needs_tl_reparse(flow):
        return True
    proto = flow.display_protocol
    if proto == "unknown":
        return True
    # HTTP/2 ghost flow: protocol detected but no request (SETTINGS-only).
    if "HTTP/2" in proto and flow.request is None:
        return True
    # HTTP/2 control frames stored without is_control_frame set.
    if "HTTP/2" in proto and flow.request is not None:
        if flow.request.method in ("SETTINGS", "PING", "GOAWAY", "WINDOW_UPDATE"):
            if not flow.request.is_control_frame:
                return True
    # WebSocket TEXT: re-parse for decompression and content detection.
    if proto == "WebSocket" and summary.method == "TEXT":
        return True
    return False


def _synthetic_flow(summary) -> Flow:
    """A layerless COMPLETE flow carrying the summary's addressing."""
    return Flow(
        flow_id=summary.flow_id,
        connection_id=summary.connection_id,
        src_addr=summary.src_addr,
        src_port=summary.src_port,
        dst_addr=summary.dst_addr,
        dst_port=summary.dst_port,
        ssl_session_id=summary.ssl_session_id,
        state=FlowState.COMPLETE,
        started=summary.started,
        ended=summary.ended,
        transport=getattr(summary, "transport", "tls") or "tls",
    )


def _attach_parse_stubs(flow: Flow, summary, received_message: bool) -> None:
    """Attach request/response ParseResult stubs rebuilt from the summary."""
    from friTap.parsers.base import ParseResult
    has_parsed_request = (
        summary.method or summary.url or summary.host
        or summary.protocol not in ("unknown", "")
    )
    if has_parsed_request and not received_message:
        flow.request = ParseResult(
            protocol=summary.protocol,
            method=summary.method,
            url=summary.url,
            host=summary.host,
            is_request=True,
            is_complete=True,
            is_control_frame=summary.is_control_frame,
        )
    if summary.status_code > 0:
        flow.response = ParseResult(
            status_code=summary.status_code,
            status_text=summary.status_text,
            body_size=summary.body_size,
            is_request=False,
            is_complete=True,
        )
    elif received_message:
        flow.response = ParseResult(
            protocol=summary.protocol,
            method=summary.method,
            url=summary.url,
            host=summary.host,
            is_request=False,
            is_complete=True,
        )


def _reparse_if_needed(ctrl, flow: Flow, summary) -> None:
    """Re-parse flows that can benefit from updated parsers and persist it."""
    from friTap.flow.reparse import reparse_flow
    if summary.total_size > 0 and needs_reparse(flow, summary):
        full_flow = ctrl.get_flow(summary.flow_id)
        if full_flow is not None and reparse_flow(full_flow):
            flow.request = full_flow.request
            flow.response = full_flow.response
            ctrl.store_reparse(
                summary.flow_id, full_flow.request, full_flow.response,
                clear_trailing=is_tl_pinned_flow(full_flow),
            )


def _carry_display_scalars(flow: Flow, summary, received_message: bool) -> None:
    """Copy size and layered display scalars onto the layerless flow."""
    flow._total_bytes = summary.total_size
    # The layerless flow would make FlowSummary.from_tap_summary return "" (list shows ???/-).
    flow.outer_app_protocol = summary.outer_app_protocol
    flow.inner_e2e_protocol = summary.inner_e2e_protocol
    flow.inner_summary = summary.inner_summary
    # Same for the derived TL Method scalar.
    flow.flow_method = getattr(summary, "flow_method", "") or (
        summary.method if received_message else "")


def iter_replay_rows(ctrl) -> Iterator[tuple[Flow, FlowSummary]]:
    """Yield ``(flow, row_summary)`` for every summary of *ctrl* (a ReplayController), in order.

    Reparsed results are persisted via ``store_reparse``. The row summary is built from
    the decoded tap summary so display filters match live capture despite missing layers.
    """
    for summary in ctrl.get_summaries():
        flow = _synthetic_flow(summary)
        received_message = is_received_message_summary(flow, summary)
        _attach_parse_stubs(flow, summary, received_message)
        _reparse_if_needed(ctrl, flow, summary)
        _carry_display_scalars(flow, summary, received_message)
        yield flow, FlowSummary.from_tap_summary(summary, flow)
