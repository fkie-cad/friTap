#!/usr/bin/env python3
"""Unit tests for the crash-attribution hook breadcrumb path.

The agent emits a `hook_breadcrumb` message on entry of a crash-prone hook
walk. The MessageRouter must turn it into a HookBreadcrumbEvent, and the
in-memory last-breadcrumb tracking must record the most recent marker so that
on_detach can attribute a target crash.
"""

from friTap.events import EventBus, HookBreadcrumbEvent
from friTap.message_router import MessageRouter


class TestHookBreadcrumbRouting:
    def test_breadcrumb_payload_emits_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe(HookBreadcrumbEvent, seen.append)
        router = MessageRouter(bus)

        router.route(
            {"contentType": "hook_breadcrumb",
             "hook_breadcrumb": "QuicSpdyStream::WriteHeaders reading HttpHeaderBlock"},
            b"",
        )

        assert len(seen) == 1
        assert "WriteHeaders" in seen[0].marker

    def test_empty_breadcrumb_still_routes(self):
        bus = EventBus()
        seen = []
        bus.subscribe(HookBreadcrumbEvent, seen.append)
        router = MessageRouter(bus)

        router.route({"contentType": "hook_breadcrumb"}, b"")

        assert len(seen) == 1
        assert seen[0].marker == ""


class TestLastBreadcrumbTracking:
    """Mirror SSL_Logger's tiny in-memory tracking without constructing the
    whole logger (which needs a device/session)."""

    def test_last_marker_wins(self):
        bus = EventBus()
        last = {"marker": ""}

        def on_crumb(ev: HookBreadcrumbEvent):
            if ev.marker:
                last["marker"] = ev.marker

        bus.subscribe(HookBreadcrumbEvent, on_crumb)
        router = MessageRouter(bus)

        router.route({"contentType": "hook_breadcrumb",
                      "hook_breadcrumb": "OnHeadersDecoded reading QuicHeaderList"}, b"")
        router.route({"contentType": "hook_breadcrumb",
                      "hook_breadcrumb": "WriteHeaders reading HttpHeaderBlock"}, b"")

        assert last["marker"] == "WriteHeaders reading HttpHeaderBlock"

    def test_empty_marker_does_not_clobber(self):
        bus = EventBus()
        last = {"marker": ""}

        def on_crumb(ev: HookBreadcrumbEvent):
            if ev.marker:
                last["marker"] = ev.marker

        bus.subscribe(HookBreadcrumbEvent, on_crumb)
        router = MessageRouter(bus)

        router.route({"contentType": "hook_breadcrumb",
                      "hook_breadcrumb": "OnHeadersDecoded reading QuicHeaderList"}, b"")
        router.route({"contentType": "hook_breadcrumb"}, b"")  # empty: must not clobber

        assert last["marker"] == "OnHeadersDecoded reading QuicHeaderList"
