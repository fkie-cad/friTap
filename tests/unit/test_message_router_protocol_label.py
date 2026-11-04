"""MessageRouter keeps the agent's protocol tag; a missing tag gets the content type's default.

``--protocol auto|all`` selects which hooks install; it is not a protocol. The
agent (ABI >= 3) stamps every message with the emitting hook's record protocol
under a meta selection, so the router no longer folds ``auto``/``all`` itself
(an older bundle is flagged by the AGENT_ABI_VERSION check instead).
"""

from __future__ import annotations

import pytest

from friTap.constants import AGENT_ABI_VERSION
from friTap.events import DatalogEvent, KeylogEvent, LibraryDetectedEvent, SessionEvent
from friTap.message_router import MessageRouter, payload_protocol


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(payload: dict, data: bytes = b"") -> object:
    bus = _Bus()
    MessageRouter(bus, active_protocol=["auto"]).route(payload, data)
    assert len(bus.events) == 1
    return bus.events[0]


@pytest.mark.parametrize("value,default,expected", [
    (None, "tls", "tls"), ("", "ohttp", "ohttp"), ("ssh", "tls", "ssh"),
    ("quic", "tls", "quic"), ("rc4", "tls", "rc4"),
])
def test_payload_protocol(value, default, expected):
    payload = {} if value is None else {"protocol": value}
    assert payload_protocol(payload, default) == expected


def test_meta_tags_are_an_agent_abi_concern():
    # The meta-selection fold moved into the agent; the ABI bump is what makes
    # a stale bundle that still stamps "auto" visible.
    assert AGENT_ABI_VERSION >= 3


def test_untagged_records_get_their_content_type_default():
    library = _route({"contentType": "library_detected", "library": "libssl.3.dylib"})
    data = _route({"contentType": "datalog", "function": "SSL_write"}, b"GET /")
    keylog = _route({"contentType": "keylog", "keylog": "CLIENT_RANDOM aa bb"})
    lifecycle = _route({"contentType": "connection_lifecycle", "event": "open"})
    assert isinstance(library, LibraryDetectedEvent) and library.protocol == "tls"
    assert isinstance(data, DatalogEvent) and data.protocol == "tls"
    assert isinstance(keylog, KeylogEvent) and keylog.protocol == "tls"
    assert isinstance(lifecycle, SessionEvent) and lifecycle.protocol == "tls"


@pytest.mark.parametrize("content_type,extra,data", [
    ("datalog", {"function": "ssh_packet_send2"}, b"x"),
    ("library_detected", {"library": "libssh.so"}, b""),
])
def test_hook_record_protocol_is_kept(content_type, extra, data):
    event = _route({"contentType": content_type, "protocol": "ssh", **extra}, data)
    assert event.protocol == "ssh"
