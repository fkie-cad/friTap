"""Wiring guard for the public FriTap builder API.

Verifies that ``FriTap.start()`` subscribes the FlowCollector to the events a
third-party consumer needs for parity with friTap's own TUI:
  * OHTTP inner payloads (``on_flow`` consumers) — the gap this milestone closed;
  * keylog-only sessions do not build a FlowCollector.

Pure Python — SSL_Logger is faked so nothing launches Frida/tshark.
"""

from __future__ import annotations

import friTap.api as api  # noqa: E402
from friTap.events import (  # noqa: E402
    EventBus,
    FlowEvent,
    OhttpEvent,
)
from friTap.flow.collector import FlowCollector  # noqa: E402


class _FakeSSLLogger:
    """Minimal stand-in for SSL_Logger used by FriTap.start()."""
    def __init__(self, config=None):
        self.config = config
        self._event_bus = EventBus()
        self._plugin_loader = None
        self.running = False

    def install_signal_handler(self):
        pass

    def start_fritap_session(self):
        pass


def _subscriber_callables(bus, event_type):
    return [cb for _prio, cb in bus._subscribers.get(event_type, [])]


def test_on_flow_wires_ohttp(monkeypatch):
    monkeypatch.setattr(api, "SSL_Logger", _FakeSSLLogger, raising=False)
    import friTap.ssl_logger as ssl_logger_mod
    monkeypatch.setattr(ssl_logger_mod, "SSL_Logger", _FakeSSLLogger)

    session = FriTap_start_with(monkeypatch, lambda f: f.on_flow(lambda e: None))

    bus = session.event_bus
    ohttp_subs = _subscriber_callables(bus, OhttpEvent)
    assert any(getattr(cb, "__name__", "") == "on_ohttp" for cb in ohttp_subs), (
        "on_flow consumers must receive Signal-over-OHTTP inner payloads"
    )
    # FlowEvent is still delivered to the user callback.
    assert _subscriber_callables(bus, FlowEvent), "FlowEvent subscription missing"


def test_no_collector_without_flow_or_message(monkeypatch):
    """A keylog-only session does not build a FlowCollector."""
    created = []
    orig_init = FlowCollector.__init__

    def spy_init(self, *a, **kw):
        created.append(kw)
        orig_init(self, *a, **kw)

    monkeypatch.setattr(FlowCollector, "__init__", spy_init)
    FriTap_start_with(monkeypatch, lambda f: f.on_keylog(lambda e: None))
    assert created == [], "no FlowCollector should be built for a keylog-only session"


# --------------------------------------------------------------------------- #
def FriTap_start_with(monkeypatch, configure):
    """Build a FriTap with the fake SSL_Logger and apply *configure* before start."""
    monkeypatch.setattr(api, "SSL_Logger", _FakeSSLLogger, raising=False)
    import friTap.ssl_logger as ssl_logger_mod
    monkeypatch.setattr(ssl_logger_mod, "SSL_Logger", _FakeSSLLogger)
    from friTap import FriTap
    builder = FriTap("com.example.app")
    configure(builder)
    return builder.start()
