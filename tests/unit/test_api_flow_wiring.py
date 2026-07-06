"""Wiring guard for the public FriTap builder API.

Verifies that ``FriTap.start()`` subscribes the FlowCollector to the events a
third-party consumer needs for parity with friTap's own TUI:
  * OHTTP inner payloads (``on_flow`` consumers) — the gap this milestone closed;
  * Signal key intake + structured ``MessageEvent`` delivery (``on_message``).

Pure Python — SSL_Logger is faked so nothing launches Frida/tshark.
"""

from __future__ import annotations

import importlib.util

import pytest

_signal_spec = importlib.util.find_spec("friTap.offline.signal")
# `.loader is not None` guards against a stale __pycache__ leftover turning the
# stripped signal dir into an importable namespace package (false positive).
_SIGNAL_AVAILABLE = _signal_spec is not None and _signal_spec.loader is not None

import friTap.api as api  # noqa: E402
from friTap.events import (  # noqa: E402
    EventBus, FlowEvent, KeylogEvent, MessageEvent, OhttpEvent,
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


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_on_message_wires_keylog_and_message(monkeypatch):
    session = FriTap_start_with(monkeypatch, lambda f: f.on_message(lambda m: None))

    bus = session.event_bus
    keylog_subs = _subscriber_callables(bus, KeylogEvent)
    assert any(getattr(cb, "__name__", "") == "on_keylog" for cb in keylog_subs), (
        "on_message must feed Signal keys to the collector's on_keylog"
    )
    assert _subscriber_callables(bus, MessageEvent), "MessageEvent subscription missing"


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


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_on_message_enables_signal_messages(monkeypatch):
    captured = {}
    orig_init = FlowCollector.__init__

    def spy_init(self, *a, **kw):
        captured.update(kw)
        orig_init(self, *a, **kw)

    monkeypatch.setattr(FlowCollector, "__init__", spy_init)
    FriTap_start_with(monkeypatch, lambda f: f.on_message(lambda m: None))
    assert captured.get("signal_messages") is True


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
