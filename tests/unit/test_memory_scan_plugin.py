#!/usr/bin/env python3

"""Unit tests for the memory-scan output path and the plugin's agent-message
translation — both drivable without a device or a Frida session.

Memory-scan findings flow through the shared keylog pipeline as
``KeylogEvent(protocol="memscan")`` (mirroring ``--scan-keys-region``):

  * :class:`MemoryScanKeylogFormatter` + the shared
    :class:`KeylogOutputHandler` write deduped raw keylog lines to a file
    opened lazily on the first finding.
  * :meth:`MemoryScanEngine.on_script_message` turns a ``keylog``-shaped
    agent message into exactly one ``KeylogEvent(protocol="memscan")``, and
    ignores ``error`` messages, ``log`` payloads and ``unpaired`` payloads.

The engine is also reachable through the plugin system via the thin
``MemoryScanScriptPlugin`` adapter — see :class:`TestPluginAdapter`.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.output.keylog_handler import KeylogOutputHandler
from friTap.memory_scanning import MemoryScanEngine, MemoryScanKeylogFormatter
from friTap.memory_scanning import MemoryScanScriptPlugin


def _memscan_event(line: str) -> KeylogEvent:
    return KeylogEvent(protocol="memscan", key_data=line)


@pytest.fixture
def bus_and_findings():
    """A real EventBus with a collector for memscan-tagged KeylogEvents."""
    bus = EventBus()
    findings = []
    bus.subscribe(
        KeylogEvent,
        lambda e: findings.append(e) if e.protocol == "memscan" else None,
    )
    return bus, findings


# ---------------------------------------------------------------------------
# Output path: shared KeylogOutputHandler + MemoryScanKeylogFormatter
# ---------------------------------------------------------------------------

class TestMemoryScanKeylogOutput:
    def _handler(self, path):
        return KeylogOutputHandler(str(path), formatter=MemoryScanKeylogFormatter())

    def test_dedups_and_writes_unique_lines(self, tmp_path):
        path = tmp_path / "memscan.keylog"
        bus = EventBus()
        handler = self._handler(path)
        handler.setup(bus)

        line_a = "CLIENT_TRAFFIC_SECRET_0 aa bb"
        line_b = "SERVER_TRAFFIC_SECRET_0 cc dd"
        bus.emit(_memscan_event(line_a))
        bus.emit(_memscan_event(line_a))  # duplicate
        bus.emit(_memscan_event(line_b))
        handler.close()

        assert path.exists()
        written = [ln for ln in path.read_text().splitlines() if not ln.startswith("#")]
        assert written == [line_a, line_b]

    def test_ignores_non_memscan_events(self, tmp_path):
        # The formatter is tagged protocol="memscan"; a plain TLS KeylogEvent
        # must not be written to the memory-scan file.
        path = tmp_path / "memscan.keylog"
        bus = EventBus()
        handler = self._handler(path)
        handler.setup(bus)
        bus.emit(KeylogEvent(protocol="tls", key_data="CLIENT_RANDOM aa bb"))
        handler.close()
        assert not path.exists()

    def test_no_file_created_without_findings(self, tmp_path):
        path = tmp_path / "memscan.keylog"
        bus = EventBus()
        handler = self._handler(path)
        handler.setup(bus)
        handler.close()
        # File is opened lazily on the first finding; none emitted -> no file.
        assert not path.exists()


# ---------------------------------------------------------------------------
# MemoryScanEngine.on_script_message
# ---------------------------------------------------------------------------

class TestEngineMessageTranslation:
    def _engine(self, bus):
        engine = MemoryScanEngine()
        # _context is normally set in start(); set it directly here.
        engine._context = SimpleNamespace(event_bus=bus)
        return engine

    def test_keylog_message_emits_one_tagged_event(self, bus_and_findings):
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        message = {
            "type": "send",
            "payload": {
                "type": "keylog",
                "line": "CLIENT_TRAFFIC_SECRET_0 aa bb",
                "tier": "B",
                "source": "s3",
            },
        }
        engine.on_script_message(message, None)

        assert len(findings) == 1
        event = findings[0]
        assert event.protocol == "memscan"
        assert event.key_data == "CLIENT_TRAFFIC_SECRET_0 aa bb"
        assert event.payload["label"] == "CLIENT_TRAFFIC_SECRET_0"
        assert event.payload["client_random"] == "aa"
        assert event.payload["secret"] == "bb"
        assert event.payload["tier"] == "B"
        assert event.payload["source"] == "s3"

    def test_error_message_emits_nothing(self, bus_and_findings):
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        engine.on_script_message(
            {"type": "error", "description": "boom", "stack": "..."}, None
        )
        assert findings == []

    def test_log_payload_emits_nothing(self, bus_and_findings):
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        engine.on_script_message(
            {"type": "send", "payload": {"type": "log", "level": "info", "msg": "hi"}},
            None,
        )
        assert findings == []

    def test_unpaired_payload_emits_nothing(self, bus_and_findings):
        # Tier C 'unpaired' secrets have no client_random: they are logged, not
        # written as keylog lines, and must not produce a keylog event.
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        engine.on_script_message(
            {"type": "send", "payload": {"type": "unpaired",
                                         "kind": "orphan_session",
                                         "secret": "deadbeef"}},
            None,
        )
        assert findings == []

    def test_standard_line_tagged_format_nss(self, bus_and_findings):
        # A standard NSS triple keeps its label/client_random/secret columns and
        # is tagged format="nss".
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        engine.on_script_message(
            {"type": "send", "payload": {"type": "keylog",
                                         "line": "CLIENT_RANDOM aa bb",
                                         "tier": "A", "source": "s1"}},
            None,
        )
        assert len(findings) == 1
        p = findings[0].payload
        assert (p["label"], p["client_random"], p["secret"]) == ("CLIENT_RANDOM", "aa", "bb")
        assert p["format"] == "nss"

    def test_schannel_session_cache_line_parsed_by_shape(self, bus_and_findings):
        # F5: the Schannel session-cache line "RSA Session-ID:<sid> Master-Key:<m>"
        # rides in as a `keylog` message but is NOT a "LABEL cr secret" triple. A
        # positional split would mislabel the Session-ID token as the client_random
        # and the Master-Key token as the secret. It must instead be parsed by shape
        # (keyed on tier="schannel_session_cache"): session_id + master extracted,
        # client_random None, format="rsa_session_cache". The raw keylog line
        # (key_data) is emitted verbatim regardless.
        bus, findings = bus_and_findings
        engine = self._engine(bus)
        sid, master = "1122aabb", "cc" * 48
        line = f"RSA Session-ID:{sid} Master-Key:{master}"
        engine.on_script_message(
            {"type": "send", "payload": {"type": "keylog", "line": line,
                                         "tier": "schannel_session_cache",
                                         "source": "session_cache"}},
            None,
        )
        assert len(findings) == 1
        event = findings[0]
        assert event.key_data == line  # raw keylog line untouched
        p = event.payload
        assert p["label"] == "RSA"
        assert p["session_id"] == sid
        assert p["secret"] == master
        assert p["client_random"] is None
        assert p["format"] == "rsa_session_cache"
        assert p["tier"] == "schannel_session_cache"


# ---------------------------------------------------------------------------
# Plugin-system access: the thin MemoryScanScriptPlugin adapter drives the engine
# ---------------------------------------------------------------------------

class TestPluginAdapter:
    def test_adapter_wraps_an_engine(self):
        # The adapter exposes the standard ScriptPlugin identity and holds a
        # MemoryScanEngine it delegates to — this is how the plugin system keeps
        # access to memory scanning after it stopped being a built-in plugin.
        plugin = MemoryScanScriptPlugin()
        assert plugin.name == "memory-scan"
        assert plugin.version == "1.0.0"
        assert isinstance(plugin.engine, MemoryScanEngine)
        # get_script_source is empty: the engine injects its own script(s).
        assert plugin.get_script_source(SimpleNamespace()) == ""

    def test_adapter_accepts_a_prebuilt_engine(self):
        engine = MemoryScanEngine()
        plugin = MemoryScanScriptPlugin(engine=engine)
        assert plugin.engine is engine

    def test_adapter_lifecycle_delegates_to_engine(self):
        # on_instrument -> engine.start, on_detach_process -> engine.stop,
        # on_unload -> engine.close.
        calls = []
        engine = MemoryScanEngine()
        engine.start = lambda ctx: calls.append(("start", ctx))       # type: ignore[method-assign]
        engine.stop = lambda ctx: calls.append(("stop", ctx))         # type: ignore[method-assign]
        engine.close = lambda: calls.append(("close",))               # type: ignore[method-assign]
        plugin = MemoryScanScriptPlugin(engine=engine)

        ctx = SimpleNamespace()
        plugin.on_instrument(ctx)
        plugin.on_detach_process(ctx)
        plugin.on_unload(None)

        assert calls == [("start", ctx), ("stop", ctx), ("close",)]
