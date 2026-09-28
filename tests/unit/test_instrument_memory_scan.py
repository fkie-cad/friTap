#!/usr/bin/env python3

"""Regression test for finding F4 — instrument() + own_message_handler + -ms.

`memory_scan_only` makes instrument() skip the main TLS-hooking agent (the
mem-scan engine owns the session). But `own_message_handler` consumes the MAIN
agent's messages, so a caller that supplies one under `-ms` still needs the main
agent — otherwise instrument() returns None and the handler is wired to nothing.

The fix treats a supplied handler as a capture surface at the instrument()
boundary (`memory_scan_only = self._is_memory_scan_only() and
own_message_handler is None`). These tests pin both directions of that predicate
without a device or a real Frida session, using the `SSL_Logger.__new__` +
mock-backend harness style of test_gated_instrumentation.py.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from friTap.config import FriTapConfig
from friTap.legacy.ssl_logger_core import SSL_Logger


def _logger_with(config: FriTapConfig) -> SSL_Logger:
    """A bare SSL_Logger wired with only what instrument() touches up to return."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.instrument_memory_scan")
    # debug / debug_output / target_app / payload_modification are read-only
    # properties backed by _config, so the real FriTapConfig supplies them.
    obj._config = config
    obj.offsets_data = None
    obj.pattern_data = None
    obj.device = None
    # Backend: create_script returns a sentinel we assert is handed back.
    obj._backend = MagicMock()
    obj._backend.name = "frida"
    obj._backend.version_at_least.return_value = False
    obj._sentinel_script = object()
    obj._backend.create_script.return_value = obj._sentinel_script
    # Stub the collaborators instrument() calls but whose internals are not
    # under test here.
    obj.get_agent_script = MagicMock(return_value="/* agent js */")
    obj._warn_on_stale_agent_bundle = MagicMock()
    obj._build_script_context = MagicMock()
    obj._provide_custom_hooking_handler = MagicMock(return_value="wrapped-handler")
    obj._event_bus = MagicMock()
    return obj


def _ms_config() -> FriTapConfig:
    # -ms passed alone -> memory_scan_only() is True.
    return FriTapConfig.from_legacy_params(app="a", memory_scan=True)


def test_own_message_handler_under_ms_returns_live_script():
    # F4: a caller supplying own_message_handler under -ms must get the main
    # agent (and a LIVE script back), not None, with the handler wired.
    obj = _logger_with(_ms_config())
    handler = MagicMock()

    result = obj.instrument(MagicMock(name="process"), handler)

    assert result is obj._sentinel_script
    assert obj.script is obj._sentinel_script
    obj._backend.create_script.assert_called_once()
    # The supplied handler was wrapped and wired onto the created script.
    obj._provide_custom_hooking_handler.assert_called_once_with(handler)
    obj._backend.on_message.assert_called_once_with(
        obj._sentinel_script, "wrapped-handler"
    )


def test_ms_only_without_handler_still_skips_main_agent():
    # The mem-scan-only contract is preserved: with no handler, -ms alone skips
    # the main agent (no script created) and returns None.
    obj = _logger_with(_ms_config())

    result = obj.instrument(MagicMock(name="process"), None)

    assert result is None
    assert obj.script is None
    obj._backend.create_script.assert_not_called()
