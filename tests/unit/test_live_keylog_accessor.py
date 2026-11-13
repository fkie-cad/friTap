"""SSL_Logger resolves the hooked-key keylog handler lazily, not via a snapshot."""
from __future__ import annotations

import types

from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.memory_scanning.formatter import MemoryScanKeylogFormatter
from friTap.output import KeylogOutputHandler
from friTap.protocols.tls_handler import TlsKeylogFormatter


def _bare_logger():
    logger = SSL_Logger.__new__(SSL_Logger)
    logger.keylog_file = None
    logger._config = types.SimpleNamespace(output=types.SimpleNamespace(keylog="cli.log"))
    logger._tls_keylog_handler = None
    return logger


def test_without_handler_falls_back_to_legacy_fields():
    logger = _bare_logger()
    assert logger._live_keylog_file() is None
    assert logger._live_keylog_path() == "cli.log"


def test_memory_scan_handler_is_never_remembered():
    logger = _bare_logger()
    logger._remember_tls_keylog_handler(
        KeylogOutputHandler("ms.log", formatter=MemoryScanKeylogFormatter()))
    assert logger._tls_keylog_handler is None


def test_tls_handler_is_not_replaced_by_a_later_handler():
    logger = _bare_logger()
    tls = KeylogOutputHandler("keys.log", formatter=TlsKeylogFormatter())
    logger._remember_tls_keylog_handler(tls)
    logger._remember_tls_keylog_handler(
        KeylogOutputHandler("ms.log", formatter=MemoryScanKeylogFormatter()))
    assert logger._live_keylog_path() == "keys.log"


def test_live_keylog_file_follows_lazy_open(tmp_path):
    from friTap.events import EventBus, KeylogEvent
    logger = _bare_logger()
    handler = KeylogOutputHandler(str(tmp_path / "k.log"), formatter=TlsKeylogFormatter())
    bus = EventBus()
    handler.setup(bus)
    logger._remember_tls_keylog_handler(handler)
    assert logger._live_keylog_file() is None
    bus.emit(KeylogEvent(key_data="CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48))
    try:
        assert logger._live_keylog_file() is not None
    finally:
        handler.close()
