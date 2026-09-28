"""The attach-mode hint shared by the mtproto/telegram handlers and the TUI."""

from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest

from friTap.protocols.mtproto_hints import (
    ATTACH_MEMORY_SCAN_RECOVERY,
    ATTACH_WITHOUT_MEMORY_SCAN,
    attach_mode_hint,
)


def test_hint_with_memory_scan():
    assert attach_mode_hint(True) == f"attach mode + memory scan: {ATTACH_MEMORY_SCAN_RECOVERY}"
    assert "(Tier E)" in ATTACH_MEMORY_SCAN_RECOVERY


def test_hint_without_memory_scan():
    assert attach_mode_hint(False) == f"attach mode: {ATTACH_WITHOUT_MEMORY_SCAN}"
    assert "-s (spawn)" in ATTACH_WITHOUT_MEMORY_SCAN
    assert "(-ms)" in ATTACH_WITHOUT_MEMORY_SCAN


def _handler(name):
    if name == "mtproto":
        from friTap.protocols.mtproto_handler import MTProtoHandler
        return MTProtoHandler()
    from friTap.protocols.telegram_handler import TelegramHandler
    return TelegramHandler()


@pytest.mark.parametrize("name", ["mtproto", "telegram"])
@pytest.mark.parametrize("memory_scan", [True, False])
def test_handlers_emit_tagged_hint_in_attach_mode(name, memory_scan):
    logger = MagicMock()
    parsed = types.SimpleNamespace(spawn=False, memory_scan=memory_scan,
                                   keylog="k.log", pcap=None, live=False)
    try:
        _handler(name).validate_cli_intent(parsed, MagicMock(), logger)
    except SystemExit:
        pass
    infos = [c.args[0] for c in logger.info.call_args_list]
    assert f"[{name}] {attach_mode_hint(memory_scan)}" in infos


@pytest.mark.parametrize("name", ["mtproto", "telegram"])
def test_handlers_skip_hint_in_spawn_mode(name):
    logger = MagicMock()
    parsed = types.SimpleNamespace(spawn=True, memory_scan=False,
                                   keylog="k.log", pcap=None, live=False)
    try:
        _handler(name).validate_cli_intent(parsed, MagicMock(), logger)
    except SystemExit:
        pass
    infos = [c.args[0] for c in logger.info.call_args_list]
    assert not any("attach mode" in m for m in infos)
