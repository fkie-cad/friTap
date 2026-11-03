"""The Telegram formatter validates the agent-supplied Secret-Chat ``chat_id``.

The agent runs inside a possibly hostile target, so ``chat_id`` is untrusted:
only an ``int`` or a decimal ``str`` (optional leading ``-``) within the signed
64-bit range is accepted. Anything else is replaced by the unknown chat id 0,
logged once, and never raises. Hermetic: no device, no crypto backend.
"""

from __future__ import annotations

import logging

import pytest

from friTap.events import KeylogEvent
from friTap.protocols import mtproto_keylog_spec as spec
from friTap.protocols import telegram_handler
from friTap.protocols.telegram_handler import TelegramKeylogFormatter

_FP = "0011223344556677"
_SK = "cd" * 256  # 512 hex chars
_INT64_MAX = 2 ** 63 - 1
_INT64_MIN = -(2 ** 63)


@pytest.fixture(autouse=True)
def _reset_warn_once(monkeypatch):
    monkeypatch.setattr(telegram_handler, "_invalid_chat_id_logged", False)


def _format_with_chat_id(chat_id):
    event = KeylogEvent(
        protocol="telegram",
        payload={"key_fingerprint": _FP, "shared_key": _SK, "chat_id": chat_id},
    )
    return TelegramKeylogFormatter().format(event)


def _e2e_line(chat_id: int) -> list[str]:
    return [f"{spec.E2E_LABEL} {_FP} {_SK} {chat_id}"]


@pytest.mark.parametrize("chat_id, expected", [
    (42, 42),
    ("42", 42),
    ("-1001234567890", -1001234567890),
    (-7, -7),
    (_INT64_MAX, _INT64_MAX),
    (str(_INT64_MIN), _INT64_MIN),
])
def test_valid_chat_id_is_rendered(chat_id, expected):
    assert _format_with_chat_id(chat_id) == _e2e_line(expected)


@pytest.mark.parametrize("chat_id", [None, 0, "", "0"])
def test_missing_chat_id_renders_zero_without_warning(chat_id, caplog):
    with caplog.at_level(logging.WARNING, logger=telegram_handler.__name__):
        assert _format_with_chat_id(chat_id) == _e2e_line(0)
    assert not caplog.records


@pytest.mark.parametrize("chat_id", [
    "abc",
    "12x",
    " 42",
    "42\n",
    "+42",
    "--1",
    "٤٢",            # Arabic-Indic digits: str.isdigit() but not ASCII
    "9" * 5000,               # would hit int()'s max-digits limit
    str(_INT64_MAX + 1),
    str(_INT64_MIN - 1),
    _INT64_MAX + 1,
    _INT64_MIN - 1,
    True,
    1.5,
    float("inf"),
    float("nan"),
    [1, 2],
    {"id": 1},
])
def test_invalid_chat_id_does_not_raise_and_renders_zero(chat_id):
    assert _format_with_chat_id(chat_id) == _e2e_line(0)


def test_invalid_chat_id_is_logged_once(caplog):
    with caplog.at_level(logging.WARNING, logger=telegram_handler.__name__):
        _format_with_chat_id("not-a-number")
        _format_with_chat_id(float("inf"))
        _format_with_chat_id(2 ** 70)
    warnings = [r for r in caplog.records if "chat_id" in r.getMessage()]
    assert len(warnings) == 1
    assert "not-a-number" not in warnings[0].getMessage()  # agent text not logged
