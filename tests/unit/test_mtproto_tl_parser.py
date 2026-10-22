"""friTap.offline.mtproto.tl_parser + its friTap.parsers.telegram_tl shim."""

import subprocess
import sys

import pytest

from friTap.flow import display
from friTap.offline.mtproto import tl_parser
from friTap.parsers import registry as registry_mod
from friTap.parsers import telegram_tl
from friTap.parsers.http3 import Http3Parser
from friTap.parsers.registry import ParserRegistry


def test_shim_reexports_public_and_private_names():
    assert telegram_tl.MtprotoParser is tl_parser.MtprotoParser
    assert telegram_tl.TelegramE2EParser is tl_parser.TelegramE2EParser
    assert telegram_tl._rpc_result_name is tl_parser._rpc_result_name
    assert "MtprotoParser" in dir(telegram_tl)


def test_shim_import_does_not_load_offline_mtproto():
    code = (
        "import sys, friTap.parsers.telegram_tl;"
        "print('friTap.offline.mtproto' in sys.modules)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_http3_declares_its_exclusive_transport():
    assert Http3Parser.EXCLUSIVE_TRANSPORTS == Http3Parser.TRANSPORTS == ("quic",)


def test_classify_method_is_public_with_private_alias():
    assert display._classify_method is display.classify_method
    assert display.classify_method("messages.sendMessage") == 4


def test_mtproto_parser_feed_names_the_constructor():
    pong = bytes.fromhex("c5737734") + b"\x00" * 16
    [result] = tl_parser.MtprotoParser().feed(pong, "read")
    assert result.headers["constructor"] == "pong#347773c5"
    assert result.is_request is False


def test_apply_declared_transport_rules():
    reg = ParserRegistry()
    registry_mod._apply_declared_transport_rules(reg, [Http3Parser])
    assert reg._rule("quic").allowed == frozenset({Http3Parser})


def test_building_registry_does_not_import_offline():
    code = (
        "import sys\n"
        "from friTap.parsers.registry import get_default_registry\n"
        "reg = get_default_registry()\n"
        "for t in (None, 'tls', 'quic'):\n"
        "    reg.detect(b'GET / HTTP/1.1\\r\\n\\r\\n', transport=t)\n"
        "print('friTap.offline' in sys.modules)\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_default_registry_pins_both_tl_transports():
    reg = registry_mod.get_default_registry()
    assert reg.pinned_parser_for("mtproto") is tl_parser.MtprotoParser
    assert reg.pinned_parser_for("telegram_e2e") is tl_parser.TelegramE2EParser


def test_lazy_pin_resolves_and_caches_on_first_lookup():
    reg = ParserRegistry()
    reg.pin_transport_lazy("mtproto", "friTap.offline.mtproto.tl_parser:MtprotoParser")
    assert reg.pinned_parser_for("mtproto") is tl_parser.MtprotoParser
    assert reg._lazy_pins == {}


def test_lazy_pin_import_failure_raises_once_then_sniffs():
    reg = ParserRegistry()
    reg.register(Http3Parser, priority=80)
    reg.pin_transport_lazy("mtproto", "friTap._no_such_mod:Parser")
    with pytest.raises(ImportError):
        reg.pinned_parser_for("mtproto")
    assert reg.pinned_parser_for("mtproto") is None


def test_explicit_pin_replaces_lazy_pin():
    reg = ParserRegistry()
    reg.pin_transport_lazy("mtproto", "friTap._no_such_mod:Parser")
    reg.pin_transport("mtproto", tl_parser.TelegramE2EParser)
    assert reg.pinned_parser_for("mtproto") is tl_parser.TelegramE2EParser


def test_missing_http3_logs_quic_not_restricted(monkeypatch):
    import importlib

    real_import = importlib.import_module
    warnings = []

    def fake_import(name, package=None):
        if name == ".http3":
            raise ImportError("no h3")
        return real_import(name, package)

    monkeypatch.setenv("FRITAP_DISABLE_PARSER_DISCOVERY", "1")
    monkeypatch.setattr(registry_mod, "_default_registry", None)
    monkeypatch.setattr(registry_mod.importlib, "import_module", fake_import)
    monkeypatch.setattr(registry_mod.logger, "warning",
                        lambda msg, *args: warnings.append(msg % args))
    reg = registry_mod.get_default_registry()
    assert warnings[-1] == "HTTP/3 parser unavailable; QUIC not restricted: no h3"
    assert reg._rule("quic").allowed is None
