"""Tests for pluggable parser discovery (drop-in dir + env opt-out).

Hermetic: the drop-in directory is redirected to a tmp_path, and the global
registry cache is reset around each test so no real user dir is scanned.
"""

from __future__ import annotations

import pytest

from friTap.parsers import registry as preg
from friTap.parsers.base import BaseParser


_PARSER_FILE = '''
from friTap.parsers.base import BaseParser, ParseResult


class FakeTelegramParser(BaseParser):
    is_fritap_parser = True
    PRIORITY = 70

    name = "telegram"

    def can_parse(self, data: bytes) -> bool:
        return data.startswith(b"TG")

    def feed(self, data, direction, **kwargs):
        return []

    def flush(self):
        return [ParseResult(protocol="telegram")]
'''


@pytest.fixture(autouse=True)
def _reset_registry():
    saved = preg._default_registry
    preg._default_registry = None
    yield
    preg._default_registry = saved


def _write_parser(tmp_path):
    d = tmp_path / "parsers"
    d.mkdir()
    (d / "tg_parser.py").write_text(_PARSER_FILE)
    return d


def _enable_dropin_discovery(monkeypatch, parser_dir):
    """Discovery ON: env opt-out cleared, drop-in dir redirected, entry points
    stubbed empty (so only the drop-in parser is found)."""
    monkeypatch.delenv("FRITAP_DISABLE_PARSER_DISCOVERY", raising=False)
    monkeypatch.setattr(preg, "_resolve_parser_dir", lambda: parser_dir)
    monkeypatch.setattr(preg, "_get_parser_entry_points", lambda: [])


def test_discovery_disabled_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("FRITAP_DISABLE_PARSER_DISCOVERY", "1")
    monkeypatch.setattr(preg, "_resolve_parser_dir", lambda: _write_parser(tmp_path))
    assert preg.discover_external_parsers() == []


def test_dropin_parser_discovered(monkeypatch, tmp_path):
    _enable_dropin_discovery(monkeypatch, _write_parser(tmp_path))
    found = preg.discover_external_parsers()
    assert len(found) == 1
    cls, priority = found[0]
    assert cls.__name__ == "FakeTelegramParser"
    assert priority == 70
    assert issubclass(cls, BaseParser)


def test_discovered_parser_wins_detection(monkeypatch, tmp_path):
    _enable_dropin_discovery(monkeypatch, _write_parser(tmp_path))
    reg = preg.get_default_registry()
    parser = reg.detect(b"TG\x01\x02")
    assert getattr(parser, "name", "") == "telegram"


def test_no_dropin_dir_is_noop(monkeypatch, tmp_path):
    _enable_dropin_discovery(monkeypatch, tmp_path / "nonexistent")
    assert preg.discover_external_parsers() == []
