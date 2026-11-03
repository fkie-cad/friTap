"""Hardening of ScriptErrorHandler against hostile agent messages.

The agent runs inside a possibly hostile target process: debug blob dumps must
stay inside a dedicated, capped directory, and agent text must not be able to
drive the analyst's terminal (ANSI / OSC escape injection).
"""

import logging
import os
from pathlib import Path

import pytest

from friTap import error_handler
from friTap.error_handler import FridaBlobStore, ScriptErrorHandler, frida_blob_dir
from friTap.text_safety import safe_terminal_text, visible_controls

ANSI_ATTACK = "\x1b]0;pwned\x07\x1b[2J\x1b[31mred\x9b31m end"


def _send(message_text="hello agent", **extra):
    payload = {"message": message_text, "level": "info"}
    payload.update(extra)
    return {"type": "send", "payload": payload}


def _format(message, data, logger):
    ScriptErrorHandler.format_fritap_message(
        message, data, {"info": logging.INFO}, lambda ts: None,
        lambda f: f, logger)


@pytest.fixture
def blob_dir(tmp_path, monkeypatch):
    target = tmp_path / "logs" / "frida_blobs"
    monkeypatch.setattr(error_handler, "frida_blob_dir", lambda: target)
    monkeypatch.setattr(FridaBlobStore, "_cap_warned", False)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return target


@pytest.fixture
def logger():
    log = logging.getLogger("test.error_handler_hardening")
    log.setLevel(logging.DEBUG)
    return log


class TestBlobDumps:
    def test_default_dir_is_dedicated_log_subdir(self):
        path = frida_blob_dir()
        assert path.name == "frida_blobs"
        assert path.parent.resolve() != Path.cwd().resolve()
        assert path.resolve() != Path.cwd().resolve()

    def test_blob_written_to_dedicated_dir_not_cwd(self, blob_dir, logger):
        _format(_send(), b"\x00\x01payload", logger)
        files = list(blob_dir.iterdir())
        assert len(files) == 1
        assert files[0].read_bytes() == b"\x00\x01payload"
        assert files[0].name.startswith("frida_blob_")
        assert list(os.listdir(os.getcwd())) == []

    def test_filename_never_taken_from_agent_data(self, blob_dir, logger):
        _format(_send(file="../../evil.bin", name="../evil"), b"x" * 8, logger)
        (only,) = list(blob_dir.iterdir())
        assert "evil" not in only.name
        assert only.parent == blob_dir

    def test_count_cap(self, blob_dir, logger, monkeypatch):
        monkeypatch.setattr(error_handler, "MAX_FRIDA_BLOB_FILES", 3)
        for _ in range(6):
            _format(_send(), b"abc", logger)
        assert len(list(blob_dir.iterdir())) == 3

    def test_total_size_cap(self, blob_dir, logger, monkeypatch, caplog):
        monkeypatch.setattr(error_handler, "MAX_FRIDA_BLOB_TOTAL_BYTES", 100)
        with caplog.at_level(logging.WARNING):
            for _ in range(4):
                _format(_send(), b"y" * 60, logger)
        assert len(list(blob_dir.iterdir())) == 1
        # The cap is reported once, not per message.
        assert caplog.text.count("Not saving further agent debug blobs") == 1

    def test_per_blob_cap_truncates(self, blob_dir, logger, monkeypatch):
        monkeypatch.setattr(error_handler, "MAX_FRIDA_BLOB_BYTES", 10)
        _format(_send(), b"z" * 1000, logger)
        (only,) = list(blob_dir.iterdir())
        assert only.stat().st_size == 10

    def test_blob_file_is_private(self, blob_dir, logger):
        _format(_send(), b"secret", logger)
        (only,) = list(blob_dir.iterdir())
        if os.name == "posix":
            assert only.stat().st_mode & 0o077 == 0


class TestAnsiInjection:
    def test_send_message_text_is_escaped(self, blob_dir, logger, caplog):
        with caplog.at_level(logging.DEBUG):
            _format(_send(ANSI_ATTACK, file="a\x1b[1mb.js", func="f\x1bx"), None, logger)
        text = caplog.text
        assert "\x1b" not in text and "\x07" not in text and "\x9b" not in text
        assert "\\x1b]0;pwned" in text

    def test_script_error_message_is_escaped(self, logger, caplog):
        with caplog.at_level(logging.ERROR):
            _format({"type": "error", "description": ANSI_ATTACK,
                     "stack": "at x\x1b[2K"}, None, logger)
        assert "\x1b" not in caplog.text
        assert "\\x1b[2K" in caplog.text

    def test_newline_and_tab_are_kept(self):
        assert safe_terminal_text("a\n\tb\r") == "a\n\tb\\r"

    def test_handle_debug_without_rich_escapes(self, logger, caplog, monkeypatch):
        monkeypatch.setattr(error_handler, "Console", None)
        monkeypatch.setattr(error_handler.os, "kill", lambda *a: None)
        bus = type("Bus", (), {"emit": lambda self, e: None})()
        with caplog.at_level(logging.ERROR):
            ScriptErrorHandler.handle(
                {"description": ANSI_ATTACK, "stack": "s\x1b[0m", "fileName": "f\x1b"},
                bus, {"errors": []}, __import__("threading").Lock(), None, True, logger)
        assert "\x1b" not in caplog.text
        assert "\\x1b" in caplog.text

    def test_handle_rich_markup_in_agent_text_is_inert(self, logger, monkeypatch, capsys):
        if error_handler.Console is None:
            pytest.skip("rich not installed")
        monkeypatch.setattr(error_handler.os, "kill", lambda *a: None)
        bus = type("Bus", (), {"emit": lambda self, e: None})()
        # An unbalanced closing tag would raise MarkupError if interpolated raw.
        ScriptErrorHandler.handle(
            {"description": "[/bold] [link=http://x]click[/link]", "stack": ""},
            bus, {"errors": []}, __import__("threading").Lock(), None, True, logger)
        assert "click" in capsys.readouterr().out


class TestTextSafetyParity:
    def test_matches_tui_visible_controls(self):
        from friTap.tui.widgets.wire_text import visible_controls as tui_visible
        sample = "a\x00b\r\n\t\x1b[31m\x7f\x85 ‮⁦z"
        assert visible_controls(sample) == tui_visible(sample)
