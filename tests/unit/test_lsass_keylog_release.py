"""The LSASS worker session must release the shared ``-k`` keylog at teardown.

The Windows LSASS SSL_Logger (``LsassHookManager``) writes SChannel secrets to
the base keylog through its own KeylogOutputHandler. The target session's
SChannel auto-relabel renames that file, which Windows refuses while a handle
is open, so ``stop_lsass_hook`` must flush + close the LSASS logger's output
handlers, and a closed handler must never lazily re-open (truncate) the file.
Frida-free: the LSASS logger is a mock or a bare SSL_Logger shell.
"""

import os
import types
from unittest.mock import MagicMock

import friTap.friTap as fritap
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.keylog_handler import KeylogOutputHandler


class _LineFormatter:
    """Minimal KeylogFormatter stand-in: one line per event, no header."""
    protocol = "tls"

    def format(self, event):
        return [event.line]

    def dedup_key(self, event):
        return event.line

    def header_comment(self):
        return ""


def _event(line):
    return types.SimpleNamespace(protocol="tls", line=line)


def _manager_with(lsass_logger, *, running):
    manager = fritap.LsassHookManager()
    manager.lsass_logger = lsass_logger
    manager.running = running
    return manager


def test_stop_lsass_hook_closes_the_lsass_output_handlers():
    lsass_logger = MagicMock()
    _manager_with(lsass_logger, running=True).stop_lsass_hook()

    lsass_logger.finish_fritap.assert_called_once()
    lsass_logger.close_output_handlers.assert_called_once()


def test_stop_lsass_hook_closes_handlers_even_after_the_worker_ended():
    """The worker loop exits on its own when lsass detaches; handlers stay open."""
    lsass_logger = MagicMock()
    _manager_with(lsass_logger, running=False).stop_lsass_hook()

    lsass_logger.finish_fritap.assert_not_called()
    lsass_logger.close_output_handlers.assert_called_once()


def test_stop_lsass_hook_without_a_logger_is_a_noop():
    _manager_with(None, running=False).stop_lsass_hook()  # must not raise


def test_stop_lsass_hook_survives_a_failing_close():
    lsass_logger = MagicMock()
    lsass_logger.close_output_handlers.side_effect = RuntimeError("boom")
    _manager_with(lsass_logger, running=True).stop_lsass_hook()  # must not raise


def _logger_shell(handlers):
    shell = SSL_Logger.__new__(SSL_Logger)
    shell._handlers_active = True
    shell._output_handlers = handlers
    shell.logger = MagicMock()
    return shell


def test_close_output_handlers_closes_each_handler_once():
    handler = MagicMock()
    shell = _logger_shell([handler])
    shell.close_output_handlers()
    shell.close_output_handlers()
    handler.close.assert_called_once()


def test_close_output_handlers_continues_after_a_failing_handler():
    bad, good = MagicMock(), MagicMock()
    bad.close.side_effect = OSError("disk gone")
    shell = _logger_shell([bad, good])
    shell.close_output_handlers()
    good.close.assert_called_once()
    shell.logger.error.assert_called_once()


def test_close_output_handlers_noop_when_handlers_inactive():
    handler = MagicMock()
    shell = _logger_shell([handler])
    shell._handlers_active = False
    shell.close_output_handlers()
    handler.close.assert_not_called()


def test_lsass_keylog_is_released_so_it_can_be_renamed(tmp_path):
    """End to end on the real handler: after stop, no handle holds the keylog."""
    keylog = tmp_path / "keys.log"
    handler = KeylogOutputHandler(str(keylog), _LineFormatter())
    handler.on_keylog(_event("CLIENT_RANDOM aa bb"))
    assert handler._file is not None  # the LSASS writer holds the file open

    _manager_with(_logger_shell([handler]), running=True).stop_lsass_hook()

    assert handler._file is None
    os.replace(keylog, tmp_path / "keys.raw.log")  # what the relabel does
    assert (tmp_path / "keys.raw.log").read_text() == "CLIENT_RANDOM aa bb\n"


def test_closed_keylog_handler_never_reopens_and_truncates(tmp_path):
    keylog = tmp_path / "keys.log"
    handler = KeylogOutputHandler(str(keylog), _LineFormatter())
    handler.on_keylog(_event("CLIENT_RANDOM aa bb"))
    handler.close()

    handler.on_keylog(_event("CLIENT_RANDOM cc dd"))  # a late event

    assert handler._file is None
    assert keylog.read_text() == "CLIENT_RANDOM aa bb\n"


def test_closed_keylog_handler_does_not_recreate_a_renamed_file(tmp_path):
    keylog = tmp_path / "keys.log"
    handler = KeylogOutputHandler(str(keylog), _LineFormatter())
    handler.on_keylog(_event("CLIENT_RANDOM aa bb"))
    handler.close()
    os.replace(keylog, tmp_path / "keys.raw.log")

    handler.on_keylog(_event("CLIENT_RANDOM cc dd"))

    assert not keylog.exists()
