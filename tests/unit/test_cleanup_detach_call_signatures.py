"""Regression: detach_with_timeout / cleanup must be called with matching args."""
import ast
import inspect
import pathlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from friTap.legacy import message_handler
from friTap.legacy.ssl_logger_core import SSL_Logger


def _broken_pipe_logger(timeout):
    logger = MagicMock()
    logger.live = True
    logger.full_capture = False
    logger.pcap_name = None
    logger.socket_trace = False
    logger.debug = False
    logger.debug_output = True
    logger._config = SimpleNamespace(device=SimpleNamespace(timeout=timeout))
    return logger


@pytest.fixture
def broken_pipe(monkeypatch):
    def boom(*a, **k):
        raise BrokenPipeError
    monkeypatch.setattr(message_handler, "_log_payload_to_pcap", boom)


def _drive(logger):
    payload = {"contentType": "datalog"}
    message_handler.handle_message_legacy(logger, payload, b"x", None)


@pytest.mark.parametrize("timeout,expected_call", [
    (12, ((), {"timeout": 12})),
    (None, ((), {})),
])
def test_detach_never_receives_process_as_timeout(broken_pipe, timeout, expected_call):
    logger = _broken_pipe_logger(timeout)
    _drive(logger)
    args, kwargs = logger.detach_with_timeout.call_args
    assert (args, kwargs) == expected_call
    assert logger.process not in args


def test_message_handler_cleanup_uses_keywords(broken_pipe):
    logger = _broken_pipe_logger(None)
    _drive(logger)
    logger.cleanup.assert_called_once_with(
        live=True, socket_trace=False, full_capture=False,
        debug_output=True, debug=False)


def test_cleanup_keywords_exist_on_real_signature():
    params = inspect.signature(SSL_Logger.cleanup).parameters
    for name in ("live", "socket_trace", "full_capture", "debug_output", "debug"):
        assert name in params


def test_fritap_main_cleanup_call_uses_keywords():
    src = (pathlib.Path(__file__).resolve().parents[2] / "friTap" / "friTap.py").read_text()
    calls = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "cleanup" and isinstance(n.func.value, ast.Name)
             and n.func.value.id == "ssl_log"]
    assert calls
    for call in calls:
        assert not call.args
        assert {k.arg for k in call.keywords} == {
            "live", "socket_trace", "full_capture", "debug_output", "debug"}
        kw = {k.arg: ast.unparse(k.value) for k in call.keywords}
        assert kw["debug"] == "parsed.debug"
        assert kw["debug_output"] == "parsed.debug_output"
