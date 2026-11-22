"""Tri-state follow-exec: auto is off everywhere (Frida fork-child crash)."""
import logging
import types
from unittest.mock import MagicMock

import pytest

from friTap.config import DeviceConfig, FriTapConfig, resolve_follow_exec
from friTap.legacy.ssl_logger_core import SSL_Logger
from tests.unit._log_helpers import attach_log_capture


@pytest.mark.parametrize("mobile,requested,expected", [
    (False, None, False), (True, None, False),
    (False, True, True), (True, True, True),
    (False, False, False), (True, False, False),
    ("serial123", None, False),
])
def test_resolution_matrix(mobile, requested, expected):
    assert resolve_follow_exec(DeviceConfig(mobile=mobile, follow_exec=requested)) is expected


def test_legacy_params_and_api_paths():
    from friTap.api import FriTap
    cfg = FriTapConfig.from_legacy_params(app="t", mobile=True)
    assert resolve_follow_exec(cfg.device) is False
    assert resolve_follow_exec(FriTapConfig.from_legacy_params(app="t", mobile=True, follow_exec=True).device) is True
    assert resolve_follow_exec(FriTap("t").mobile().build_config().device) is False
    assert resolve_follow_exec(FriTap("t").follow_exec(True).mobile().build_config().device) is True
    assert resolve_follow_exec(FriTap("t").follow_exec(False).build_config().device) is False


def test_cli_flags_parse_tristate():
    import friTap.friTap as cli
    src = open(cli.__file__).read()
    assert '"--follow-exec"' in src and '"--no-follow-exec"' in src


def _logger(mobile, follow_exec, child_gating=False):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.follow_exec_resolution")
    obj._backend = MagicMock()
    obj.process = MagicMock()
    obj.pid = 1
    obj._config = types.SimpleNamespace(device=types.SimpleNamespace(
        spawn=True, mobile=mobile, follow_exec=follow_exec, enable_child_gating=child_gating))
    obj._init_process_following()
    return obj


def _run(obj):
    _, cap = attach_log_capture("test.follow_exec_resolution")
    try:
        obj.follow_exec_of(obj.process)
    finally:
        logging.getLogger("test.follow_exec_resolution").removeHandler(cap)
    return cap


@pytest.mark.parametrize("mobile", [True, False])
def test_auto_logs_info_and_never_gates(mobile):
    obj = _logger(mobile, None)
    cap = _run(obj)
    obj._backend.enable_child_gating.assert_not_called()
    assert any("off by default" in m and "--follow-exec" in m for m in cap.messages(logging.INFO))
    assert not cap.messages(logging.WARNING)


@pytest.mark.parametrize("mobile", [True, False])
@pytest.mark.parametrize("follow,gating", [(True, False), (None, True)])
def test_explicit_on_warns_on_any_platform(mobile, follow, gating):
    obj = _logger(mobile, follow, gating)
    cap = _run(obj)
    obj._backend.enable_child_gating.assert_called_once()
    assert any("fork-child" in m for m in cap.messages(logging.WARNING))


def test_desktop_explicit_no_follow_exec_is_silent():
    obj = _logger(False, False)
    cap = _run(obj)
    obj._backend.enable_child_gating.assert_not_called()
    assert cap.messages() == []


def test_nothing_gated_when_resolved_off():
    obj = _logger(False, None)
    assert obj.gates_children is False
    assert obj.follow_exec_of(obj.process) is False
    obj._backend.enable_child_gating.assert_not_called()
