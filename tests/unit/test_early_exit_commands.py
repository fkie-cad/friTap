#!/usr/bin/env python3

"""Unit tests for friTap's early-exit commands (``-ll`` / ``--extract-libraries``).

``_run_early_exit_command`` used to be a nested helper inside ``cli()`` whose
success path was a bare ``return`` -- which returned from the *helper*, not from
``cli()``. So ``fritap -ll <target>`` printed its library listing and then fell
through into a full capture session that blocks forever in
``wait_for_completion()``, even though ``-ll``'s help text promises "This will
not start the logging process, but only list the libraries and exit."

The helper now lives at module scope (which also makes it directly testable) and
every path out of it raises a :class:`FriTapExit`. That single invariant is the
regression test: whatever the action does, control must never come back.

No ``caplog`` here on purpose -- friTap's loggers are created with
``propagate = False``, so pytest's capture handler on the root logger sees
nothing. The tests use a recording stub logger instead.
"""

from __future__ import annotations

import pytest

from friTap.backends import BackendTransportError
from friTap.friTap import FridaBasedException, _run_early_exit_command
from friTap.fritap_utility import Failure, FriTapExit, Success
from friTap.inspector import LibraryInspector

_LISTING = "=== [ TLS/SSL Library Detection (tlsLibHunter) ] ===\nLibraries found:  1"
_ERROR_RESULT = LibraryInspector.ERROR_PREFIX + "Failed to inspect libraries - boom"


class RecordingLogger:
    """Minimal stand-in for friTap's loggers that just remembers what it got."""

    def __init__(self):
        self.infos = []
        self.errors = []

    def info(self, message, *args):
        self.infos.append(str(message) % args if args else str(message))

    def error(self, message, *args):
        self.errors.append(str(message) % args if args else str(message))


@pytest.fixture
def loggers():
    """The ``(logger, special_logger)`` pair ``cli()`` passes to the helper."""
    return RecordingLogger(), RecordingLogger()


def _raising_action():
    raise RuntimeError("scan blew up")


# ---------------------------------------------------------------------------
# The regression test: the helper never returns, whatever the action does
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action_fn", [
    lambda: _LISTING,                       # a clean listing
    lambda: _ERROR_RESULT,                  # a failure reported in the return value
    _raising_action,                        # a failure reported by raising
], ids=["listing", "error_string", "raises"])
def test_always_raises_fritap_exit(action_fn, loggers):
    """Every action shape must terminate ``cli()``, never fall through to capture."""
    logger, special_logger = loggers
    with pytest.raises(FriTapExit):
        _run_early_exit_command("label", action_fn, logger, special_logger)


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_normal_result_raises_success_with_code_zero(loggers):
    logger, special_logger = loggers
    with pytest.raises(Success) as excinfo:
        _run_early_exit_command("label", lambda: _LISTING, logger, special_logger)
    assert excinfo.value.code == 0
    assert special_logger.infos == [_LISTING]
    assert logger.errors == []


def test_success_carries_logger_not_info(loggers):
    """Pins the keyword-vs-positional trap in ``FriTapExit(info, logger, code)``.

    ``raise Success(special_logger)`` would bind the Logger to *info* and print
    its repr instead of the goodbye banner.
    """
    logger, special_logger = loggers
    with pytest.raises(Success) as excinfo:
        _run_early_exit_command("label", lambda: _LISTING, logger, special_logger)
    assert excinfo.value.logger is special_logger
    assert isinstance(excinfo.value.info, str)


def test_label_is_logged_before_the_action_runs(loggers):
    logger, special_logger = loggers
    seen_at_call_time = []

    def action():
        seen_at_call_time.extend(logger.infos)
        return _LISTING

    with pytest.raises(FriTapExit):
        _run_early_exit_command("Listing loaded libraries...", action, logger, special_logger)
    assert seen_at_call_time == ["Listing loaded libraries..."]


# ---------------------------------------------------------------------------
# Failure reported in the return value (the inspectors never raise)
# ---------------------------------------------------------------------------

def test_error_result_raises_failure_with_code_two(loggers):
    logger, special_logger = loggers
    with pytest.raises(Failure) as excinfo:
        _run_early_exit_command("label", lambda: _ERROR_RESULT, logger, special_logger)
    assert excinfo.value.code == 2
    # The error string is the diagnostic the user asked for -- still print it.
    assert special_logger.infos == [_ERROR_RESULT]


# ---------------------------------------------------------------------------
# Failure reported by raising
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    BackendTransportError("transport is down"),
    FridaBasedException("backend refused"),
    RuntimeError("something unexpected"),
], ids=["transport", "frida", "generic"])
def test_raising_action_exits_two_and_logs_the_cause(exc, loggers):
    logger, special_logger = loggers

    def action():
        raise exc

    with pytest.raises(Failure) as excinfo:
        _run_early_exit_command("label", action, logger, special_logger)
    assert excinfo.value.code == 2
    assert any(str(exc) in line for line in logger.errors)
    # Nothing to print: there is no result.
    assert special_logger.infos == []


def test_fritap_exit_from_the_action_is_not_swallowed(loggers):
    """Guards that the Success/Failure raises stay in the ``else:`` clause.

    They subclass ``Exception``; raising them inside the ``try:`` body would be
    caught by the helper's own ``except Exception`` and re-reported as an error.
    """
    logger, special_logger = loggers
    sentinel = Success(info="from the action", code=7)

    def action():
        raise sentinel

    with pytest.raises(Success) as excinfo:
        _run_early_exit_command("label", action, logger, special_logger)
    assert excinfo.value is sentinel
    assert excinfo.value.code == 7


# ---------------------------------------------------------------------------
# The ERROR_PREFIX contract itself
# ---------------------------------------------------------------------------

def test_inspect_reports_failure_through_error_prefix():
    """Drives ``LibraryInspector.inspect`` into its own ``except``.

    This is what keeps ``fritap -ll`` from silently exiting 0 on a failed scan:
    the method swallows the exception, so the prefix in the returned string is
    the only failure signal the CLI has.
    """
    class ExplodingConfig:
        def __getattr__(self, name):
            raise ValueError(f"no {name}")

    logger = RecordingLogger()
    result = LibraryInspector.inspect(ExplodingConfig(), logger)
    assert LibraryInspector.is_error(result)
    assert result.startswith(LibraryInspector.ERROR_PREFIX)
    assert logger.errors


@pytest.mark.parametrize("value", [_LISTING, "", None], ids=["listing", "empty", "none"])
def test_is_error_does_not_false_positive(value):
    assert LibraryInspector.is_error(value) is False


def test_importing_cli_does_not_load_legacy_stack():
    import subprocess
    import sys
    code = ("import sys, friTap.friTap; "
            "sys.exit(int('friTap.legacy.ssl_logger_core' in sys.modules))")
    assert subprocess.run([sys.executable, "-c", code], timeout=60).returncode == 0
