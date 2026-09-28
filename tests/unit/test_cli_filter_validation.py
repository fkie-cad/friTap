#!/usr/bin/env python3

"""In-process tests for ``_reject_invalid_headless_filter`` (the early ``--filter`` check).

``cli()`` calls the helper right after argument parsing; it must either return
(nothing to reject) or raise ``Failure`` -- exit code 2 -- carrying the single
error message ``headless_filter_error`` produced. The subprocess side (no banner,
real exit status, empty stdout) lives in ``test_cli_exit_codes.py``.

No ``caplog``: friTap's loggers do not propagate, so a stub logger is passed.
"""

from __future__ import annotations

import pytest

from friTap.friTap import _reject_invalid_headless_filter
from friTap.fritap_utility import Failure


class RecordingLogger:
    def __init__(self):
        self.records = []

    def log(self, level, message, *args):
        self.records.append((level, str(message)))


@pytest.mark.parametrize("expression", [None, "", "protocol == telegram",
                                        "ip.addr == 1.2.3.4", "tcp.port == 443"])
def test_accepted_filters_return_without_raising(expression):
    assert _reject_invalid_headless_filter(expression, RecordingLogger()) is None


def test_invalid_syntax_raises_failure_with_exit_code_two():
    with pytest.raises(Failure) as excinfo:
        _reject_invalid_headless_filter("TELE", RecordingLogger())
    assert excinfo.value.code == 2
    assert excinfo.value.info.startswith("Invalid filter expression")


def test_tui_only_field_raises_failure_with_headless_hint():
    with pytest.raises(Failure) as excinfo:
        _reject_invalid_headless_filter("telegram", RecordingLogger())
    assert excinfo.value.code == 2
    assert "not available in headless mode: telegram" in excinfo.value.info
    assert "protocol == telegram" in excinfo.value.info


def test_failure_logs_the_message_once_on_exit():
    logger = RecordingLogger()
    with pytest.raises(Failure) as excinfo:
        _reject_invalid_headless_filter("TELE", logger)
    with pytest.raises(SystemExit) as exit_info:
        excinfo.value.exit()
    assert exit_info.value.code == 2
    assert len(logger.records) == 1
    assert "Invalid filter expression" in logger.records[0][1]
