import logging
import threading

import pytest

from friTap import _warn_once as mod
from friTap._warn_once import reset_warn_once, warn_once

log = logging.getLogger("test_warn_once")


@pytest.fixture(autouse=True)
def _clean():
    reset_warn_once()
    yield
    reset_warn_once()


def test_once_per_key():
    assert warn_once(log, "a", "m") is True
    assert warn_once(log, "a", "m") is False
    assert warn_once(log, "b", "m") is True


def test_level_and_args_forwarded(caplog):
    log.propagate = True
    with caplog.at_level(logging.DEBUG, logger=log.name):
        warn_once(log, "k", "hello %s", "x", level=logging.INFO)
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [(logging.INFO, "hello x")]


def test_reset():
    warn_once(log, "a", "m")
    reset_warn_once()
    assert warn_once(log, "a", "m") is True


def test_bounded(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_KEYS", 3)
    assert [warn_once(log, i, "m") for i in range(5)] == [True, True, True, False, False]
    assert len(mod._seen) == 3


def test_thread_safety_single_winner():
    wins = []
    threads = [threading.Thread(target=lambda: wins.append(warn_once(log, "k", "m")))
               for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1


def test_family_reset_only_clears_that_family():
    assert warn_once(log, ("fam-a", 1), "m") is True
    assert warn_once(log, ("fam-a", 2), "m") is True
    assert warn_once(log, "plain-key", "m") is True
    assert warn_once(log, ("fam-b", 1), "m") is True
    reset_warn_once("fam-a")
    assert warn_once(log, ("fam-a", 1), "m") is True
    assert warn_once(log, ("fam-a", 2), "m") is True
    assert warn_once(log, "plain-key", "m") is False
    assert warn_once(log, ("fam-b", 1), "m") is False
    reset_warn_once("plain-key")
    assert warn_once(log, "plain-key", "m") is True


def test_reset_drop_warnings_leaves_other_keys():
    from friTap.sinks.tcp_state import reset_drop_warnings, warn_dropped_record
    assert warn_once(log, "telegram:invalid_chat_id", "m") is True
    assert warn_once(log, ("tshark-env", "VAR", "x"), "m") is True
    warn_dropped_record("bad reason", log)
    reset_drop_warnings()
    assert warn_once(log, "telegram:invalid_chat_id", "m") is False
    assert warn_once(log, ("tshark-env", "VAR", "x"), "m") is False
    assert warn_once(log, ("tcp_state:drop", "bad reason"), "m") is True


def test_full_reset_clears_everything():
    warn_once(log, "telegram:invalid_chat_id", "m")
    warn_once(log, ("tshark-env", "VAR", "x"), "m")
    reset_warn_once()
    assert warn_once(log, "telegram:invalid_chat_id", "m") is True
    assert warn_once(log, ("tshark-env", "VAR", "x"), "m") is True
