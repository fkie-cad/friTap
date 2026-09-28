"""One shared, refcounted writer per keylog path within a friTap process.

On Windows full captures the main SSL_Logger and the LSASS SSL_Logger both
write the ``-k`` keylog through their own KeylogOutputHandler. Each used to
open the path with ``"w"`` on its first key, so the later one truncated the
other's keys. The handlers now share one handle per normalized path: the
first opener truncates, later openers append through the same handle, and the
file closes when the last handler releases it.
"""

from __future__ import annotations

import os
import threading
import types
from unittest.mock import MagicMock

import pytest

import friTap.friTap as fritap
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.offline.keylog_coverage import RepairResult
from friTap.output import shared_keylog_writer as registry
from friTap.output.keylog_handler import KeylogOutputHandler


class _LineFormatter:
    """Minimal KeylogFormatter stand-in: one line per event."""
    protocol = "tls"

    def __init__(self, header=""):
        self._header = header

    def format(self, event):
        return [event.line]

    def dedup_key(self, event):
        return event.line

    def header_comment(self):
        return self._header


def _event(line):
    return types.SimpleNamespace(protocol="tls", line=line)


def _handler(path, header=""):
    return KeylogOutputHandler(str(path), _LineFormatter(header))


@pytest.fixture(autouse=True)
def _no_leaked_writers(tmp_path):
    yield
    leaked = [p for p in registry.open_keylog_paths() if str(tmp_path) in p]
    assert not leaked, f"writers left open: {leaked}"


# ---------------------------------------------------------------------------
# Two handlers, one file
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("first", ["main", "lsass"])
def test_two_handlers_on_one_path_keep_every_line(tmp_path, first):
    keylog = tmp_path / "keys.log"
    handlers = {"main": _handler(keylog), "lsass": _handler(keylog)}
    second = "lsass" if first == "main" else "main"

    handlers[first].on_keylog(_event(f"{first} 1"))
    handlers[second].on_keylog(_event(f"{second} 1"))  # must not truncate
    handlers[first].on_keylog(_event(f"{first} 2"))
    handlers[second].on_keylog(_event(f"{second} 2"))
    for h in handlers.values():
        h.close()

    assert keylog.read_text().splitlines() == [
        f"{first} 1", f"{second} 1", f"{first} 2", f"{second} 2"]


def test_second_handler_does_not_repeat_the_header(tmp_path):
    keylog = tmp_path / "keys.log"
    a, b = _handler(keylog, "# hdr"), _handler(keylog, "# hdr")
    a.on_keylog(_event("a"))
    b.on_keylog(_event("b"))
    a.close()
    b.close()

    assert keylog.read_text() == "# hdr\na\nb\n"


def test_concurrent_writers_produce_whole_lines_only(tmp_path):
    keylog = tmp_path / "keys.log"
    a, b = _handler(keylog), _handler(keylog)
    per_thread = 500
    payload = "x" * 200

    def pump(handler, tag):
        for i in range(per_thread):
            handler.on_keylog(_event(f"{tag} {i} {payload}"))

    threads = [threading.Thread(target=pump, args=(a, "A")),
               threading.Thread(target=pump, args=(b, "B"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()
    a.close()
    b.close()

    lines = keylog.read_text().splitlines()
    expected = {f"{tag} {i} {payload}" for tag in "AB" for i in range(per_thread)}
    assert len(lines) == 2 * per_thread
    assert set(lines) == expected


# ---------------------------------------------------------------------------
# Refcount / lifecycle
# ---------------------------------------------------------------------------

def test_file_stays_open_until_the_last_handler_closes(tmp_path):
    keylog = tmp_path / "keys.log"
    a, b = _handler(keylog), _handler(keylog)
    a.on_keylog(_event("a"))
    b.on_keylog(_event("b"))

    a.close()
    assert registry.is_keylog_path_open(str(keylog))
    assert b._file is not None and not b._file.closed
    b.on_keylog(_event("b late"))  # the surviving writer keeps writing

    b.close()
    assert not registry.is_keylog_path_open(str(keylog))
    assert keylog.read_text() == "a\nb\nb late\n"


def test_reacquiring_after_full_close_truncates(tmp_path):
    """A new capture run in the same process (TUI restart) starts a fresh keylog."""
    keylog = tmp_path / "keys.log"
    first_run = _handler(keylog)
    first_run.on_keylog(_event("old"))
    first_run.close()

    second_run = _handler(keylog)
    second_run.on_keylog(_event("new"))
    second_run.close()

    assert keylog.read_text() == "new\n"


def test_closed_handler_never_reopens_even_while_another_holds_the_file(tmp_path):
    keylog = tmp_path / "keys.log"
    a, b = _handler(keylog), _handler(keylog)
    a.on_keylog(_event("a"))
    b.on_keylog(_event("b"))
    a.close()

    a.on_keylog(_event("a late"))  # dropped: a is closed
    b.close()

    assert keylog.read_text() == "a\nb\n"


def test_closed_handler_does_not_recreate_the_file(tmp_path):
    keylog = tmp_path / "keys.log"
    handler = _handler(keylog)
    handler.on_keylog(_event("a"))
    handler.close()
    os.replace(keylog, tmp_path / "keys.raw.log")

    handler.on_keylog(_event("late"))

    assert not keylog.exists()
    assert not registry.is_keylog_path_open(str(keylog))


def test_close_is_idempotent_and_does_not_steal_other_references(tmp_path):
    keylog = tmp_path / "keys.log"
    a, b = _handler(keylog), _handler(keylog)
    a.on_keylog(_event("a"))
    b.on_keylog(_event("b"))
    a.close()
    a.close()  # second close must not drop b's reference

    assert registry.is_keylog_path_open(str(keylog))
    b.close()
    assert not registry.is_keylog_path_open(str(keylog))


def test_release_past_zero_is_a_noop(tmp_path):
    writer, created = registry.acquire_keylog_writer(str(tmp_path / "k.log"))
    assert created
    assert registry.release_keylog_writer(writer) is True
    assert registry.release_keylog_writer(writer) is False
    assert writer.write_lines(["x"]) is False  # closed writer writes nothing


def test_different_paths_are_independent(tmp_path):
    a, b = _handler(tmp_path / "a.log"), _handler(tmp_path / "b.log")
    a.on_keylog(_event("a"))
    b.on_keylog(_event("b"))
    a.close()

    assert not registry.is_keylog_path_open(str(tmp_path / "a.log"))
    assert registry.is_keylog_path_open(str(tmp_path / "b.log"))
    b.close()
    assert (tmp_path / "a.log").read_text() == "a\n"
    assert (tmp_path / "b.log").read_text() == "b\n"


def test_relative_and_absolute_paths_share_one_writer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    relative = _handler("keys.log")
    absolute = _handler(tmp_path / "sub" / ".." / "keys.log")
    relative.on_keylog(_event("rel"))
    absolute.on_keylog(_event("abs"))  # same file: must not truncate "rel"

    assert relative._writer is absolute._writer
    relative.close()
    absolute.close()
    assert (tmp_path / "keys.log").read_text() == "rel\nabs\n"


def test_open_failure_is_logged_and_leaves_no_registry_entry(tmp_path):
    missing_dir = tmp_path / "nope" / "keys.log"
    handler = _handler(missing_dir)
    handler.on_keylog(_event("a"))  # must not raise

    assert handler._file is None
    assert not registry.is_keylog_path_open(str(missing_dir))
    handler.close()


# ---------------------------------------------------------------------------
# SChannel relabel after both sessions released the shared keylog
# ---------------------------------------------------------------------------

def _logger_shell(handlers):
    shell = SSL_Logger.__new__(SSL_Logger)
    shell._handlers_active = True
    shell._output_handlers = handlers
    shell.logger = MagicMock()
    return shell


def _relabel_self(keylog, logger):
    output = types.SimpleNamespace(auto_relabel=True, keylog=str(keylog), tshark_path=None)
    return types.SimpleNamespace(
        _config=types.SimpleNamespace(output=output),
        pcap_obj=types.SimpleNamespace(keylog_path=str(keylog)),
        keylog_file=None,
        logger=logger,
    )


@pytest.fixture
def relabel_env(tmp_path, monkeypatch):
    """Windows + tshark stubbed; relabel_keylog returns a corrected copy."""
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00" * 64)
    relabeled = tmp_path / "keys.relabeled.log"

    def fake_relabel(_tshark, _pcap, _keylog, progress=None):
        relabeled.write_text("FIXED\n")
        return RepairResult(str(relabeled), 1, 1, "Relabeled 1 session.")

    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: True)
    monkeypatch.setattr("friTap.offline.tshark.find_tshark", lambda _p=None: "tshark")
    monkeypatch.setattr("friTap.offline.keylog_coverage.relabel_keylog", fake_relabel)
    return pcap


def _install_lsass_manager(monkeypatch, lsass_shell):
    manager = fritap.LsassHookManager()
    manager.lsass_logger = lsass_shell
    manager.running = False  # worker already ended; handlers still open
    monkeypatch.setattr(fritap, "_lsass_hook_manager", manager)


def test_relabel_renames_after_both_sessions_released(tmp_path, relabel_env, monkeypatch):
    keylog = tmp_path / "keys.log"
    main_handler, lsass_handler = _handler(keylog), _handler(keylog)
    main_handler.on_keylog(_event("main key"))
    lsass_handler.on_keylog(_event("lsass key"))
    main_shell, lsass_shell = _logger_shell([main_handler]), _logger_shell([lsass_handler])
    _install_lsass_manager(monkeypatch, lsass_shell)

    main_shell.close_output_handlers()  # teardown order: our handlers first
    assert registry.is_keylog_path_open(str(keylog))  # LSASS still holds it
    logger = MagicMock()
    SSL_Logger._auto_relabel_schannel_keylog(_relabel_self(keylog, logger), str(relabel_env))

    assert not registry.is_keylog_path_open(str(keylog))
    assert keylog.read_text() == "FIXED\n"
    assert (tmp_path / "keys.raw.log").read_text() == "main key\nlsass key\n"
    logger.warning.assert_not_called()


def test_relabel_skips_a_keylog_still_held_open(tmp_path, relabel_env, monkeypatch):
    keylog = tmp_path / "keys.log"
    holder = _handler(keylog)  # some writer that was never released
    holder.on_keylog(_event("held key"))
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: None)
    logger = MagicMock()
    try:
        SSL_Logger._auto_relabel_schannel_keylog(
            _relabel_self(keylog, logger), str(relabel_env))
    finally:
        holder.close()

    assert keylog.read_text() == "held key\n"
    assert not (tmp_path / "keys.raw.log").exists()
    warning = " ".join(str(c.args) for c in logger.warning.call_args_list)
    assert "still open" in warning and "--repair-keylog" in warning
