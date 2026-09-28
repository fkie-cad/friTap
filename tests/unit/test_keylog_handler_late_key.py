"""Late-key handling in :class:`KeylogOutputHandler` (Defect 2).

An async RC4/memscan scan can land its FIRST key at or after main-session
teardown (``close_output_handlers`` set ``_closed=True``). Such a key must
still open its NON-tls split keylog for the first time. A TLS handler, by
contrast, must never re-open after close — the SChannel relabel may have
renamed its file to ``<stem>.raw`` and a late key would recreate it. A handler
that already wrote keys must not re-open either — its file is finished, and a
lazy ``"w"`` open would truncate it.

Uses real :class:`KeylogOutputHandler` instances with the real
:class:`Rc4KeylogFormatter` / :class:`TlsKeylogFormatter` and real
:class:`KeylogEvent` payloads. The shared-writer registry is process-wide, so
each test uses a distinct ``tmp_path`` and closes its handlers in teardown.
"""

from __future__ import annotations

import pytest

from friTap.events import KeylogEvent
from friTap.output import shared_keylog_writer as registry
from friTap.output.keylog_handler import KeylogOutputHandler
from friTap.protocols.rc4_handler import Rc4KeylogFormatter
from friTap.protocols.tls_handler import TlsKeylogFormatter

# key hex for b"fritap-rc4-demo-key" (mirrors the rc4_keylog_spec docstring example)
_RC4_KEY_HEX = "6672697461702d7263342d64656d6f2d6b6579"


@pytest.fixture(autouse=True)
def _no_leaked_writers(tmp_path):
    """Fail loudly if a test leaves a writer open on its tmp path."""
    yield
    leaked = [p for p in registry.open_keylog_paths() if str(tmp_path) in p]
    assert not leaked, f"writers left open: {leaked}"


def _rc4_handler(path):
    return KeylogOutputHandler(str(path), Rc4KeylogFormatter())


def _tls_handler(path):
    return KeylogOutputHandler(str(path), TlsKeylogFormatter())


def _rc4_event(key_hex=_RC4_KEY_HEX, assoc="4711"):
    return KeylogEvent(
        protocol="rc4",
        payload={"key": key_hex, "source": "RC4_set_key", "assoc": assoc},
    )


def _tls_event(client_random="aa" * 32, master="bb" * 48):
    return KeylogEvent(
        protocol="tls",
        key_data=f"CLIENT_RANDOM {client_random} {master}",
    )


def test_late_rc4_key_after_close_opens_the_split_for_the_first_time(tmp_path):
    """A never-opened rc4 handler still creates its file on a post-close key."""
    keylog = tmp_path / "keys.rc4.keylog"
    handler = _rc4_handler(keylog)
    handler.close()  # main-session teardown before the async scan finished

    handler.on_keylog(_rc4_event())  # the late memscan key lands
    try:
        assert keylog.exists(), "late first rc4 key must create the split keylog"
        line = f"RC4_KEY {_RC4_KEY_HEX} 19 RC4_set_key unknown 4711"
        assert line in keylog.read_text().splitlines()
    finally:
        handler.close()


def test_late_tls_key_after_close_does_not_recreate_the_relabel_subject(tmp_path):
    """A closed tls handler drops a late key (protects the relabel-renamed file)."""
    keylog = tmp_path / "keys.log"
    handler = _tls_handler(keylog)
    handler.close()  # e.g. after the SChannel relabel renamed the file

    assert handler._open_lazy() is None
    handler.on_keylog(_tls_event())  # must be dropped, not recreate the file

    assert not keylog.exists()
    assert not registry.is_keylog_path_open(str(keylog))


def test_late_rc4_key_after_writing_does_not_truncate_the_finished_file(tmp_path):
    """An already-written handler drops a late key — no ``"w"`` truncation."""
    keylog = tmp_path / "keys.rc4.keylog"
    handler = _rc4_handler(keylog)
    handler.on_keylog(_rc4_event(assoc="1"))  # first key: opens + writes
    handler.close()
    before = keylog.read_text()
    assert f"RC4_KEY {_RC4_KEY_HEX} 19 RC4_set_key unknown 1" in before

    # A late, DIFFERENT key arrives after close — the file is finished.
    handler.on_keylog(_rc4_event(key_hex="ff" * 16, assoc="2"))

    assert handler._writer is None  # did not re-open
    assert keylog.read_text() == before  # content unchanged, not truncated
    assert not registry.is_keylog_path_open(str(keylog))
