#!/usr/bin/env python3

"""End-of-session teardown when the memory scanner ends (headless, -ms only).

A memory-scan-only run (``fritap -m -f -p cap.pcapng -ms mtproto Telegram``) has
no hook surface, so when the target dies the scanner's poll thread is what
notices. That path used to flush only the raw pcap and set ``_done_event``; the
main thread then ``os._exit``-ed before ``finalize_full_capture`` / the manifest
ever ran. And the frida ``on_detach`` for the same death could race it.

Both entry points now funnel into one once-guarded ``_end_session``. These tests
pin: the scanner path runs the full teardown (finalize + manifest) exactly once,
and a concurrent ``on_detach`` + scanner end tears down once, with
``_done_event`` set only after the finalize finished.

``os._exit`` is patched out (it would kill pytest); every wait is bounded.
"""

from __future__ import annotations

import logging
import threading
import types

import pytest

import friTap.legacy.ssl_logger_core as core
from friTap.legacy.ssl_logger_core import SSL_Logger

WAIT = 5.0


class _FakePcap:
    """Stands in for friTap.pcap.PCAP: records the finalize / manifest pass."""

    def __init__(self, finalize_hook=None):
        self.pcap_file_name = "cap.pcapng"
        self.full_capture_thread = types.SimpleNamespace(is_alive=lambda: False)
        self.finalize_calls = 0
        self._finalize_hook = finalize_hook

    def finalize_full_capture(self, formatted_keys, traced_Socket_Set=None):
        if self._finalize_hook is not None:
            self._finalize_hook()
        self.finalize_calls += 1


def _make_logger(pcap):
    """A bare headless SSL_Logger with only what the teardown path touches."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.memscan.teardown")
    obj.special_logger = logging.getLogger("test.memscan.teardown.special")
    obj._tui_mode = False
    obj._cleanup_done = False
    obj.running = True
    obj._done_event = threading.Event()
    obj._consumer_stop = threading.Event()
    obj._instrument_stop = threading.Event()
    obj._config = types.SimpleNamespace(
        output=types.SimpleNamespace(
            auto_relabel=False, full_capture=True, pcap="cap.pcapng",
            live=False, socket_trace=False, json_output=None,
        ),
        device=types.SimpleNamespace(timeout=None, mobile=True),
        hooking=types.SimpleNamespace(library_scan=False),
        protocol="mtproto",
        debug=False,
        debug_output=False,
    )
    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
    obj._memory_scan_engine = None
    obj._handlers_active = True
    obj._output_handlers = []
    obj.pcap_obj = pcap
    obj.traced_scapy_socket_Set = set()
    obj.traced_Socket_Set = set()
    obj.process = None
    obj.device = None
    obj.pid = 1234
    obj.pcap_cleanup_calls = 0

    def _pcap_cleanup(*_a, **_k):
        obj.pcap_cleanup_calls += 1

    obj.pcap_cleanup = _pcap_cleanup
    obj._stop_instrument_thread = lambda: None
    obj._stop_consumer_thread = lambda: None
    obj._finalize_live_scan = lambda: None
    obj._is_memory_scan_only = lambda: True
    obj._pending_crash = None
    obj._report_target_crash = lambda *a, **k: None
    return obj


@pytest.fixture
def exits(monkeypatch):
    """Replace os._exit with a recorder (the teardown calls it from threads)."""
    calls = []
    monkeypatch.setattr(core.os, "_exit", lambda code: calls.append(code))
    return calls


def test_headless_scan_ended_runs_full_teardown_once(exits):
    pcap = _FakePcap()
    obj = _make_logger(pcap)

    obj._on_memory_scan_ended()

    assert obj._done_event.is_set()
    assert pcap.finalize_calls == 1, "finalize_full_capture/manifest must run"
    assert obj.pcap_cleanup_calls == 1
    assert exits == [0]

    # A later frida detach for the same death must not tear down again.
    obj.on_detach("process-terminated")
    obj._on_memory_scan_ended()
    assert pcap.finalize_calls == 1
    assert obj.pcap_cleanup_calls == 1


def test_tui_scan_ended_only_requests_stop(exits):
    pcap = _FakePcap()
    obj = _make_logger(pcap)
    obj._tui_mode = True

    obj._on_memory_scan_ended()

    assert obj.running is False
    assert pcap.finalize_calls == 0
    assert not obj._done_event.is_set()
    assert exits == []


def test_concurrent_detach_and_scan_ended_tear_down_once(exits):
    finalize_entered = threading.Event()
    release_finalize = threading.Event()

    def _block_in_finalize():
        finalize_entered.set()
        assert release_finalize.wait(WAIT), "test never released finalize"

    pcap = _FakePcap(finalize_hook=_block_in_finalize)
    obj = _make_logger(pcap)
    obj.process = None  # no frida detach to run afterwards

    detach = threading.Thread(
        target=obj.on_detach, args=("process-terminated",), daemon=True)
    detach.start()
    assert finalize_entered.wait(WAIT), "on_detach never reached finalize"

    # Scanner notices the same death while the detach teardown is mid-finalize.
    scan = threading.Thread(target=obj._on_memory_scan_ended, daemon=True)
    scan.start()
    scan.join(WAIT)
    assert not scan.is_alive(), "second caller must not block on the teardown"

    assert not obj._done_event.is_set(), "_done_event set before finalize finished"
    release_finalize.set()
    detach.join(WAIT)
    assert not detach.is_alive()

    assert obj._done_event.is_set()
    assert pcap.finalize_calls == 1
    assert obj.pcap_cleanup_calls == 1
    assert exits == [0]


def test_bounded_end_sets_done_event_on_pre_flush_wedge(exits, monkeypatch):
    release = threading.Event()
    pcap = _FakePcap(finalize_hook=lambda: release.wait(WAIT))
    obj = _make_logger(pcap)
    monkeypatch.setattr(SSL_Logger, "SESSION_END_WEDGE_TIMEOUT", 0.2)

    try:
        obj._on_memory_scan_ended()
        assert obj._done_event.is_set(), "wedged teardown must not hang the exit"
    finally:
        release.set()
