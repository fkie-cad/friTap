"""Capture coordinator (:class:`friTap.session.Session`) lifecycle, cleanup and wiring.

Covers: the coordinator's own start/stop is a CaptureLifecycleEvent, never a
TLS SessionEvent; "stopped" reaches subscribers before wait() returns; the
cleanup stack undoes acquired resources in reverse even when one step fails;
CoreController's single backend-resolution rule; FriTapSession delegation.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from friTap.config import FriTapConfig, OutputConfig
from friTap.core import CoreController
from friTap.events import SessionEvent
from friTap.session import (
    CAPTURE_STARTED,
    CAPTURE_STOPPED,
    CaptureLifecycleEvent,
    SessionState,
)


class _Producer:
    def __init__(self, calls=None):
        self.calls = calls if calls is not None else []

    def start(self, emit, finished):
        self.calls.append("producer.start")

    def stop(self):
        self.calls.append("producer.stop")


def _ebpf_session(producer=None, **output):
    config = FriTapConfig(target="fixture", backend="ebpf", output=OutputConfig(**output))
    return CoreController().create_session(config, producer=producer or _Producer())


# --- lifecycle events --------------------------------------------------------

def test_coordinator_start_stop_is_not_a_tls_session_event():
    session = _ebpf_session()
    tls_sessions, lifecycle = [], []
    session.lifecycle_bus.subscribe(SessionEvent, tls_sessions.append)
    session.lifecycle_bus.subscribe(CaptureLifecycleEvent, lambda e: lifecycle.append(e.event_type))

    session.start()
    session.stop()

    assert tls_sessions == []
    assert lifecycle == [CAPTURE_STARTED, CAPTURE_STOPPED]


def test_json_output_counts_no_fake_session_for_the_coordinator(tmp_path):
    out = tmp_path / "out.json"
    session = _ebpf_session(json_output=str(out))

    session.start()
    session.stop()

    doc = json.loads(out.read_text())
    assert doc["ssl_sessions"] == []
    assert doc["statistics"]["total_sessions"] == 0


def test_stopped_is_announced_before_wait_returns():
    session = _ebpf_session()
    done_when_stopped = []

    def on_lifecycle(event):
        if event.event_type == CAPTURE_STOPPED:
            done_when_stopped.append(session.wait_timeout(0))

    session.lifecycle_bus.subscribe(CaptureLifecycleEvent, on_lifecycle)
    session.start()
    session.stop()

    assert done_when_stopped == [False]
    assert session.wait_timeout(0)


# --- cleanup stack -----------------------------------------------------------

def _recording_session(calls, *, fail_on=None):
    session = _ebpf_session(producer=_Producer(calls))

    def record(name, real=None):
        def step(*args, **kwargs):
            calls.append(name)
            if name == fail_on:
                raise RuntimeError(name)
            return real(*args, **kwargs) if real else None
        return step

    session.pipeline.flush_all = record("flush_all")
    session.pipeline.close_all = record("close_all")
    session._plugin_loader = SimpleNamespace(load_all=record("load_all"),
                                             unload_all=record("unload_all"))
    session._producer.stop = record("producer.stop")
    return session


def test_finalize_undoes_resources_in_reverse_order():
    calls = []
    session = _recording_session(calls)
    session.start()
    calls.clear()

    session.stop()

    assert calls == ["producer.stop", "unload_all", "flush_all", "close_all"]
    assert session.state == SessionState.STOPPED


def test_one_failing_cleanup_does_not_skip_the_rest():
    calls = []
    session = _recording_session(calls, fail_on="unload_all")
    session.start()
    calls.clear()

    session.stop()

    assert calls == ["producer.stop", "unload_all", "flush_all", "close_all"]
    assert isinstance(session.failure, RuntimeError)
    assert session.wait_timeout(0)


def test_failed_startup_undoes_only_what_was_acquired():
    calls = []
    session = _recording_session(calls, fail_on="load_all")

    with pytest.raises(RuntimeError):
        session.start()

    # The producer never started, so it is never stopped.
    assert calls == ["load_all", "unload_all", "flush_all", "close_all"]
    assert session.state == SessionState.STOPPED


def test_finalize_runs_each_cleanup_once():
    calls = []
    session = _recording_session(calls)
    session.start()
    session.stop()
    calls.clear()

    session._finalize()

    assert calls == []


def test_router_is_created_only_when_needed():
    config = FriTapConfig(target="fixture")
    controller = CoreController(backend=SimpleNamespace(name="frida"))
    idle = controller.create_session(config, manage_capture_resources=False)
    idle.start()
    assert idle._router is None

    producer_session = _ebpf_session()
    producer_session.start()
    assert producer_session._router is not None
    producer_session.stop()


# --- CoreController backend resolution --------------------------------------

def test_injected_backend_wins(monkeypatch):
    injected = SimpleNamespace(name="frida")
    monkeypatch.setattr("friTap.core.get_backend", pytest.fail)
    controller = CoreController(backend=injected)

    assert controller.backend is injected
    assert controller.create_session(FriTapConfig(target="x"))._backend is injected


def test_producer_session_needs_no_backend(monkeypatch):
    monkeypatch.setattr("friTap.core.get_backend", pytest.fail)
    session = _ebpf_session()
    assert session._backend is None


def test_named_backend_resolved_per_config(monkeypatch):
    monkeypatch.setattr("friTap.core.get_backend", lambda name="frida": SimpleNamespace(name=name))
    controller = CoreController()

    assert controller.backend.name == "frida"
    session = controller.create_session(FriTapConfig(target="x", backend="gdb"))
    assert session._backend.name == "gdb"
    # Using the default backend must not pin it as an injected one.
    assert controller._backend is None


# --- FriTapSession -----------------------------------------------------------

def test_fritap_session_delegates_to_the_coordinator():
    from friTap.api import FriTapSession

    coordinator = _ebpf_session()
    handle = FriTapSession(None, coordinator.lifecycle_bus, coordinator=coordinator)
    coordinator.start()
    assert handle.is_running

    handle.stop()
    handle.wait()
    assert not handle.is_running
    handle.stop()  # harmless


def test_fritap_session_requires_a_coordinator():
    from friTap.api import FriTapSession
    from friTap.events import EventBus

    with pytest.raises(TypeError):
        FriTapSession(None, EventBus())


def test_api_on_session_gets_capture_start_stop_without_bus_session_events(monkeypatch):
    from friTap.api import FriTap

    producer = _Producer()
    monkeypatch.setattr("friTap.backends.capture.create_ebpf_producer", lambda config: producer)
    received = []
    handle = FriTap("fixture").backend("ebpf").on_session(received.append).start()
    bus_sessions = []
    handle.event_bus.subscribe(SessionEvent, bus_sessions.append)

    handle.stop()

    assert [e.event_type for e in received] == [CAPTURE_STARTED, CAPTURE_STOPPED]
    assert all(isinstance(e, SessionEvent) for e in received)
    assert bus_sessions == []
