"""The managed local full-capture worker (eBPF -f): one AsyncSniffer, readiness, idempotent cleanup."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from friTap import pcap_full_capture
from friTap.pcap_full_capture import FullCaptureThread


class FakeAsyncSniffer:
    """Stands in for scapy's AsyncSniffer: a real thread that 'sniffs' until stopped."""

    instances = []

    def __init__(self, fail_before_start=None, fail_while_running=None, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self._stop = threading.Event()
        self._fail_before_start = fail_before_start
        self._fail_while_running = fail_while_running
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.stop_calls = 0
        FakeAsyncSniffer.instances.append(self)

    def _run(self):
        if self._fail_before_start is not None:
            self.exception = self._fail_before_start
            return
        self.running = True
        self.kwargs["started_callback"]()
        self._stop.wait()
        self.running = False
        if self._fail_while_running is not None:
            self.exception = self._fail_while_running

    def start(self):
        self.thread.start()

    def stop(self, join=True):
        self.stop_calls += 1
        self._stop.set()

    def join(self, *args):
        self.thread.join(*args)
        if self.exception is not None:
            raise self.exception


@pytest.fixture
def sniffer_factory(monkeypatch):
    FakeAsyncSniffer.instances = []
    options = {}

    def factory(**kwargs):
        return FakeAsyncSniffer(**options, **kwargs)

    monkeypatch.setattr(pcap_full_capture, "_async_sniffer_class", lambda: factory)
    return options


@pytest.fixture
def pcap_module(monkeypatch):
    module = SimpleNamespace(
        conf=SimpleNamespace(L2listen=MagicMock(return_value=MagicMock(name="socket"))),
        ETH_P_ALL=3, Scapy_Exception=type("Scapy_Exception", (Exception,), {}),
        build_capture_bpf=lambda **kw: "tcp", sniff=MagicMock(name="sniff"),
        _libpcap_hint=lambda: "hint", temp_capture_path=lambda name: "_" + name,
    )
    monkeypatch.setattr(pcap_full_capture, "_pcap", lambda: module)
    return module


def _thread(managed=True):
    owner = SimpleNamespace(pcap_file_name="cap.pcap", is_Mobile=False, logger=MagicMock(),
                            include_loopback=False, filter_infrastructure=True)
    thread = FullCaptureThread(owner)
    thread.managed_local = managed
    return thread


def test_managed_worker_runs_one_sniffer_until_join(sniffer_factory, pcap_module):
    thread = _thread()
    thread.start()
    thread.wait_until_ready(2)
    thread.join(2)

    assert not thread.is_alive()
    assert thread.failure is None
    (sniffer,) = FakeAsyncSniffer.instances
    assert sniffer.kwargs["store"] is False
    assert sniffer.kwargs["filter"] == "tcp"
    assert "stop_filter" not in sniffer.kwargs
    assert sniffer.stop_calls == 1
    # Queued packets are drained once from the still-open socket.
    pcap_module.sniff.assert_called_once()
    assert pcap_module.sniff.call_args.kwargs["timeout"] == pcap_full_capture._DRAIN_TIMEOUT_SECONDS
    thread.socket.close.assert_called_once()


def test_wait_until_ready_reports_startup_failure(sniffer_factory, pcap_module):
    sniffer_factory["fail_before_start"] = PermissionError("no capture permission")
    thread = _thread()
    thread.start()
    with pytest.raises(RuntimeError, match="no capture permission"):
        thread.wait_until_ready(2)
    thread.join(2)
    assert isinstance(thread.failure, PermissionError)
    pcap_module.sniff.assert_not_called()


def test_wait_until_ready_times_out(sniffer_factory, pcap_module):
    thread = _thread()  # never started
    with pytest.raises(RuntimeError, match="timed out"):
        thread.wait_until_ready(0.01)


def test_failure_while_sniffing_is_recorded_at_stop(sniffer_factory, pcap_module):
    sniffer_factory["fail_while_running"] = OSError("interface went away")
    thread = _thread()
    thread.start()
    thread.wait_until_ready(2)
    thread.join(2)
    assert isinstance(thread.failure, OSError)


def test_cleanup_is_idempotent_on_teardown_type_error(sniffer_factory, pcap_module):
    sniffer_factory["fail_while_running"] = TypeError("fileno() is None")
    thread = _thread()
    thread.start()
    thread.wait_until_ready(2)
    thread.join(2)

    # TypeError path cleaned up, then run()'s finally ran cleanup again: one close only.
    assert thread.failure is None
    thread.socket.close.assert_called_once()
    cleanup_logs = [c for c in thread.pcap.logger.info.call_args_list
                    if c.args and "Cleaning up" in c.args[0]]
    assert len(cleanup_logs) == 1


def test_clean_up_and_exit_runs_once():
    thread = _thread(managed=False)
    thread.socket = MagicMock()
    thread.clean_up_and_exit()
    thread.clean_up_and_exit()
    thread.socket.close.assert_called_once()


def test_unmanaged_path_keeps_single_blocking_sniff(sniffer_factory, pcap_module):
    thread = _thread(managed=False)
    thread.full_local_capture()

    assert FakeAsyncSniffer.instances == []
    pcap_module.sniff.assert_called_once()
    kwargs = pcap_module.sniff.call_args.kwargs
    assert kwargs["stop_filter"] == thread.stop_capture_thread
    assert "timeout" not in kwargs and "started_callback" not in kwargs


def test_stop_sniffer_tolerates_sniffer_that_already_finished():
    sniffer = MagicMock(running=False)
    sniffer.thread.is_alive.return_value = False
    FullCaptureThread._stop_sniffer(sniffer)
    sniffer.stop.assert_not_called()
    sniffer.join.assert_called_once_with(0)


def test_request_sniffer_stop_swallows_race_with_natural_exit():
    sniffer = MagicMock(running=True)

    def stop(join):
        sniffer.running = False
        raise RuntimeError("Not running")

    sniffer.stop.side_effect = stop
    FullCaptureThread._request_sniffer_stop(sniffer)  # no raise
