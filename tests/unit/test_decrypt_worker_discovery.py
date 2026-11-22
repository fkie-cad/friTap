"""The viewer's decrypt worker triggers offline-decryptor discovery (task 6.6)."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("textual")

from friTap.tui.screens.viewer_mixins.decrypt import DecryptMixin  # noqa: E402


def _stub_host():
    host = MagicMock()
    host._zero_flow_coverage = MagicMock(return_value=None)
    return host


def _patch_worker(monkeypatch, calls):
    import textual.worker as tw
    import friTap.offline.pcap_to_tap as p2t

    monkeypatch.setattr(
        tw, "get_current_worker", lambda: SimpleNamespace(is_cancelled=False)
    )

    def fake(**kwargs):
        calls.append("convert")
        return SimpleNamespace()

    monkeypatch.setattr(p2t, "pcap_to_tap", fake)


def test_worker_discovers_once_before_converting(monkeypatch):
    import friTap.offline.discovery as disc

    calls: list = []
    monkeypatch.setattr(
        disc, "discover_external_offline_decryptors",
        lambda *a, **k: calls.append("discover") or {},
    )
    _patch_worker(monkeypatch, calls)
    DecryptMixin._decrypt_worker(_stub_host(), {"tap_path": "x.tap"})
    assert calls == ["discover", "convert"]


def test_discovery_failure_does_not_break_decrypt(monkeypatch):
    import friTap.offline.discovery as disc

    def boom(*a, **k):
        raise RuntimeError("bad plugin")

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", boom)
    calls: list = []
    _patch_worker(monkeypatch, calls)
    host = _stub_host()
    DecryptMixin._decrypt_worker(host, {"tap_path": "x.tap"})
    assert calls == ["convert"]
    host._on_decrypt_error.assert_not_called()


class _ThreadedHost(DecryptMixin):
    """Minimal DecryptMixin host: thread workers run (and are joined) for real."""

    def __init__(self):
        self.app = SimpleNamespace(call_from_thread=lambda fn, *a: fn(*a))
        self._alert = MagicMock()
        self._launch_decrypt_worker = MagicMock()
        self._is_live_screen = lambda: True

    def run_worker(self, work, **kwargs):
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()


def test_start_decrypt_discovers_in_a_worker_before_the_registry_read(
    monkeypatch, tmp_path
):
    """_build_convert_args no longer discovers (it runs on the UI thread):
    start_decrypt_to_flow discovers in a thread worker, THEN reads the registry."""
    import friTap.offline.discovery as disc
    import friTap.offline.registry as reg

    order: list = []
    monkeypatch.setattr(
        disc, "discover_external_offline_decryptors",
        lambda *a, **k: order.append(("discover", threading.current_thread())) or {},
    )

    def fake_registry():
        order.append(("registry", threading.current_thread()))
        return SimpleNamespace(list=lambda: [])

    monkeypatch.setattr(reg, "get_offline_decryptor_registry", fake_registry)
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    host = _ThreadedHost()
    host.start_decrypt_to_flow(str(pcap), "")
    assert [step for step, _ in order[:2]] == ["discover", "registry"]
    assert order[0][1] is not threading.main_thread()
    host._launch_decrypt_worker.assert_called_once()


def test_continuation_skipped_when_screen_removed_during_discovery(monkeypatch):
    import friTap.offline.discovery as disc

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", lambda *a, **k: {})
    host = _ThreadedHost()
    host._is_live_screen = lambda: False
    continuation = MagicMock()
    host._after_decryptor_discovery(continuation)
    continuation.assert_not_called()


def test_build_convert_args_itself_does_not_discover(monkeypatch, tmp_path):
    """The registry read stays in _build_convert_args; discovery moved out."""
    import friTap.offline.discovery as disc

    called: list = []
    monkeypatch.setattr(
        disc, "discover_external_offline_decryptors",
        lambda *a, **k: called.append(1) or {},
    )
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    DecryptMixin._build_convert_args(
        MagicMock(), pcap=str(pcap), keylog="", proto_keylog="", protocol="tls", tap=""
    )
    assert called == []


def test_discovery_runs_before_registry_read_in_build_convert_args(
    monkeypatch, tmp_path
):
    import friTap.offline.discovery as disc
    import friTap.offline.registry as reg

    order: list = []
    monkeypatch.setattr(
        disc, "discover_external_offline_decryptors",
        lambda *a, **k: order.append("discover") or {},
    )

    def fake_registry():
        order.append("registry")
        return SimpleNamespace(list=lambda: [])

    monkeypatch.setattr(reg, "get_offline_decryptor_registry", fake_registry)
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    host = _ThreadedHost()
    host.start_decrypt_to_flow(str(pcap), "")
    assert order[:2] == ["discover", "registry"]
