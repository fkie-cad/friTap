"""SSL_Logger._auto_relabel_schannel_keylog: overwrite-with-backup, tshark hint, no-op.

The helper trial-decrypts a Windows SChannel keylog against the full capture at
teardown and overwrites it with the corrected version (raw kept as <stem>.raw.keylog).
tshark, the relabel engine and the Windows check are stubbed here; this exercises only
the finalization wiring.
"""

from __future__ import annotations

import os
import types
from unittest.mock import MagicMock

import pytest

from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.offline.keylog_coverage import RepairResult


def _fake_self(keylog_path, *, auto_relabel=True):
    output = types.SimpleNamespace(
        auto_relabel=auto_relabel, keylog=str(keylog_path), tshark_path=None)
    return types.SimpleNamespace(
        _config=types.SimpleNamespace(output=output),
        pcap_obj=types.SimpleNamespace(keylog_path=str(keylog_path)),
        keylog_file=None,
        logger=MagicMock(),
    )


@pytest.fixture
def paths(tmp_path):
    keylog = tmp_path / "cap.keylog"
    keylog.write_text("SERVER_TRAFFIC_SECRET_0 " + "aa" * 32 + " " + "bb" * 48 + "\n")
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00" * 64)
    return keylog, pcap, tmp_path


def _patch_env(monkeypatch, *, windows=True, tshark="tshark", relabel=None):
    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: windows)

    def fake_find(_p=None):
        if tshark is None:
            raise RuntimeError("tshark not found")
        return tshark

    monkeypatch.setattr("friTap.offline.tshark.find_tshark", fake_find)
    if relabel is not None:
        monkeypatch.setattr("friTap.offline.keylog_coverage.relabel_keylog", relabel)


def test_relabel_hit_overwrites_keylog_and_backs_up_raw(paths, monkeypatch):
    keylog, pcap, tmp_path = paths
    raw_content = keylog.read_text()
    relabeled = tmp_path / "cap.relabeled.keylog"
    corrected_content = "SERVER_HANDSHAKE_TRAFFIC_SECRET " + "aa" * 32 + " " + "bb" * 48 + "\n"
    relabeled.write_text(corrected_content)

    def fake_relabel(_tshark, _pcap, _keylog, progress=None):
        return RepairResult(str(relabeled), 1, 1, "Relabeled 1 session by trial decryption.")

    _patch_env(monkeypatch, relabel=fake_relabel)
    SSL_Logger._auto_relabel_schannel_keylog(_fake_self(keylog), str(pcap))

    # corrected content is now under the user's keylog name; raw is preserved
    assert keylog.read_text() == corrected_content
    assert (tmp_path / "cap.raw.keylog").read_text() == raw_content
    assert not relabeled.exists()  # moved into place


def test_no_tshark_prints_hint_and_leaves_files(paths, monkeypatch):
    keylog, pcap, _tmp = paths
    original = keylog.read_text()
    called = []
    _patch_env(monkeypatch, tshark=None,
               relabel=lambda *a, **k: called.append(a) or RepairResult(None, 0, 0, ""))
    fake = _fake_self(keylog)
    SSL_Logger._auto_relabel_schannel_keylog(fake, str(pcap))

    assert keylog.read_text() == original  # untouched
    assert called == []  # relabel never reached
    assert any("--repair-keylog" in str(c.args) for c in fake.logger.info.call_args_list)


def test_noop_result_leaves_keylog_untouched(paths, monkeypatch):
    keylog, pcap, tmp_path = paths
    original = keylog.read_text()
    _patch_env(monkeypatch,
               relabel=lambda *a, **k: RepairResult(None, 0, 1, "nothing to relabel"))
    SSL_Logger._auto_relabel_schannel_keylog(_fake_self(keylog), str(pcap))

    assert keylog.read_text() == original
    assert not (tmp_path / "cap.raw.keylog").exists()


def test_opt_out_skips_relabel(paths, monkeypatch):
    keylog, pcap, _tmp = paths
    called = []
    _patch_env(monkeypatch, relabel=lambda *a, **k: called.append(a))
    SSL_Logger._auto_relabel_schannel_keylog(_fake_self(keylog, auto_relabel=False), str(pcap))
    assert called == []


def test_non_windows_skips_relabel(paths, monkeypatch):
    keylog, pcap, _tmp = paths
    called = []
    _patch_env(monkeypatch, windows=False, relabel=lambda *a, **k: called.append(a))
    SSL_Logger._auto_relabel_schannel_keylog(_fake_self(keylog), str(pcap))
    assert called == []


# --- The LSASS worker's keylog handle and a held (unrenamable) keylog --------


def _relabel_hit(tmp_path):
    relabeled = tmp_path / "cap.relabeled.keylog"
    relabeled.write_text("SERVER_HANDSHAKE_TRAFFIC_SECRET " + "aa" * 32 + " " + "bb" * 48 + "\n")

    def fake_relabel(_tshark, _pcap, _keylog, progress=None):
        return RepairResult(str(relabeled), 1, 1, "Relabeled 1 session by trial decryption.")

    return relabeled, fake_relabel


def _warning_text(fake):
    return " ".join(str(c.args) for c in fake.logger.warning.call_args_list)


def test_lsass_writer_is_released_before_the_relabel(paths, monkeypatch):
    """The separate LSASS session must drop its keylog handle before the rename."""
    keylog, pcap, tmp_path = paths
    order = []
    relabeled, fake_relabel = _relabel_hit(tmp_path)

    def recording_relabel(*a, **k):
        order.append("relabel")
        return fake_relabel(*a, **k)

    _patch_env(monkeypatch, relabel=recording_relabel)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: order.append("release"))
    SSL_Logger._auto_relabel_schannel_keylog(_fake_self(keylog), str(pcap))

    assert order == ["release", "relabel"]


def test_release_lsass_keylog_writer_stops_the_lsass_hook(monkeypatch):
    import friTap.friTap as fritap
    from friTap.legacy.ssl_logger_core import _release_lsass_keylog_writer
    calls = []
    monkeypatch.setattr(fritap, "cleanup_lsass_hook", lambda: calls.append(1))
    _release_lsass_keylog_writer(MagicMock())
    assert calls == [1]


def test_release_lsass_keylog_writer_never_raises(monkeypatch):
    import friTap.friTap as fritap
    from friTap.legacy.ssl_logger_core import _release_lsass_keylog_writer

    def boom():
        raise RuntimeError("lsass teardown failed")

    monkeypatch.setattr(fritap, "cleanup_lsass_hook", boom)
    _release_lsass_keylog_writer(MagicMock())  # must not raise


def test_held_keylog_permission_error_keeps_original_and_warns(paths, monkeypatch):
    """Windows: renaming a keylog another handle holds open raises PermissionError."""
    keylog, pcap, tmp_path = paths
    original = keylog.read_text()
    relabeled, fake_relabel = _relabel_hit(tmp_path)
    _patch_env(monkeypatch, relabel=fake_relabel)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: None)

    def held_replace(src, dst):
        raise PermissionError(32, "The process cannot access the file", src)

    monkeypatch.setattr("friTap.legacy.ssl_logger_core.os.replace", held_replace)
    fake = _fake_self(keylog)
    SSL_Logger._auto_relabel_schannel_keylog(fake, str(pcap))

    assert keylog.read_text() == original
    assert not (tmp_path / "cap.raw.keylog").exists()
    assert relabeled.exists()  # the fixed copy is kept for the user
    warning = _warning_text(fake)
    assert "--repair-keylog" in warning and str(relabeled) in warning
    fake.logger.info.assert_not_called()  # no false "relabeled" success line


def test_failed_second_rename_restores_original(paths, monkeypatch):
    keylog, pcap, tmp_path = paths
    original = keylog.read_text()
    relabeled, fake_relabel = _relabel_hit(tmp_path)
    _patch_env(monkeypatch, relabel=fake_relabel)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: None)
    real_replace = os.replace

    def replace_fails_for_relabeled(src, dst):
        if str(src) == str(relabeled):
            raise PermissionError(32, "in use", src)
        return real_replace(src, dst)

    monkeypatch.setattr("friTap.legacy.ssl_logger_core.os.replace", replace_fails_for_relabeled)
    fake = _fake_self(keylog)
    SSL_Logger._auto_relabel_schannel_keylog(fake, str(pcap))

    assert keylog.read_text() == original
    assert not (tmp_path / "cap.raw.keylog").exists()
    assert "--repair-keylog" in _warning_text(fake)
