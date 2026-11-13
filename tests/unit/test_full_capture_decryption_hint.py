"""Message selection for the full-capture decryption hint (session_manager)."""
from __future__ import annotations

import pytest

from friTap.legacy.session_manager import full_capture_decryption_hint


@pytest.mark.parametrize("name", ["out.pcapng", "out.bin", "out.pcap"])
def test_pcapng_output_says_keys_are_embedded(name):
    hint = full_capture_decryption_hint(name, "pcapng", "keys.log")
    assert "embeds the captured keys" in hint
    assert "decrypts it directly" in hint
    assert "keys.log" not in hint


@pytest.mark.parametrize("name", ["out.pcap", "out.bin", "out.pcapng"])
def test_pcap_output_points_at_the_keylog(name):
    hint = full_capture_decryption_hint(name, "pcap", "keys.log")
    assert "only encrypted TLS traffic" in hint
    assert "keylog file keys.log" in hint


def test_pcap_output_without_keylog_suggests_how_to_keep_keys():
    hint = full_capture_decryption_hint("out.pcap", "pcap", None)
    assert "no keylog file was written" in hint
    assert "-k" in hint and ".pcapng" in hint


# --- Regression: the hint must follow the keylog that was REALLY written ---
# KeylogOutputHandler opens its file lazily on the first key, so the
# ``SSL_Logger.keylog_file`` snapshot taken at setup stays None. The hint used
# to read that snapshot and claim "no keylog file was written" for a populated
# -k keylog. It now asks PCAP.written_keylog_path(), the manifest's own rule.

import logging  # noqa: E402
import types  # noqa: E402

from friTap.events import EventBus, KeylogEvent  # noqa: E402
from friTap.legacy.session_manager import SessionManager  # noqa: E402
from friTap.output import KeylogOutputHandler  # noqa: E402
from friTap.pcap import PCAP  # noqa: E402
from friTap.protocols.tls_handler import TlsKeylogFormatter  # noqa: E402

_KEY_LINE = "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _bare_pcap(keylog_path=None, pcap_name="out.pcap"):
    pcap = PCAP.__new__(PCAP)
    pcap.pcap_file_name = pcap_name
    pcap.pcap_container = "pcap"
    pcap.keylog_path = keylog_path
    pcap.base_keylog_path = None
    pcap.active_keylogs = {}
    return pcap


def _staged_hint(tmp_path, pcap_obj, keylog=None):
    """Run _log_full_capture_staged with a stub logger whose snapshot is None."""
    staged = tmp_path / "staged.pcap"
    staged.write_bytes(b"\0")
    manager = SessionManager(
        types.SimpleNamespace(pcap_obj=pcap_obj, keylog_file=None, keylog=keylog))
    collector = _ListHandler()
    session_logger = logging.getLogger("friTap.session")
    previous_level = session_logger.level
    session_logger.setLevel(logging.INFO)
    session_logger.addHandler(collector)
    try:
        manager._log_full_capture_staged(str(staged), is_mobile=False)
    finally:
        session_logger.removeHandler(collector)
        session_logger.setLevel(previous_level)
    return "\n".join(collector.messages)


def test_written_keylog_path_missing_file_is_none(tmp_path):
    assert _bare_pcap(str(tmp_path / "absent.log")).written_keylog_path() is None


def test_written_keylog_path_empty_file_is_none(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert _bare_pcap(str(empty)).written_keylog_path() is None


def test_written_keylog_path_non_empty_file_is_returned(tmp_path):
    keys = tmp_path / "keys.log"
    keys.write_text(_KEY_LINE + "\n")
    assert _bare_pcap(str(keys)).written_keylog_path() == str(keys)


def test_written_keylog_path_prefers_tls_split_then_base(tmp_path):
    split, base = tmp_path / "keys.tls.log", tmp_path / "keys.log"
    base.write_text(_KEY_LINE + "\n")
    pcap = _bare_pcap(str(tmp_path / "keys.signal.log"))
    pcap.active_keylogs = {"tls": str(split)}
    pcap.base_keylog_path = str(base)
    assert pcap.written_keylog_path() == str(base)  # split never written
    split.write_text(_KEY_LINE + "\n")
    assert pcap.written_keylog_path() == str(split)


def test_staged_hint_points_at_written_keylog_despite_none_snapshot(tmp_path):
    keys = tmp_path / "keys.log"
    keys.write_text(_KEY_LINE + "\n")
    hint = _staged_hint(tmp_path, _bare_pcap(str(keys)))
    assert f"load the keylog file {keys}" in hint
    assert "no keylog file was written" not in hint


@pytest.mark.parametrize("content", [None, ""])
def test_staged_hint_without_written_keylog_says_none_was_written(tmp_path, content):
    keys = tmp_path / "keys.log"
    if content is not None:
        keys.write_text(content)
    hint = _staged_hint(tmp_path, _bare_pcap(str(keys)), keylog=str(keys))
    assert "no keylog file was written" in hint


def test_staged_hint_falls_back_to_live_keylog_option(tmp_path):
    keys = tmp_path / "keys.log"
    keys.write_text(_KEY_LINE + "\n")
    hint = _staged_hint(tmp_path, _bare_pcap(None), keylog=str(keys))
    assert f"load the keylog file {keys}" in hint


def test_real_handler_lazy_open_is_seen_by_written_keylog_path(tmp_path):
    keys = tmp_path / "keys.log"
    handler = KeylogOutputHandler(str(keys), formatter=TlsKeylogFormatter())
    bus = EventBus()
    handler.setup(bus)
    snapshot = handler._file  # what SSL_Logger stores as keylog_file
    pcap = _bare_pcap(handler._path)
    assert snapshot is None
    assert pcap.written_keylog_path() is None
    try:
        bus.emit(KeylogEvent(key_data=_KEY_LINE))
    finally:
        handler.close()
    assert pcap.written_keylog_path() == str(keys)
    assert f"load the keylog file {keys}" in _staged_hint(tmp_path, pcap)
