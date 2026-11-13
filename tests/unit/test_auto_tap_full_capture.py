"""``-f --tap X.tap``: the .tap is built from the finished full capture.

Covers the pure gate, the manual-command fallback, the atomic writer, the
never-raising orchestrator (logs go to a list handler: friTap loggers do not
propagate, so caplog would see nothing), the factory skipping the live tap
handler under -f, the teardown wiring, and one real-tshark end-to-end run.
"""

from __future__ import annotations

import logging
import os
import shlex
import types
from unittest.mock import MagicMock

import pytest

from friTap.config import FriTapConfig
from friTap.flow.tap_reader import TapReader
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.offline import auto_tap
from friTap.offline import tshark as tshark_mod
from friTap.offline.pcap_to_tap import NoDecryptionKeysError
from friTap.offline.pipeline_api import ConvertResult
from friTap.offline.tshark import TsharkLimitError, TsharkNotFoundError
from friTap.output.factory import OutputHandlerFactory
from friTap.output.tap_handler import TapOutputHandler

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PREMASTER_PCAP = os.path.join(_FIXTURE_DIR, "dump_premaster.pcapng")
_PREMASTER_KEYLOG = os.path.join(_FIXTURE_DIR, "premaster.txt")


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[tuple[int, str]] = []

    def emit(self, record):
        self.messages.append((record.levelno, record.getMessage()))


@pytest.fixture
def collected():
    logger = logging.getLogger("test.auto_tap")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler = _ListHandler()
    logger.addHandler(handler)
    yield logger, handler.messages
    logger.removeHandler(handler)


def _write(path, data=b"data"):
    path.write_bytes(data)
    return str(path)


# ---------------------------------------------------------------- gate ----

@pytest.mark.parametrize("full_capture, tap, aux, pcap_bytes, expected", [
    (True, "out.tap", False, b"x", True),
    (False, "out.tap", False, b"x", False),
    (True, None, False, b"x", False),
    (True, "", False, b"x", False),
    (True, "out.tap", True, b"x", False),
    (True, "out.tap", False, b"", False),
])
def test_should_auto_build_tap_matrix(tmp_path, full_capture, tap, aux, pcap_bytes, expected):
    pcap = _write(tmp_path / "cap.pcap", pcap_bytes)
    assert auto_tap.should_auto_build_tap(
        full_capture=full_capture, tap_path=tap, pcap_path=pcap,
        auxiliary_session=aux) is expected


@pytest.mark.parametrize("pcap", [None, "/no/such/cap.pcap"])
def test_should_auto_build_tap_missing_pcap(pcap):
    assert not auto_tap.should_auto_build_tap(
        full_capture=True, tap_path="out.tap", pcap_path=pcap)


# ------------------------------------------------------ manual command ----

def test_manual_command_quotes_paths_with_spaces():
    cmd = auto_tap.manual_from_pcap_command("/a b/cap.pcap", "/a b/keys.log", "/a b/o.tap")
    assert shlex.split(cmd) == ["fritap", "--from-pcap", "/a b/cap.pcap",
                                "--keylog", "/a b/keys.log", "--tap", "/a b/o.tap"]


def test_manual_command_without_keylog():
    cmd = auto_tap.manual_from_pcap_command("cap.pcap", None, "o.tap")
    assert shlex.split(cmd) == ["fritap", "--from-pcap", "cap.pcap", "--tap", "o.tap"]


# ------------------------------------------------------- atomic build -----

def _leftovers(directory):
    return [n for n in os.listdir(directory) if n.endswith(".partial")]


def test_build_tap_atomically_replaces_target(tmp_path):
    target = tmp_path / "out.tap"
    target.write_bytes(b"old")

    def convert(pcap, *, tap_path, **kwargs):
        assert tap_path != str(target) and os.path.dirname(tap_path) == str(tmp_path)
        with open(tap_path, "wb") as fh:
            fh.write(b"new")
        return ConvertResult(tap_path=tap_path, flow_count=2)

    result = auto_tap.build_tap_atomically("cap.pcap", str(target), convert=convert)
    assert target.read_bytes() == b"new" and result.flow_count == 2
    assert _leftovers(tmp_path) == []


def test_build_tap_atomically_failure_keeps_target_and_reraises(tmp_path):
    target = tmp_path / "out.tap"
    target.write_bytes(b"precious")

    def convert(pcap, *, tap_path, **kwargs):
        with open(tap_path, "wb") as fh:
            fh.write(b"half")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        auto_tap.build_tap_atomically("cap.pcap", str(target), convert=convert)
    assert target.read_bytes() == b"precious"
    assert _leftovers(tmp_path) == []


def test_build_tap_atomically_failure_creates_no_target(tmp_path):
    def convert(pcap, *, tap_path, **kwargs):
        raise ValueError("nope")

    with pytest.raises(ValueError):
        auto_tap.build_tap_atomically("cap.pcap", str(tmp_path / "o.tap"), convert=convert)
    assert os.listdir(tmp_path) == []


# ------------------------------------------------------- orchestrator -----

@pytest.mark.parametrize("error", [
    NoDecryptionKeysError("no keys"), TsharkNotFoundError("missing"),
    TsharkLimitError("too big"), OSError("disk full"),
])
def test_auto_build_tap_never_raises_and_logs_manual_command(tmp_path, collected, capsys, error):
    logger, messages = collected

    def convert(pcap, **kwargs):
        raise error

    ok = auto_tap.auto_build_tap("/x y/cap.pcap", str(tmp_path / "o.tap"),
                                 keylog_path="/x y/k.log", logger=logger, convert=convert)
    assert ok is False
    warnings = [m for lvl, m in messages if lvl == logging.WARNING]
    assert len(warnings) == 1
    assert auto_tap.manual_from_pcap_command(
        "/x y/cap.pcap", "/x y/k.log", str(tmp_path / "o.tap")) in warnings[0]
    assert str(error) in warnings[0]
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "o.tap").exists()


def test_auto_build_tap_success_logs_summary(tmp_path, collected, capsys):
    logger, messages = collected
    seen = {}

    def convert(pcap, *, tap_path, **kwargs):
        seen.update(kwargs)
        open(tap_path, "wb").close()
        return ConvertResult(tap_path=tap_path, flow_count=3, decrypted_packet_count=7)

    assert auto_tap.auto_build_tap("cap.pcap", str(tmp_path / "o.tap"), keylog_path="k.log",
                                   logger=logger, convert=convert)
    assert seen["use_manifest"] is True and seen["keylog_path"] == "k.log"
    text = " ".join(m for _, m in messages)
    assert "Building" in text and "3 flow(s)" in text and "7 decrypted" in text
    assert capsys.readouterr().out == ""


# ------------------------------------------------------------ factory -----

def _handlers_for(full_capture, collected_logger):
    config = FriTapConfig.from_legacy_params(app="x", full_capture=full_capture,
                                             pcap_name="cap.pcap" if full_capture else None)
    config.output.tap_output = "x.tap"
    handlers, _ = OutputHandlerFactory.create_handlers(
        config, MagicMock(), None, {"session_info": {}}, collected_logger)
    return handlers


def test_factory_skips_live_tap_handler_under_full_capture(collected):
    logger, messages = collected
    handlers = _handlers_for(True, logger)
    assert not any(isinstance(h, TapOutputHandler) for h in handlers)
    assert any("x.tap will be built from the full-capture" in m for _, m in messages)


def test_factory_keeps_live_tap_handler_without_full_capture(collected):
    logger, _ = collected
    assert any(isinstance(h, TapOutputHandler) for h in _handlers_for(False, logger))


# ------------------------------------------------------ teardown wiring ---

def _cleanup_shell(order, tap_output="out.tap"):
    shell = SSL_Logger.__new__(SSL_Logger)
    shell._config = types.SimpleNamespace(
        output=types.SimpleNamespace(auxiliary_session=False, tap_output=tap_output),
        device=types.SimpleNamespace(timeout=None),
        hooking=types.SimpleNamespace(library_scan=False),
        protocol="tls", target="app")
    shell.logger = MagicMock()
    shell.special_logger = MagicMock()
    for name in ("_stop_instrument_thread", "_stop_consumer_thread", "_finalize_live_scan",
                 "_release_lsass_contributor"):
        setattr(shell, name, MagicMock())
    shell.close_output_handlers = lambda: order.append("close")
    shell._auto_relabel_schannel_keylog = lambda _p: order.append("relabel")
    pcap_obj = MagicMock(apptap_session=None, capture_tier=None, pcap_file_name="cap.pcap")
    pcap_obj.full_capture_thread.is_alive.return_value = False
    pcap_obj.finalize_full_capture.side_effect = lambda *a, **k: order.append("finalize")
    pcap_obj.written_keylog_path.return_value = "keys.log"
    shell.pcap_obj = pcap_obj
    shell._handlers_active = True
    shell._output_handlers = []
    shell.traced_scapy_socket_Set = set()
    shell.traced_Socket_Set = set()
    shell._done_event = MagicMock()
    shell._done_event.set.side_effect = lambda: order.append("done")
    shell.process = None
    return shell


def test_cleanup_builds_tap_after_relabel_before_done(monkeypatch):
    order, calls = [], []
    monkeypatch.setattr(auto_tap, "should_auto_build_tap", lambda **kw: True)
    monkeypatch.setattr(auto_tap, "auto_build_tap",
                        lambda pcap, tap, **kw: (order.append("auto_tap"),
                                                 calls.append((pcap, tap, kw))))
    _cleanup_shell(order)._run_cleanup_steps(full_capture=True)
    assert order == ["close", "finalize", "relabel", "auto_tap", "done"]
    pcap, tap, kwargs = calls[0]
    assert (pcap, tap, kwargs["keylog_path"], kwargs["capture_target"]) == \
        ("cap.pcap", "out.tap", "keys.log", "app")


def test_cleanup_auto_tap_failure_does_not_break_teardown(monkeypatch):
    order = []
    monkeypatch.setattr(auto_tap, "should_auto_build_tap", lambda **kw: True)

    def explode(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(auto_tap, "auto_build_tap", explode)
    _cleanup_shell(order)._run_cleanup_steps(full_capture=True)
    assert order[-1] == "done"


def test_cleanup_without_tap_skips_auto_build(monkeypatch):
    order = []
    monkeypatch.setattr(auto_tap, "auto_build_tap", lambda *a, **k: order.append("auto_tap"))
    _cleanup_shell(order, tap_output=None)._run_cleanup_steps(full_capture=True)
    assert "auto_tap" not in order and order[-1] == "done"


# ------------------------------------------------------ real end-to-end ---

def _real_tshark_available() -> bool:
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return os.path.isfile(_PREMASTER_PCAP) and os.path.isfile(_PREMASTER_KEYLOG)


@pytest.mark.skipif(not _real_tshark_available(), reason="tshark or premaster fixture missing")
def test_auto_build_tap_real_capture(tmp_path, collected, capsys):
    logger, _ = collected
    tap = tmp_path / "dir with space" / "auto.tap"
    tap.parent.mkdir()
    assert auto_tap.auto_build_tap(_PREMASTER_PCAP, str(tap), keylog_path=_PREMASTER_KEYLOG,
                                   logger=logger)
    with TapReader(str(tap)) as reader:
        assert reader.flow_count > 0
    assert _leftovers(tap.parent) == []
    assert capsys.readouterr().out == ""
