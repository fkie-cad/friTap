"""The Windows LSASS helper session must not clobber the target session's outputs.

``hook_lsass`` (friTap.py) builds a second SSL_Logger for lsass.exe with the
SAME ``-p`` and ``--json`` paths as the target session. Each session used to
open those paths privately (``"wb"``/``"w"``), so the later opener truncated
the earlier one's output, the two file offsets overwrote each other's records,
and in full-capture mode (-f) the LSASS session held the ``-p`` file open as a
plaintext pcap, so the target session's finalize (``os.replace`` of the temp
capture, refused by Windows for an open destination) failed.

Now: the LSASS session is marked ``auxiliary_session``; plaintext pcap/pcapng,
JSON and JSONL outputs are process-wide shared per path; in full-capture mode
the LSASS session gets no pcap at all; and the target session's teardown
releases the LSASS session before completing its own outputs.
Frida-free: real SSL_Loggers are constructed without a device.
"""

from __future__ import annotations

import json
import struct
import types
from unittest.mock import MagicMock

import pytest

import friTap.friTap as fritap
from friTap.config import FriTapConfig
from friTap.events import DatalogEvent, KeylogEvent
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output import shared_keylog_writer as keylog_registry
from friTap.output import shared_output_file as output_registry
from friTap.output.json_handler import JsonOutputHandler
from friTap.pcap import _write_pcap_record

LSASS_PID = 684
_PCAP_GLOBAL_HEADER_LEN = 24
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_EPB = 0x00000006


@pytest.fixture(autouse=True)
def _no_leaked_shared_files(tmp_path):
    yield
    leaked = [p for p in keylog_registry.open_keylog_paths() if str(tmp_path) in p]
    leaked += [p for p in list(output_registry._registry) if str(tmp_path) in p]
    assert not leaked, f"shared files left open: {leaked}"


def _lsass_config(tmp_path, *, full_capture=False, pcap="cap.pcap", json_name="out.json"):
    return fritap._build_lsass_config(
        LSASS_PID, pcap_name=str(tmp_path / pcap), verbose=False,
        keylog=str(tmp_path / "keys.log"), live=False, debug_mode=False, host=False,
        debug_output=False, enable_default_fd=False, patterns=None,
        custom_hook_script=None, json_output=str(tmp_path / json_name),
        full_capture=full_capture)


def _main_config(tmp_path, *, pcap="cap.pcap", json_name="out.json"):
    return FriTapConfig.from_legacy_params(
        app="target.exe", pcap_name=str(tmp_path / pcap),
        keylog=str(tmp_path / "keys.log"), json_output=str(tmp_path / json_name),
        install_lsass_hook=False)


def _sessions(tmp_path, **names):
    """LSASS first, then the target session: the CLI's construction order."""
    lsass = SSL_Logger(config=_lsass_config(tmp_path, **names))
    main = SSL_Logger(config=_main_config(tmp_path, **names))
    return main, lsass


def _datalog(payload, port):
    return DatalogEvent(data=payload, function="SSL_write", src_addr="10.0.0.1",
                        src_port=port, dst_addr="10.0.0.2", dst_port=443,
                        src_addr_raw=0x0A000001, dst_addr_raw=0x0A000002)


def _emit(logger, *events):
    for event in events:
        logger._event_bus.emit(event)


def _close_in_cli_order(main, lsass):
    lsass.close_output_handlers()  # _release_lsass_contributor runs first
    main.close_output_handlers()


def _pcap_payloads(raw):
    """Payloads of a classic LINKTYPE_RAW pcap written by PCAP (IPv4+TCP, 40B)."""
    assert struct.unpack("=I", raw[:4])[0] == 0xA1B2C3D4
    payloads, offset = [], _PCAP_GLOBAL_HEADER_LEN
    while offset < len(raw):
        incl_len = struct.unpack("=I", raw[offset + 8:offset + 12])[0]
        record = raw[offset + 16:offset + 16 + incl_len]
        assert len(record) == incl_len, "truncated record"
        payloads.append(record[40:])
        offset += 16 + incl_len
    return payloads


def _pcapng_blocks(raw):
    blocks, offset = [], 0
    while offset < len(raw):
        block_type, length = struct.unpack("<II", raw[offset:offset + 8])
        assert struct.unpack("<I", raw[offset + length - 4:offset + length])[0] == length
        blocks.append((block_type, raw[offset:offset + length]))
        offset += length
    return blocks


# ---------------------------------------------------------------------------
# LSASS session config
# ---------------------------------------------------------------------------

def test_lsass_config_is_an_auxiliary_contributor(tmp_path):
    config = _lsass_config(tmp_path)
    assert config.output.auxiliary_session is True
    assert config.output.full_capture is False
    assert config.output.pcap == str(tmp_path / "cap.pcap")
    assert config.install_lsass_hook is True


def test_lsass_gets_no_pcap_when_the_target_runs_a_full_capture(tmp_path):
    config = _lsass_config(tmp_path, full_capture=True)
    assert config.output.pcap is None
    assert config.output.keylog == str(tmp_path / "keys.log")  # still contributes keys


def test_target_session_config_is_not_auxiliary(tmp_path):
    assert _main_config(tmp_path).output.auxiliary_session is False


def test_lsass_worker_builds_its_logger_from_the_auxiliary_config(tmp_path, monkeypatch):
    """start_lsass_hook forwards full_capture into the LSASS config it builds."""
    built = []

    class _StopAfterBuild(Exception):
        pass

    def _fake_logger(config):
        built.append(config)
        raise _StopAfterBuild

    monkeypatch.setattr(fritap.sys, "platform", "win32")
    monkeypatch.setattr(fritap, "get_pid_of_lsass", lambda: LSASS_PID)
    monkeypatch.setattr(fritap, "SSL_Logger", _fake_logger)
    monkeypatch.setattr(fritap.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fritap.traceback, "print_exc", lambda: None)
    manager = fritap.LsassHookManager()
    manager.start_lsass_hook(pcap_name=str(tmp_path / "cap.pcap"), full_capture=True)
    manager.lsass_thread.join(timeout=5)

    assert not manager.lsass_thread.is_alive()
    assert len(built) == 1
    assert built[0].output.auxiliary_session is True
    assert built[0].output.pcap is None


def test_full_capture_lsass_session_never_touches_the_pcap(tmp_path):
    lsass = SSL_Logger(config=_lsass_config(tmp_path, full_capture=True))
    try:
        assert lsass.pcap_obj is None
        assert not (tmp_path / "cap.pcap").exists()
        assert not output_registry.is_output_path_open(str(tmp_path / "cap.pcap"))
        assert lsass._build_config_batch()["pcap_enabled"] is False
    finally:
        lsass.close_output_handlers()


# ---------------------------------------------------------------------------
# Plaintext pcap / pcapng: one file, both sessions' packets
# ---------------------------------------------------------------------------

def test_plaintext_pcap_holds_both_sessions_packets(tmp_path):
    main, lsass = _sessions(tmp_path)
    _emit(lsass, _datalog(b"lsass-early", 1001))
    _emit(main, _datalog(b"target-data", 1002))
    _emit(lsass, _datalog(b"lsass-late", 1003))
    _close_in_cli_order(main, lsass)

    payloads = _pcap_payloads((tmp_path / "cap.pcap").read_bytes())
    assert payloads == [b"lsass-early", b"target-data", b"lsass-late"]


def test_plaintext_pcapng_holds_both_sessions_packets(tmp_path):
    main, lsass = _sessions(tmp_path, pcap="cap.pcapng")
    _emit(lsass, _datalog(b"lsass-data", 1001))
    _emit(main, _datalog(b"target-data", 1002))
    _close_in_cli_order(main, lsass)

    blocks = _pcapng_blocks((tmp_path / "cap.pcapng").read_bytes())
    assert [b for b, _ in blocks].count(_PCAPNG_SHB) == 1
    assert blocks[0][0] == _PCAPNG_SHB
    packets = [raw for block, raw in blocks if block == _PCAPNG_EPB]
    assert len(packets) == 2
    assert b"lsass-data" in packets[0] and b"target-data" in packets[1]


def test_shared_pcap_stays_open_until_the_last_session_releases(tmp_path):
    main, lsass = _sessions(tmp_path)
    path = str(tmp_path / "cap.pcap")
    lsass.close_output_handlers()
    assert output_registry.is_output_path_open(path)
    _emit(main, _datalog(b"after-lsass-left", 1002))
    main.close_output_handlers()
    assert not output_registry.is_output_path_open(path)
    assert _pcap_payloads((tmp_path / "cap.pcap").read_bytes()) == [b"after-lsass-left"]


def test_pcap_record_is_written_in_one_call_with_the_legacy_bytes():
    fields = (("=I", 7), (">H", 443), (">B", 6))
    sink = MagicMock()
    _write_pcap_record(sink, fields, b"data")
    sink.write.assert_called_once_with(
        struct.pack("=I", 7) + struct.pack(">H", 443) + struct.pack(">B", 6) + b"data")


# ---------------------------------------------------------------------------
# JSON / JSONL: one valid document / stream holding both sessions
# ---------------------------------------------------------------------------

def test_json_is_one_valid_document_with_both_sessions(tmp_path):
    main, lsass = _sessions(tmp_path)
    _emit(lsass, KeylogEvent(key_data="CLIENT_RANDOM aa bb"), _datalog(b"x" * 5, 1001))
    _emit(main, KeylogEvent(key_data="CLIENT_RANDOM cc dd"), _datalog(b"y" * 7, 1002))
    _close_in_cli_order(main, lsass)

    doc = json.loads((tmp_path / "out.json").read_text())
    assert doc["session_info"]["target_app"] == "target.exe"
    assert "end_time" in doc["session_info"]
    assert [s["target_app"] for s in doc["auxiliary_sessions"]] == [str(LSASS_PID)]
    assert {k["key_data"] for k in doc["key_extractions"]} == {
        "CLIENT_RANDOM aa bb", "CLIENT_RANDOM cc dd"}
    assert doc["statistics"]["total_connections"] == 2
    assert doc["statistics"]["total_bytes_captured"] == 12


def test_json_is_valid_even_if_the_lsass_session_is_never_released(tmp_path):
    main, lsass = _sessions(tmp_path)
    _emit(lsass, KeylogEvent(key_data="CLIENT_RANDOM aa bb"))
    _emit(main, KeylogEvent(key_data="CLIENT_RANDOM cc dd"))
    main.close_output_handlers()  # e.g. os._exit before the LSASS release

    doc = json.loads((tmp_path / "out.json").read_text())
    assert len(doc["key_extractions"]) == 2
    lsass.close_output_handlers()  # completes the document and frees the path
    assert len(json.loads((tmp_path / "out.json").read_text())["key_extractions"]) == 2


def test_jsonl_holds_both_sessions_lines(tmp_path):
    main, lsass = _sessions(tmp_path, json_name="out.jsonl")
    _emit(lsass, KeylogEvent(key_data="CLIENT_RANDOM aa bb"))
    _emit(main, KeylogEvent(key_data="CLIENT_RANDOM cc dd"))
    _emit(lsass, KeylogEvent(key_data="CLIENT_RANDOM ee ff"))
    _close_in_cli_order(main, lsass)

    records = [json.loads(line) for line in
               (tmp_path / "out.jsonl").read_text().splitlines()]
    keys = [r["key_data"] for r in records if r["event_type"] == "KeylogEvent"]
    assert keys == ["CLIENT_RANDOM aa bb", "CLIENT_RANDOM cc dd", "CLIENT_RANDOM ee ff"]


def test_single_session_json_document_is_unchanged(tmp_path):
    """No LSASS: same keys, same order, no auxiliary entry, as before the change."""
    path = tmp_path / "solo.json"
    handler = JsonOutputHandler(str(path), session_info={"target_app": "solo"})
    handler.setup(MagicMock())
    handler.on_keylog(KeylogEvent(key_data="CLIENT_RANDOM aa bb"))
    handler.close()

    doc = json.loads(path.read_text())
    assert list(doc) == ["session_info", "ssl_sessions", "connections",
                         "key_extractions", "errors", "libraries_detected", "statistics"]
    assert path.read_text() == json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Teardown: LSASS released before the target completes its outputs
# ---------------------------------------------------------------------------

def _cleanup_shell(order, *, auxiliary=False, full_capture=True):
    shell = SSL_Logger.__new__(SSL_Logger)
    shell._config = types.SimpleNamespace(
        output=types.SimpleNamespace(auxiliary_session=auxiliary),
        device=types.SimpleNamespace(timeout=None),
        hooking=types.SimpleNamespace(library_scan=False),
        protocol="tls")
    shell.logger = MagicMock()
    shell.special_logger = MagicMock()
    for name in ("_stop_instrument_thread", "_stop_consumer_thread", "_finalize_live_scan"):
        setattr(shell, name, MagicMock())
    shell.close_output_handlers = lambda: order.append("close_own_handlers")
    shell._auto_relabel_schannel_keylog = lambda _p: order.append("relabel")
    pcap_obj = MagicMock(apptap_session=None, capture_tier=None, pcap_file_name="cap.pcap")
    pcap_obj.full_capture_thread.is_alive.return_value = False
    pcap_obj.finalize_full_capture.side_effect = lambda *a, **k: order.append("finalize")
    shell.pcap_obj = pcap_obj if full_capture else None
    shell._handlers_active = True
    shell._output_handlers = []
    shell.traced_scapy_socket_Set = set()
    shell.traced_Socket_Set = set()
    shell._done_event = MagicMock()
    shell.process = None
    return shell


def test_target_teardown_releases_lsass_before_closing_and_finalizing(monkeypatch):
    order = []
    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: True)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: order.append("release_lsass"))
    shell = _cleanup_shell(order)
    shell._run_cleanup_steps(full_capture=True)

    assert order == ["release_lsass", "close_own_handlers", "finalize", "relabel"]
    shell.pcap_obj.finalize_full_capture.assert_called_once()


def test_lsass_session_teardown_does_not_release_itself(monkeypatch):
    order = []
    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: True)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: order.append("release_lsass"))
    _cleanup_shell(order, auxiliary=True, full_capture=False)._run_cleanup_steps()
    assert order == ["close_own_handlers"]


def test_teardown_off_windows_never_touches_lsass(monkeypatch):
    order = []
    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: False)
    monkeypatch.setattr("friTap.legacy.ssl_logger_core._release_lsass_keylog_writer",
                        lambda _logger: order.append("release_lsass"))
    _cleanup_shell(order, full_capture=False)._run_cleanup_steps()
    assert order == ["close_own_handlers"]


def test_cleanup_releases_the_real_lsass_session_outputs(tmp_path, monkeypatch):
    """End to end: the LSASS manager's logger is closed by the target's release."""
    main, lsass = _sessions(tmp_path)
    manager = fritap.LsassHookManager()
    manager.lsass_logger, manager.running = lsass, False
    monkeypatch.setattr(fritap, "_lsass_hook_manager", manager)
    monkeypatch.setattr("friTap.fritap_utility.are_we_running_on_windows", lambda: True)
    _emit(lsass, KeylogEvent(key_data="CLIENT_RANDOM aa bb"))

    main._release_lsass_contributor()
    assert lsass._output_handlers_closed is True
    main.close_output_handlers()
    doc = json.loads((tmp_path / "out.json").read_text())
    assert [k["key_data"] for k in doc["key_extractions"]] == ["CLIENT_RANDOM aa bb"]
