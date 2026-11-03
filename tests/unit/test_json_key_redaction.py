#!/usr/bin/env python3

"""JSON outputs carry raw key material only on opt-in (``-k`` / ``--json-keys``).

``-j file.json``, ``-j file.jsonl`` and ``-j -`` share one policy
(:mod:`friTap.output.key_material`): without ``-k`` or ``--json-keys`` every
keylog record is kept but redacted to its label (and the public client_random
of NSS lines) with ``"redacted": true``. JSON output is often handed to AI
agents, so the secret bytes must not appear anywhere in the file. Frida is
never touched.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

import friTap.friTap as fritap_cli
from friTap.api import FriTap
from friTap.config import FriTapConfig, OutputConfig
from friTap.events import EventBus, KeylogEvent
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.factory import OutputHandlerFactory
from friTap.output.json_handler import JsonOutputHandler
from friTap.output.json_stream import recover_json_output
from friTap.output.jsonl_handler import JsonlOutputHandler
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
from friTap.output.key_material import (
    apply_key_material_policy,
    json_key_material_enabled,
    redact_key_record,
)
from friTap.schemas.canonical import KeylogCanonical
from friTap.sinks.json_sink import JsonlSink, JsonSink
from tests.unit.test_cli_unattended import fake_cli  # noqa: F401  (fixture)

CLIENT_RANDOM = "aa" * 32
SECRET = "bb" * 48
NSS_LINE = f"CLIENT_RANDOM {CLIENT_RANDOM} {SECRET}"
SSH_SHARED_SECRET = "cd" * 32
REDACTED_NSS = {"label": "CLIENT_RANDOM", "client_random": CLIENT_RANDOM, "redacted": True}


def _key_events():
    """A TLS NSS line, an SSH KEX payload and a heap memory-scan finding."""
    return [
        KeylogEvent(timestamp=1.0, key_data=NSS_LINE),
        KeylogEvent(timestamp=2.0, protocol="ssh",
                    payload={"cookie": "00" * 16, "shared_secret": SSH_SHARED_SECRET}),
        KeylogEvent(timestamp=3.0, protocol="memscan", key_data=NSS_LINE,
                    payload={"label": "CLIENT_RANDOM", "client_random": CLIENT_RANDOM,
                             "tier": "A", "source": "heap", "secret": SECRET}),
    ]


def _capture(tmp_path, json_name, **legacy_params):
    """Run the real factory + handlers via SSL_Logger; return the output text."""
    path = tmp_path / json_name
    config = FriTapConfig.from_legacy_params(
        app="target", json_output=str(path), install_lsass_hook=False, **legacy_params)
    logger = SSL_Logger(config=config)
    for event in _key_events():
        logger._event_bus.emit(event)
    logger.close_output_handlers()
    return path.read_text()


def _key_records(text, json_name):
    if json_name.endswith(".jsonl"):
        records = [json.loads(line) for line in text.splitlines()]
        return [r for r in records if r["event_type"] == "KeylogEvent"]
    return json.loads(text)["key_extractions"]


# --------------------------------------------------------------------------
# end to end: config -> factory -> file (json + jsonl)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("json_name", ["session.json", "events.jsonl"])
def test_no_key_bytes_in_json_output_without_opt_in(tmp_path, json_name):
    text = _capture(tmp_path, json_name)
    assert SECRET not in text and SSH_SHARED_SECRET not in text
    records = _key_records(text, json_name)
    assert len(records) == 3  # every key event is still recorded
    assert all(r["redacted"] is True for r in records)
    assert all("key_data" not in r and "payload" not in r for r in records)
    assert records[0]["label"] == "CLIENT_RANDOM"
    assert records[0]["client_random"] == CLIENT_RANDOM


@pytest.mark.parametrize("json_name", ["session.json", "events.jsonl"])
def test_key_bytes_present_with_keylog(tmp_path, json_name):
    text = _capture(tmp_path, json_name, keylog=str(tmp_path / "keys.log"))
    records = _key_records(text, json_name)
    assert records[0]["key_data"] == NSS_LINE
    assert not any(r.get("redacted") for r in records)
    assert SECRET in text


@pytest.mark.parametrize("json_name", ["session.json", "events.jsonl"])
def test_key_bytes_present_with_json_keys(tmp_path, json_name):
    text = _capture(tmp_path, json_name, json_keys=True)
    records = _key_records(text, json_name)
    assert records[0]["key_data"] == NSS_LINE
    assert not any(r.get("redacted") for r in records)
    assert not (tmp_path / "keys.log").exists()  # --json-keys writes no keylog file


def test_jsonl_ssh_payload_is_kept_only_with_opt_in(tmp_path):
    redacted = _key_records(_capture(tmp_path, "a.jsonl"), "a.jsonl")[1]
    assert redacted == {"event_type": "KeylogEvent", "timestamp": 2.0,
                        "protocol": "ssh", "redacted": True}
    full = _key_records(_capture(tmp_path, "b.jsonl", json_keys=True), "b.jsonl")[1]
    assert full["payload"]["shared_secret"] == SSH_SHARED_SECRET


def test_memory_scan_finding_keeps_its_provenance_when_redacted(tmp_path):
    finding = _key_records(_capture(tmp_path, "s.json"), "s.json")[2]
    assert finding == {"timestamp": 3.0, "type": "memory_scan_finding",
                       "label": "CLIENT_RANDOM", "client_random": CLIENT_RANDOM,
                       "tier": "A", "source": "heap", "redacted": True}


# --------------------------------------------------------------------------
# factory wiring: one policy for json, jsonl and the stdout stream
# --------------------------------------------------------------------------

def _factory_json_handlers(json_output, **legacy_params):
    config = FriTapConfig.from_legacy_params(app="x", json_output=json_output,
                                             **legacy_params)
    handlers, _ = OutputHandlerFactory.create_handlers(
        config, None, None, {"session_info": {}}, logging.getLogger("t"))
    kinds = (JsonOutputHandler, JsonlOutputHandler)  # Jsonl covers the stdout one
    return [h for h in handlers if isinstance(h, kinds)]


@pytest.mark.parametrize("json_output", ["s.json", "s.jsonl", "-"])
@pytest.mark.parametrize("params,expected", [
    ({}, False),
    ({"keylog": "k.log"}, True),
    ({"json_keys": True}, True),
])
def test_factory_applies_one_policy_to_every_json_output(json_output, params, expected):
    (handler,) = _factory_json_handlers(json_output, **params)
    assert handler._include_key_material is expected
    if json_output == "-":
        assert isinstance(handler, JsonlStdoutHandler)


def test_stdout_stream_includes_keys_with_json_keys():
    buffer = io.StringIO()
    handler = JsonlStdoutHandler(include_key_material=True, stream=buffer)
    handler.setup(bus := EventBus())
    bus.emit(KeylogEvent(key_data=NSS_LINE))
    handler.close()
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    assert records[0]["key_material"] is True
    assert records[1]["key_data"] == NSS_LINE


def test_handlers_default_to_redaction(tmp_path):
    """Constructed without the flag (e.g. by third-party code), nothing leaks."""
    path = tmp_path / "d.jsonl"
    handler = JsonlOutputHandler(str(path))
    handler.setup(bus := EventBus())
    bus.emit(KeylogEvent(key_data=NSS_LINE))
    handler.close()
    assert SECRET not in path.read_text()
    assert JsonOutputHandler(str(tmp_path / "d.json"))._include_key_material is False
    assert JsonlStdoutHandler()._include_key_material is False


# --------------------------------------------------------------------------
# shared helper
# --------------------------------------------------------------------------

@pytest.mark.parametrize("output,expected", [
    (OutputConfig(), False),
    (OutputConfig(keylog="k.log"), True),
    (OutputConfig(json_output="s.json", json_keys=True), True),
    (OutputConfig(json_output="-", json_keys=True), True),
    (OutputConfig(json_keys=True), False),  # --json-keys without any -j output
])
def test_json_key_material_enabled(output, expected):
    assert json_key_material_enabled(output) is expected


def test_apply_policy_keeps_record_when_allowed():
    record = {"key_data": NSS_LINE}
    assert apply_key_material_policy(record, True) == {"key_data": NSS_LINE}


def test_apply_policy_redacts_nss_line_like_the_stdout_stream():
    record = apply_key_material_policy({"key_data": NSS_LINE, "payload": None}, False)
    assert record == REDACTED_NSS == redact_key_record({"key_data": NSS_LINE})


# --------------------------------------------------------------------------
# sinks (pipeline JSON / JSONL writers)
# --------------------------------------------------------------------------

def _sink_text(sink_cls, path, **kwargs):
    sink = sink_cls(str(path), **kwargs)
    sink.open()
    sink.on_keylog(KeylogCanonical(key_data=NSS_LINE, timestamp=1.0))
    sink.flush()
    sink.close()
    return path.read_text()


@pytest.mark.parametrize("sink_cls,name", [(JsonSink, "s.json"), (JsonlSink, "s.jsonl")])
def test_sinks_redact_by_default_and_include_on_opt_in(tmp_path, sink_cls, name):
    redacted = _sink_text(sink_cls, tmp_path / ("r_" + name))
    assert SECRET not in redacted and '"redacted": true' in redacted
    full = _sink_text(sink_cls, tmp_path / ("f_" + name), include_key_material=True)
    assert NSS_LINE in full


# --------------------------------------------------------------------------
# consumers: crash recovery, Python API, CLI flag, LSASS helper session
# --------------------------------------------------------------------------

def test_crash_recovery_reassembles_redacted_records(tmp_path):
    path = str(tmp_path / "s.json")
    handler = JsonOutputHandler(path, session_info={"target_app": "x"})
    handler.setup(EventBus())
    handler.on_keylog(KeylogEvent(timestamp=1.0, key_data=NSS_LINE))
    from friTap.output import json_stream
    json_stream._registry.clear()  # simulate SIGKILL: writer never released
    assert recover_json_output(path) is True
    doc = json.loads((tmp_path / "s.json").read_text())
    assert doc["key_extractions"] == [
        {"timestamp": 1.0, "type": "key_extraction", **REDACTED_NSS}]


def test_python_api_json_keys_builder():
    redacted = FriTap("app").json_output("s.json").build_config()
    assert redacted.output.json_keys is False
    assert not json_key_material_enabled(redacted.output)
    opted_in = FriTap("app").json_output("s.json").json_keys().build_config()
    assert opted_in.output.json_keys is True
    assert json_key_material_enabled(opted_in.output)
    assert FriTap("app").json_keys().json_keys(False).build_config().output.json_keys is False


def test_cli_json_keys_flag_reaches_the_config(fake_cli, tmp_path):  # noqa: F811
    ssl_log, _ = fake_cli("--non-interactive", "-j", str(tmp_path / "s.json"),
                          "--json-keys", "target")
    assert ssl_log.config.output.json_keys is True
    assert ssl_log.config.output.keylog is None


def test_cli_without_json_keys_redacts(fake_cli, tmp_path):  # noqa: F811
    ssl_log, _ = fake_cli("--non-interactive", "-j", str(tmp_path / "s.json"), "target")
    assert ssl_log.config.output.json_keys is False
    assert not json_key_material_enabled(ssl_log.config.output)


@pytest.mark.parametrize("params,expected", [
    ({}, False),                                   # -j alone: agent extracts no keys
    ({"json_keys": True}, True),                   # -j --json-keys: keys for the JSON
    ({"keylog": "k.log"}, True),                   # -k: unchanged
])
def test_agent_key_extraction_follows_keylog_or_json_keys(tmp_path, params, expected):
    config = FriTapConfig.from_legacy_params(
        app="target", json_output=str(tmp_path / "s.json"), install_lsass_hook=False,
        **params)
    logger = SSL_Logger(config=config)
    try:
        assert logger._build_config_batch()["keylog_enabled"] is expected
    finally:
        logger.close_output_handlers()


def test_json_keys_without_json_output_does_not_enable_key_extraction():
    logger = SSL_Logger(config=FriTapConfig.from_legacy_params(
        app="target", json_keys=True, install_lsass_hook=False))
    assert logger._build_config_batch()["keylog_enabled"] is False


def test_lsass_helper_session_shares_the_json_key_policy(tmp_path):
    common = dict(pcap_name=None, verbose=False, keylog=None, live=False,
                  debug_mode=False, host=False, debug_output=False,
                  enable_default_fd=False, patterns=None, custom_hook_script=None,
                  json_output=str(tmp_path / "s.json"), full_capture=False)
    assert fritap_cli._build_lsass_config(684, **common).output.json_keys is False
    assert fritap_cli._build_lsass_config(684, json_keys=True, **common).output.json_keys


def test_hook_lsass_forwards_json_keys(monkeypatch):
    seen = {}
    monkeypatch.setattr(fritap_cli._lsass_hook_manager, "start_lsass_hook",
                        lambda **kw: seen.update(kw))
    fritap_cli.hook_lsass(json_output="s.json", json_keys=True)
    assert seen["json_keys"] is True


def test_redaction_keeps_client_random_only_for_nss_lines():
    """A 3-token line that is not NSS-shaped must not grow a bogus client_random."""
    assert redact_key_record({"key_data": "AES_KEY not-hex secret"}) == {
        "label": "AES_KEY", "redacted": True}


def test_dash_json_target_is_normalized_to_the_stream_flag():
    output = OutputConfig(json_output="-")
    assert output.json_stream is True and output.json_output is None
    assert FriTap("app").json_output("-").build_config().output.json_stream is True
    assert OutputConfig(json_output="s.json").json_stream is False


# ----------------------------------------------------------------------
# A bare secret's first token must never be copied out as its "label"
# ----------------------------------------------------------------------

_BARE_SECRETS = {
    "ssh_shared_secret": "00000020" + "ab" * 32,
    "rc4_key": "0123456789abcdef0123456789abcdef",
    "mtproto_auth_key": "cd" * 256,
    "custom_cipher_hex": "DEADBEEFCAFEBABE00112233445566778899AABBCCDDEEFF",
    "custom_cipher_base64": "q83vEjRWeJCrze8SNFZ4kA==",
    "ipsec_esp_key": "ef" * 16,
}


@pytest.mark.parametrize("secret", list(_BARE_SECRETS.values()), ids=list(_BARE_SECRETS))
def test_bare_secret_is_never_copied_into_the_label(secret):
    record = redact_key_record({"key_data": secret, "payload": None})
    assert record == {"label": "unknown", "redacted": True}
    assert secret not in json.dumps(record)


@pytest.mark.parametrize("key_data", [
    "ab" * 16 + " " + "cd" * 32,                       # two bare hex fields
    " ".join(["aa" * 33, "bb" * 32, "cc" * 32, "dd" * 32, "ee" * 32, "ff" * 16]),  # Signal 1:1
    " ".join(["aa" * 16, "bb" * 32, "cc" * 32, "dd" * 16]),                      # Signal group
])
def test_label_less_multi_field_lines_redact_to_unknown(key_data):
    record = redact_key_record({"key_data": key_data})
    assert record == {"label": "unknown", "redacted": True}
    assert all(token not in json.dumps(record) for token in key_data.split())


@pytest.mark.parametrize("key_data, label", [
    (NSS_LINE, "CLIENT_RANDOM"),
    ("SSH_ENC_KEY_C2S deadbeef", "SSH_ENC_KEY_C2S"),
    ("ab" * 16 + " SHARED_SECRET " + "cd" * 32, "SHARED_SECRET"),
    ("RC4_KEY 0123456789abcdef 8 heap c2s none", "RC4_KEY"),
    ("MTPROTO_AUTH_KEY 2 0011223344556677 " + "aa" * 256 + " temp", "MTPROTO_AUTH_KEY"),
    ("MTPROTO_E2E_KEY 0011223344556677 " + "aa" * 256 + " 42", "MTPROTO_E2E_KEY"),
    ("MTPROTO_OBF_KEY " + " ".join(["aa" * 32, "bb" * 16, "cc" * 32, "dd" * 16, "0", "0"]),
     "MTPROTO_OBF_KEY"),
    ("SK_ei " + "aa" * 32, "SK_ei"),
    ("encr_i " + "aa" * 16, "encr_i"),
    ("WG_SENDING_KEY " + "aa" * 32, "WG_SENDING_KEY"),
])
def test_known_labels_are_kept_without_their_secret(key_data, label):
    record = redact_key_record({"key_data": key_data})
    assert record["label"] == label
    text = json.dumps(record)
    secrets = [t for t in key_data.split()[1:] if len(t) >= 8 and t != "SHARED_SECRET"]
    assert secrets and not any(t in text for t in secrets if t != record.get("client_random"))


def test_known_labels_cover_every_emitted_label():
    from friTap.output.key_material import KNOWN_KEYLOG_LABELS
    from friTap.pipeline import TLS_KEYLOG_LABELS
    from friTap.protocols import mtproto_keylog_spec, rc4_keylog_spec

    assert TLS_KEYLOG_LABELS <= KNOWN_KEYLOG_LABELS
    assert {rc4_keylog_spec.LABEL, mtproto_keylog_spec.LABEL,
            mtproto_keylog_spec.E2E_LABEL, mtproto_keylog_spec.OBF_LABEL} <= KNOWN_KEYLOG_LABELS
