"""WP9: agent-controlled keylog strings can never inject extra keylog lines.

Key material arrives from an agent inside a possibly hostile process; a CR/LF in
a label or secret used to be written verbatim, forging lines in the keylog the
user later feeds to Wireshark. Valid inputs must be written exactly as before.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.output import keylog_format
from friTap.output.keylog_format import (
    KeylogFormatter,
    filter_safe_keylog_lines,
    is_hex_field,
    is_nss_keylog_line,
    is_safe_keylog_label,
    is_safe_keylog_line,
    is_secret_field,
    sanitize_keylog_fields,
)
from friTap.output.shared_keylog_writer import (
    acquire_keylog_writer,
    release_keylog_writer,
)
from friTap.plugins.custom_protocol import CustomProtocolPlugin
from friTap.protocols import ssh_extractor
from friTap.protocols.ssh_extractor import SSHKeyProcessor
from friTap.protocols.tls_handler import TlsKeylogFormatter

CR = "aa" * 32
SECRET = "bb" * 48
VALID_TLS = f"CLIENT_RANDOM {CR} {SECRET}"


@pytest.fixture(autouse=True)
def _reset_warn_once():
    keylog_format._dropped_reasons.clear()
    yield
    keylog_format._dropped_reasons.clear()


# --------------------------------------------------------------------------- #
# validators
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("line", [
    VALID_TLS, "SSH_ENC_KEY_C2S abcd", "# a comment — with unicode", "LABEL=YWJj==",
])
def test_safe_lines(line):
    assert is_safe_keylog_line(line)


@pytest.mark.parametrize("line", [
    "", None, 42, b"CLIENT_RANDOM aa bb", "A\nB", "A\rB", "A\x00B", "A\tB", "A\x7fB",
    "x" * (keylog_format.MAX_KEYLOG_LINE_LENGTH + 1),
])
def test_unsafe_lines(line):
    assert not is_safe_keylog_line(line)


@pytest.mark.parametrize("label", [
    "CLIENT_RANDOM", "SERVER_TRAFFIC_SECRET_0", "MTPROTO_AUTH_KEY", "RC4_KEY",
    "SSH_ENC_KEY_C2S", "AES_KEY", "wg_key", "EXPORTER-SECRET",
])
def test_valid_labels(label):
    assert is_safe_keylog_label(label)


@pytest.mark.parametrize("label", ["", "A B", "A\nB", "-X", "X" * 65, None, 1, "A=B"])
def test_invalid_labels(label):
    assert not is_safe_keylog_label(label)


def test_hex_fields():
    assert is_hex_field("aB09")
    assert not is_hex_field("abc")  # odd length
    assert not is_hex_field("zz")
    assert not is_hex_field("a")
    assert not is_hex_field("aa" * 2049)
    assert not is_hex_field(None)
    assert is_secret_field("YWJjZA==", allow_base64=True)
    assert not is_secret_field("YWJjZA==")
    assert not is_secret_field("ab\ncd", allow_base64=True)


def test_sanitize_keylog_fields():
    assert sanitize_keylog_fields("CLIENT_RANDOM", CR, SECRET) == VALID_TLS
    assert sanitize_keylog_fields("CLIENT_RANDOM\nX", CR, SECRET) is None
    assert sanitize_keylog_fields("CLIENT_RANDOM", CR, SECRET + "\n") is None
    assert sanitize_keylog_fields("CLIENT_RANDOM") is None
    assert sanitize_keylog_fields(None, CR) is None


def test_nss_lines():
    assert is_nss_keylog_line(VALID_TLS)
    assert is_nss_keylog_line(f"CLIENT_RANDOM ??? {SECRET}")
    assert not is_nss_keylog_line(f"CLIENT_RANDOM {CR}\nCLIENT_RANDOM {CR} {SECRET}")
    assert not is_nss_keylog_line(f"client_random {CR} {SECRET}")
    assert not is_nss_keylog_line("CLIENT_RANDOM")


def test_drop_warning_is_logged_once_per_reason(caplog):
    with caplog.at_level("WARNING", logger="friTap.output.keylog_format"):
        filter_safe_keylog_lines(["X a\nb", "X c\nd"])
    assert len([r for r in caplog.records if "Dropping" in r.getMessage()]) == 1


# --------------------------------------------------------------------------- #
# formatters
# --------------------------------------------------------------------------- #

class _Passthrough(KeylogFormatter):
    @property
    def protocol(self) -> str:
        return "x"


def test_tls_formatter_valid_line_unchanged():
    assert TlsKeylogFormatter().format(KeylogEvent(key_data=VALID_TLS)) == [VALID_TLS]


@pytest.mark.parametrize("bad", [
    f"CLIENT_RANDOM {CR} {SECRET}\r\nCLIENT_RANDOM {'cc' * 32} {SECRET}",
    f"CLIENT_RANDOM\n {CR} {SECRET}",
    f"CLIENT_RANDOM {CR} {SECRET}\x00",
])
def test_tls_formatter_drops_crlf(bad):
    assert TlsKeylogFormatter().format(KeylogEvent(key_data=bad)) == []


def test_base_passthrough_drops_crlf_keeps_valid():
    fmt = _Passthrough()
    assert fmt.format(KeylogEvent(key_data="SSH_ENC_KEY_C2S abcd")) == ["SSH_ENC_KEY_C2S abcd"]
    assert fmt.format(KeylogEvent(key_data="SSH_ENC_KEY_C2S ab\nFORGED cd")) == []
    assert fmt.format(KeylogEvent(key_data="")) == []


# --------------------------------------------------------------------------- #
# shared writer (last line of defense)
# --------------------------------------------------------------------------- #

def test_shared_writer_drops_injected_lines(tmp_path):
    path = tmp_path / "keys.log"
    writer, _created = acquire_keylog_writer(str(path))
    try:
        writer.write_lines([VALID_TLS, "RC4_KEY aa 1 src c2s -\nFORGED x", 7])
    finally:
        release_keylog_writer(writer)
    assert path.read_text() == VALID_TLS + "\n"


# --------------------------------------------------------------------------- #
# SSH key processor
# --------------------------------------------------------------------------- #

def _ssh_processor():
    bus = EventBus()
    seen: list = []
    bus.subscribe(KeylogEvent, seen.append)
    return SSHKeyProcessor(event_bus=bus), seen


def test_ssh_valid_event_unchanged():
    proc, seen = _ssh_processor()
    record = proc.process_key_event({
        "direction": "C2S", "cipher": "aes128-ctr", "key_len": 16, "iv_len": 16,
        "key_data": "00" * 16, "iv_data": "11" * 16,
    })
    assert record["direction"] == "C2S"
    assert [e.key_data for e in seen] == ["SSH_ENC_KEY_C2S " + "00" * 16]
    assert proc.format_keylog() == (
        "SSH_ENC_KEY_C2S " + "00" * 16 + "\nSSH_IV_C2S " + "11" * 16)


@pytest.mark.parametrize("event", [
    {"direction": "C2S\nFORGED", "key_data": "00" * 16},
    {"direction": "C2S", "key_data": "00" * 16 + "\r\nFORGED aa"},
    {"direction": "C2S", "iv_data": "zz"},
    {"direction": 5, "key_data": "00"},
    "not a dict",
])
def test_ssh_invalid_event_dropped(event):
    proc, seen = _ssh_processor()
    assert proc.process_key_event(event) is None
    assert seen == [] and proc.extracted_keys == []


def test_ssh_extracted_keys_capped(monkeypatch):
    monkeypatch.setattr(ssh_extractor, "MAX_EXTRACTED_SSH_KEYS", 3)
    proc = SSHKeyProcessor()
    for _ in range(5):
        proc.process_key_event({"direction": "s2c", "key_data": "ab"})
    assert len(proc.extracted_keys) == 3


# --------------------------------------------------------------------------- #
# custom protocol plugin
# --------------------------------------------------------------------------- #

class _Plugin(CustomProtocolPlugin):
    name = "my_crypto"
    version = "1.0.0"
    display_name = "My Crypto"
    library_patterns = [r".*libmy.*"]

    def setup_hooks(self):
        pass


def _plugin(template=None):
    plugin = _Plugin()
    if template:
        plugin.format_template = template
    bus = EventBus()
    seen: list = []
    bus.subscribe(KeylogEvent, seen.append)
    plugin._session = SimpleNamespace(lifecycle_bus=bus)
    return plugin, seen


def test_custom_valid_key_unchanged():
    plugin, seen = _plugin()
    plugin.emit_key("AES_KEY", "00" * 32)
    assert [e.key_data for e in seen] == ["AES_KEY " + "00" * 32]


def test_custom_base64_template_unchanged():
    plugin, seen = _plugin("{label}={secret_base64}")
    plugin.emit_key("WG_SENDING_KEY", "YWJjZGVm+/==")
    assert [e.key_data for e in seen] == ["WG_SENDING_KEY=YWJjZGVm+/=="]


@pytest.mark.parametrize("label,secret", [
    ("AES_KEY\nCLIENT_RANDOM", "00" * 16),
    ("AES_KEY", "00" * 16 + "\r\nCLIENT_RANDOM aa bb"),
    (None, "00"),
    ("AES_KEY", 1234),
])
def test_custom_crlf_dropped(label, secret):
    plugin, seen = _plugin()
    plugin.emit_key(label, secret)
    assert seen == []


def test_custom_script_message_crlf_dropped():
    plugin, seen = _plugin()
    plugin.on_script_message(
        {"payload": {"contentType": "keylog", "label": "K\nX", "data": "00"}}, None)
    assert seen == []


# --------------------------------------------------------------------------- #
# legacy message handler
# --------------------------------------------------------------------------- #

def _legacy_logger(verbose: bool):
    import io
    import logging

    return SimpleNamespace(
        logger=logging.getLogger("test.legacy"), debug=False, debug_output=False,
        verbose=verbose, keylog=True, keylog_file=io.StringIO(), keydump_Set=set(),
        json_output=False, pcap_name=None, live=False, full_capture=False,
        socket_trace=False,
    )


@pytest.mark.parametrize("verbose", [False, True])
def test_legacy_handler_writes_valid_drops_injected(verbose):
    from friTap.legacy.message_handler import handle_message_legacy

    inst = _legacy_logger(verbose)
    for line in (VALID_TLS, VALID_TLS + "\nFORGED aa", "X\x00Y"):
        payload = {"contentType": "keylog", "keylog": line}
        handle_message_legacy(inst, payload, None, {"payload": payload})
    assert inst.keylog_file.getvalue() == VALID_TLS + "\n"
