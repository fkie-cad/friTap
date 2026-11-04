#!/usr/bin/env python3

"""Tests for the IPsec Wireshark UAT formatter and decryption-table writer.

The rows are compared against the exact format strongSwan's ``save-keys`` plugin
writes (``ikev2_decryption_table`` / ``esp_sa``), because that is the ground
truth tshark consumes. Every field is agent-controlled, so malformed records
must be dropped rather than written.
"""

import logging

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.output import keylog_format
from friTap.output.ipsec_decryption_tables import IPsecDecryptionTableHandler
from friTap.protocols.ipsec_handler import (
    ESP_TABLE,
    IKEV2_TABLE,
    IPsecKeylogFormatter,
    esp_names,
    ike_names,
)

# --- known-good inputs ----------------------------------------------------- #

SPI_I = "1111111111111111"
SPI_R = "2222222222222222"
SK_EI = "aa" * 16
SK_ER = "bb" * 16
SK_AI = "cc" * 16
SK_AR = "dd" * 16

# AES-CBC-256 (enc_alg 12, 256-bit) + HMAC_SHA2_256_128 (int_alg 12) IKE.
IKE_ROW = (
    f'{SPI_I},{SPI_R},{SK_EI},{SK_ER},"AES-CBC-256 [RFC3602]",'
    f'{SK_AI},{SK_AR},"HMAC_SHA2_256_128 [RFC4868]"'
)

# AES-CBC (enc_alg 12) + HMAC-SHA-256-128 (int_alg 12) ESP.
ESP_ENC_KEY = "11" * 16
ESP_INT_KEY = "22" * 16
ESP_ROW = (
    f'"IPv4","10.0.0.1","10.0.0.2","0x0a0b0c0d","AES-CBC [RFC3602]",'
    f'"0x{ESP_ENC_KEY}","HMAC-SHA-256-128 [RFC4868]","0x{ESP_INT_KEY}"'
)

# AES-GCM-128 (ICV16 = enc_alg 20) AEAD ESP: no integrity key. Wireshark requires
# the integrity column to be exactly "NULL" for AES-GCM/CCM (it rejects the
# save_keys "ANY N bit authentication" form), so the row uses "NULL".
ESP_GCM_KEY = "33" * 16
ESP_GCM_ROW = (
    f'"IPv4","192.168.1.1","192.168.1.2","0xdeadbeef","AES-GCM [RFC4106]",'
    f'"0x{ESP_GCM_KEY}","NULL","0x"'
)


def _ike_event(**overrides):
    payload = {
        "record": "ike", "ike_version": 2,
        "spi_i": SPI_I, "spi_r": SPI_R,
        "enc_alg": 12, "enc_key_len_bits": 256, "int_alg": 12,
        "sk_ei": SK_EI, "sk_er": SK_ER, "sk_ai": SK_AI, "sk_ar": SK_AR,
    }
    payload.update(overrides)
    return KeylogEvent(protocol="ipsec", payload=payload)


def _esp_event(**overrides):
    payload = {
        "record": "esp", "spi": "0a0b0c0d", "src": "10.0.0.1", "dst": "10.0.0.2",
        "family": "IPv4", "enc_alg": 12, "int_alg": 12,
        "enc_key": ESP_ENC_KEY, "int_key": ESP_INT_KEY,
    }
    payload.update(overrides)
    return KeylogEvent(protocol="ipsec", payload=payload)


@pytest.fixture(autouse=True)
def _reset_warn_once():
    keylog_format._dropped_reasons.clear()
    yield
    keylog_format._dropped_reasons.clear()


# --- algorithm name maps (verbatim from save_keys) ------------------------- #

class TestAlgoNames:
    def test_ike_aes_cbc_256(self):
        assert ike_names(12, 256, 12) == (
            "AES-CBC-256 [RFC3602]", "HMAC_SHA2_256_128 [RFC4868]")

    def test_ike_aead_forces_none_integrity(self):
        # AES-GCM-128/16 IKE (enc 20) is AEAD -> integ "NONE [RFC4306]".
        assert ike_names(20, 128, 0) == (
            "AES-GCM-128 with 16 octet ICV [RFC5282]", "NONE [RFC4306]")

    def test_esp_aes_cbc_hmac_sha256(self):
        assert esp_names(12, 12) == (
            "AES-CBC [RFC3602]", "HMAC-SHA-256-128 [RFC4868]")

    @pytest.mark.parametrize("enc_alg", [18, 19, 20])
    def test_esp_aead_integrity_is_null(self, enc_alg):
        # AES-GCM (any ICV length) is AEAD: Wireshark requires the esp_sa
        # integrity column to be exactly "NULL" (it rejects "ANY N bit ...").
        enc, integ = esp_names(enc_alg, 0)
        assert enc == "AES-GCM [RFC4106]"
        assert integ == "NULL"

    def test_unknown_algorithms_are_none(self):
        assert ike_names(9999, 256, 9999) == (None, None)
        assert esp_names(9999, 9999) == (None, None)


# --- formatter: exact rows ------------------------------------------------- #

class TestFormatterRows:
    def test_protocol_and_marker(self):
        fmt = IPsecKeylogFormatter()
        assert fmt.protocol == "ipsec"
        assert fmt.writes_decryption_tables is True
        assert fmt.format(_ike_event()) == []  # no NSS keylog lines

    def test_ike_row(self):
        assert IPsecKeylogFormatter().format_rows(_ike_event()) == [(IKEV2_TABLE, IKE_ROW)]

    def test_esp_row(self):
        assert IPsecKeylogFormatter().format_rows(_esp_event()) == [(ESP_TABLE, ESP_ROW)]

    def test_esp_aead_gcm_row(self):
        evt = _esp_event(spi="deadbeef", src="192.168.1.1", dst="192.168.1.2",
                         enc_alg=20, int_alg=0, enc_key=ESP_GCM_KEY, int_key="")
        assert IPsecKeylogFormatter().format_rows(evt) == [(ESP_TABLE, ESP_GCM_ROW)]

    def test_unknown_record_type_yields_nothing(self):
        evt = KeylogEvent(protocol="ipsec", payload={"record": "bogus"})
        assert IPsecKeylogFormatter().format_rows(evt) == []

    def test_no_payload_yields_nothing(self):
        assert IPsecKeylogFormatter().format_rows(KeylogEvent(protocol="ipsec")) == []

    @pytest.mark.parametrize("bad", [
        {"spi_i": "zz" * 8},          # non-hex SPI
        {"sk_ei": "abc"},             # odd-length key
        {"sk_ar": "cc\n" + "dd" * 8},  # CR/LF injection
        {"enc_alg": 9999},            # unknown encryption alg
    ])
    def test_malformed_ike_dropped(self, bad):
        assert IPsecKeylogFormatter().format_rows(_ike_event(**bad)) == []

    @pytest.mark.parametrize("bad", [
        {"spi": "nothex0"},                 # non-hex SPI
        {"enc_key": "111"},                 # odd-length key
        {"src": "10.0.0.1\",\"x"},          # CSV/quote injection in endpoint
        {"family": "IPvX"},                 # bad family
        {"int_key": "zz" * 16},             # non-hex integrity key
    ])
    def test_malformed_esp_dropped(self, bad):
        assert IPsecKeylogFormatter().format_rows(_esp_event(**bad)) == []


# --- writer: files, dedup, lazy open --------------------------------------- #

class TestDecryptionTableHandler:
    def _handler(self, tmp_path):
        keylog = str(tmp_path / "keys.log")
        return IPsecDecryptionTableHandler(keylog, formatter=IPsecKeylogFormatter())

    def test_writes_both_tables_next_to_keylog(self, tmp_path):
        handler = self._handler(tmp_path)
        bus = EventBus()
        try:
            handler.setup(bus)
            bus.emit(_ike_event())
            bus.emit(_esp_event())
        finally:
            handler.close()

        ike_file = tmp_path / IKEV2_TABLE
        esp_file = tmp_path / ESP_TABLE
        assert ike_file.read_text() == IKE_ROW + "\n"
        assert esp_file.read_text() == ESP_ROW + "\n"

    def test_identical_rows_are_deduped(self, tmp_path):
        handler = self._handler(tmp_path)
        bus = EventBus()
        try:
            handler.setup(bus)
            for _ in range(3):
                bus.emit(_esp_event())   # same SA reported repeatedly
        finally:
            handler.close()
        assert (tmp_path / ESP_TABLE).read_text() == ESP_ROW + "\n"

    def test_ike_only_leaves_no_esp_file(self, tmp_path):
        handler = self._handler(tmp_path)
        bus = EventBus()
        try:
            handler.setup(bus)
            bus.emit(_ike_event())
        finally:
            handler.close()
        assert (tmp_path / IKEV2_TABLE).exists()
        assert not (tmp_path / ESP_TABLE).exists()

    def test_bare_filename_writes_to_current_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        handler = IPsecDecryptionTableHandler("keys.log", formatter=IPsecKeylogFormatter())
        # A bare filename resolves the tables into the current directory.
        assert handler.table_path(IKEV2_TABLE) in (IKEV2_TABLE, f"./{IKEV2_TABLE}")
        bus = EventBus()
        try:
            handler.setup(bus)
            bus.emit(_ike_event())
        finally:
            handler.close()
        assert (tmp_path / IKEV2_TABLE).read_text() == IKE_ROW + "\n"

    def test_malformed_row_never_written(self, tmp_path, caplog):
        handler = self._handler(tmp_path)
        bus = EventBus()
        try:
            handler.setup(bus)
            with caplog.at_level(logging.WARNING):
                bus.emit(_ike_event(spi_i="zz" * 8))
        finally:
            handler.close()
        assert not (tmp_path / IKEV2_TABLE).exists()
