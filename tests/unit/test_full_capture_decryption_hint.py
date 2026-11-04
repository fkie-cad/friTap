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
