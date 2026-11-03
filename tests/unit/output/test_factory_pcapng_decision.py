"""The full-capture DSB injection (KeyCollectorHandler) follows the same pcapng
decision as the -p handler: the ``.pcap`` extension wins over
``--output-format pcapng``, so ``-p out.pcap --output-format pcapng -f`` writes
classic pcap and must not get a pcapng-only key collector."""

from __future__ import annotations

import logging

import pytest

from friTap.config import FriTapConfig, OutputConfig
from friTap.output.factory import OutputHandlerFactory
from friTap.output.key_collector_handler import KeyCollectorHandler
from friTap.protocols.registry import create_default_registry


def _has_key_collector(tmp_path, pcap_name, output_format, full_capture=True):
    config = FriTapConfig(
        target="app",
        output=OutputConfig(pcap=str(tmp_path / pcap_name), output_format=output_format,
                            full_capture=full_capture),
    )
    reg = create_default_registry(["tls"])
    handlers, _ = OutputHandlerFactory.create_handlers(
        config, None, reg.get("tls"), {}, logging.getLogger("friTap.tests.pcapng"),
        protocol_registry=reg,
    )
    return any(isinstance(h, KeyCollectorHandler) for h in handlers)


def test_pcap_extension_wins_over_pcapng_format_for_full_capture(tmp_path):
    assert not _has_key_collector(tmp_path, "out.pcap", "pcapng")


@pytest.mark.parametrize("name, fmt", [("out.pcapng", "auto"), ("out.bin", "pcapng")])
def test_real_pcapng_full_capture_gets_the_key_collector(tmp_path, name, fmt):
    assert _has_key_collector(tmp_path, name, fmt)


def test_no_key_collector_without_full_capture(tmp_path):
    assert not _has_key_collector(tmp_path, "out.pcapng", "auto", full_capture=False)
