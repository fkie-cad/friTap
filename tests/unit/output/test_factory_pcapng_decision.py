"""The full-capture DSB injection (KeyCollectorHandler) follows the same pcapng
decision as the -p handler (the config's resolved ``pcap_container``): an explicit
``--pcap-format`` wins over the extension, so ``-p out.pcap --pcap-format pcapng
-f`` writes pcapng and needs the key collector, while ``--pcap-format pcap`` on a
``.pcapng`` name writes classic pcap and must not get one."""

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


def test_explicit_pcap_format_wins_over_pcapng_extension_for_full_capture(tmp_path):
    assert not _has_key_collector(tmp_path, "out.pcapng", "pcap")


@pytest.mark.parametrize("name, fmt", [("out.pcapng", "auto"), ("out.bin", "pcapng"),
                                       ("out.pcap", "pcapng")])
def test_real_pcapng_full_capture_gets_the_key_collector(tmp_path, name, fmt):
    assert _has_key_collector(tmp_path, name, fmt)


def test_no_key_collector_without_full_capture(tmp_path):
    assert not _has_key_collector(tmp_path, "out.pcapng", "auto", full_capture=False)


def test_pcap_handler_class_reads_the_resolved_container():
    """Writers never re-resolve: the factory follows ``pcap_container`` only."""
    from friTap.output.factory import _pcap_handler_class
    from friTap.output.pcap_handler import PcapOutputHandler
    from friTap.output.pcapng_handler import PcapngOutputHandler
    output = OutputConfig(pcap="out.pcap")
    assert _pcap_handler_class(output) is PcapOutputHandler
    output.pcap_container = "pcapng"
    assert _pcap_handler_class(output) is PcapngOutputHandler
    assert _pcap_handler_class(OutputConfig()) is None
