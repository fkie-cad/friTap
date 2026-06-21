#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the generic memory-scan candidate path (--scan-keys-region).

Covers the three links of the chain the public engine relies on:
  1. the scan_candidate KeylogFormatter renders a candidate event;
  2. the message router forwards a ``private_key_material`` message tagged
     ``classifier="scan_candidate"`` as ``KeylogEvent(protocol="scan_candidate")``;
  3. the output factory wires a scan_candidate keylog handler whenever a scan
     region is configured, regardless of the selected ``--protocol``.
"""

import logging

import pytest

from friTap.config import FriTapConfig, OutputConfig, HookingConfig
from friTap.events import EventBus, KeylogEvent
from friTap.message_router import MessageRouter
from friTap.output.factory import OutputHandlerFactory
from friTap.output.keylog_handler import KeylogOutputHandler
from friTap.output.scan_candidate_formatter import ScanCandidateKeylogFormatter
from friTap.protocols.registry import create_default_registry


@pytest.fixture
def silent_logger():
    return logging.getLogger("friTap.tests.scan_candidate")


def _keylog_handlers(handlers):
    return [h for h in handlers if isinstance(h, KeylogOutputHandler)]


class TestScanCandidateFormatter:
    def test_protocol_is_reveal_free(self):
        assert ScanCandidateKeylogFormatter().protocol == "scan_candidate"

    def test_format_renders_ranked_fields(self):
        fmt = ScanCandidateKeylogFormatter()
        event = KeylogEvent(protocol="scan_candidate", payload={
            "score": 132, "signals": ["entropy", "aes256_schedule"],
            "region": "heap", "offset": 4096, "length": 32, "bytes": "ab" * 32,
        })
        lines = fmt.format(event)
        assert len(lines) == 1
        line = lines[0]
        assert "score=132" in line
        assert "signals=entropy,aes256_schedule" in line
        assert "region=heap" in line
        assert "offset=4096" in line
        assert "length=32" in line

    def test_dedup_key_is_stable_per_location(self):
        fmt = ScanCandidateKeylogFormatter()
        ev = KeylogEvent(protocol="scan_candidate", payload={
            "region": "heap", "offset": 4096, "bytes": "ab" * 32,
        })
        assert fmt.dedup_key(ev) == "heap|4096|" + "ab" * 32


class TestRouterScanCandidate:
    def test_private_key_material_routes_by_classifier(self):
        bus = EventBus()
        captured = []
        bus.subscribe(KeylogEvent, lambda e: captured.append(e))
        router = MessageRouter(bus)
        router.route({
            "contentType": "private_key_material",
            "classifier": "scan_candidate",
            "score": 42,
            "signals": ["entropy"],
            "region": "heap",
            "offset": 128,
            "length": 32,
            "bytes": "cd" * 32,
        }, b"")
        assert len(captured) == 1
        ev = captured[0]
        assert ev.protocol == "scan_candidate"
        assert ev.payload["region"] == "heap"
        assert ev.payload["score"] == 42
        # The opaque routing tags must NOT leak into the rendered payload.
        assert "classifier" not in ev.payload
        assert "contentType" not in ev.payload

    def test_empty_classifier_is_dropped(self):
        bus = EventBus()
        captured = []
        bus.subscribe(KeylogEvent, lambda e: captured.append(e))
        router = MessageRouter(bus)
        router.route({"contentType": "private_key_material"}, b"")
        assert captured == []


class TestFactoryScanCandidateWiring:
    def _config(self, keylog, protocol, scan_region):
        return FriTapConfig(
            target="dummy",
            output=OutputConfig(keylog=keylog),
            protocol=protocol,
            hooking=HookingConfig(scan_keys_region=scan_region),
        )

    def test_scan_region_adds_scan_candidate_alongside_protocol(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry(["tls"])
        config = self._config(keylog, "tls", "heap")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )
        protos = {h._formatter.protocol for h in _keylog_handlers(handlers)}
        assert "scan_candidate" in protos
        assert "tls" in protos

    def test_scan_region_alone_writes_to_verbatim_path(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry(["tls"])
        # A protocol with no active keylog formatter; the scan candidate is the
        # only emitter, so it writes straight to the -k path.
        config = self._config(keylog, "nonsense", "libfoo.so")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, None, {}, silent_logger,
            protocol_registry=reg,
        )
        keylog_h = _keylog_handlers(handlers)
        assert len(keylog_h) == 1
        assert isinstance(keylog_h[0]._formatter, ScanCandidateKeylogFormatter)
        assert keylog_h[0]._path == keylog

    def test_no_scan_region_keeps_default_wiring(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry(["tls"])
        config = self._config(keylog, "tls", None)

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )
        protos = {h._formatter.protocol for h in _keylog_handlers(handlers)}
        assert "scan_candidate" not in protos
