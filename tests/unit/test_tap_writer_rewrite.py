#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression lock for the offline early-write fix.

An offline-decrypted flow can "complete" mid-collection and be written to the
.tap BEFORE its decrypted messages are folded onto its layer (that attachment
runs post-collection). The conversion therefore re-writes offline-attached flows
in the final sweep, relying on the reader keeping the LAST record per flow_id.
This test proves that write -> mutate -> re-write -> read yields the mutated
state, and that the writer collapses the duplicate flow_id at close.
"""

from __future__ import annotations

from friTap.flow.models import Flow
from friTap.flow.layers import SignalLayer
from friTap.flow.tap_writer import TapWriter
from friTap.flow.tap_reader import TapReader


def _signal_flow():
    flow = Flow(flow_id="net:2.2.2.2:443-1.1.1.1:45088:0", connection_id="c",
                src_addr="2.2.2.2", src_port=443, dst_addr="1.1.1.1", dst_port=45088)
    flow.transport = "signal"
    layer = SignalLayer()
    flow.add_layer(layer)
    return flow, layer


def test_rewrite_after_attach_wins(tmp_path):
    tap_path = str(tmp_path / "rewrite.tap")
    writer = TapWriter()
    writer.open(tap_path, target="t")

    flow, layer = _signal_flow()
    # 1) Early write — flow "completed" mid-collection with NO messages yet.
    writer.write_flow(flow)
    assert flow.flow_id in writer.written_flow_ids

    # 2) Post-collection metadata attachment mutates the SAME live object.
    layer.chat_type = "one_to_one"
    layer.messages = [
        {"direction": "read", "kind": "data", "timestamp": 1, "body": "Tesla"},
        {"direction": "read", "kind": "data", "timestamp": 1, "body": "Tesla"},
    ]
    layer.message_count = 2

    # 3) Final sweep re-writes it (the fix writes offline-attached flows even when
    #    already in written_flow_ids).
    writer.write_flow(flow)
    writer.close()

    # 4) Reader keeps the LAST record -> the attached messages are present, and the
    #    duplicate flow_id is collapsed to ONE distinct flow.
    reader = TapReader(tap_path)
    reader.open()
    flows = reader.read_all_flows()
    assert len(flows) == 1                       # duplicate flow_id collapsed
    assert reader.flow_count == 1
    sig = next(ln for ln in flows[0].layers if getattr(ln, "name", "") == "signal")
    bodies = [m["body"] for m in sig.messages]
    assert bodies == ["Tesla", "Tesla"]          # mutated (v2) state won, dup kept
    assert sig.chat_type == "one_to_one"
    reader.close()


def test_flow_summary_carries_transport(tmp_path):
    """The summary fast-path (decode_flow_summary) restores Flow.transport.

    Lets the TUI group Signal sibling connections from the cheap in-memory
    summaries without decoding every full Flow.
    """
    tap_path = str(tmp_path / "transport.tap")
    writer = TapWriter()
    writer.open(tap_path, target="t")
    flow, _ = _signal_flow()
    writer.write_flow(flow)
    writer.close()

    reader = TapReader(tap_path)
    reader.open()
    summaries = reader.read_flow_summaries()
    reader.close()

    assert len(summaries) == 1
    assert summaries[0].transport == "signal"            # read back from FLOW meta
    assert summaries[0].to_dict()["transport"] == "signal"


def test_flow_summary_from_flow_copies_transport():
    """Both FlowSummary shapes copy Flow.transport on construction."""
    from friTap.flow.tap_format import FlowSummary as TapSummary
    from friTap.flow.models import FlowSummary as LiveSummary

    flow, _ = _signal_flow()
    assert TapSummary.from_flow(flow).transport == "signal"
    assert LiveSummary.from_flow(flow).transport == "signal"
    # Default-tls flow round-trips to the default.
    tls_flow, _ = _signal_flow()
    tls_flow.transport = "tls"
    assert TapSummary.from_flow(tls_flow).transport == "tls"
