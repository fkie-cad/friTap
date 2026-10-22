"""Unit tests for the golden harness normalization (dev/golden/canonicalize.py)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "dev", "golden"))
import canonicalize as c  # noqa: E402
import golden_child  # noqa: E402
import run_golden  # noqa: E402

from friTap.flow.tap_format import TapHeader, TapMeta


def test_chunk_timestamps_are_not_normalized():
    """Every emitter stamps pcap capture times, so a chunk's timestamp is part
    of the golden: two chunks differing only in time must digest differently."""
    from friTap.flow.models import FlowChunk

    early = FlowChunk(data=b"x", direction="read", timestamp=1000.0, function="f")
    late = FlowChunk(data=b"x", direction="read", timestamp=1001.0, function="f")
    assert c.canonical_chunks([early]) != c.canonical_chunks([late])


def test_replace_work_dirs_recurses():
    out = c.replace_work_dirs({"a": ["/w/x.tap", ("/w",)]}, ["/w"])
    assert out == {"a": ["<WORK>/x.tap", ["<WORK>"]]}


def test_header_and_meta_normalization():
    assert c.canonical_header(TapHeader(capture_start=5.0))["capture_start"] == c.WALLCLOCK_PLACEHOLDER
    assert c.canonical_header(TapHeader(capture_start=5.0, flow_count=1))["capture_start"] == 5.0
    assert "fritap_version" not in c.canonical_meta(TapMeta(fritap_version="1.2.3"))


def test_dumps_is_sorted_and_hashes_bytes():
    text = c.dumps({"b": b"x", "a": 1})
    assert text.index('"a"') < text.index('"b"')
    assert c.sha256_hex(b"x") in text


def test_build_convert_kwargs_maps_basenames_into_work_dir():
    kwargs = golden_child.build_convert_kwargs(
        {"keylog_path": "d/k.log", "protocol_keylogs": {"rc4": "d/r.log"}, "tls_ports": [8443]},
        "/w")
    assert kwargs == {"run_scan": False, "keylog_path": "/w/k.log",
                      "protocol_keylogs": {"rc4": "/w/r.log"}, "tls_ports": (8443,)}


def test_entry_input_paths_and_slug():
    entry = {"pcap": "p.pcap", "args": {"keylog_path": "k", "protocol_keylogs": {"x": "k"}}}
    assert run_golden.entry_input_paths(entry) == ["p.pcap", "k"]
    assert run_golden.path_slug(os.path.join("a b", "c.tap")) == "a_b__c.tap"
