#!/usr/bin/env python3

"""quic_synthetic degrades gracefully when aioquic's private attributes go away."""

from __future__ import annotations

import types

import pytest

from friTap.output import quic_synthetic
from friTap.output.quic_synthetic import CLIENT, SERVER, SyntheticQuicWriter

pytestmark = pytest.mark.skipif(not quic_synthetic.is_available(), reason="aioquic not installed")


@pytest.fixture
def debug_log(fritap_log_records):
    return fritap_log_records("friTap.output.quic_synthetic")


def test_missing_stream_limits_fall_back_to_aioquic_default(debug_log):
    assert quic_synthetic._raise_stream_limits(types.SimpleNamespace()) == 128
    assert any("cannot raise aioquic stream limits" in r.getMessage() for r in debug_log)


def test_present_stream_limits_are_raised():
    limit = types.SimpleNamespace(value=128, sent=128)
    connection = types.SimpleNamespace(_local_max_streams_bidi=limit, _local_max_streams_uni=limit)
    assert quic_synthetic._raise_stream_limits(connection) == quic_synthetic.MAX_STREAMS_PER_TYPE
    assert limit.value == limit.sent == quic_synthetic.MAX_STREAMS_PER_TYPE


def test_missing_private_stream_helpers_are_detected():
    bare = types.SimpleNamespace()
    assert quic_synthetic._can_open_peer_streams(bare, bare) is False
    assert quic_synthetic._known_streams(bare) == {}


def test_missing_send_state_counts_as_unsent_so_acks_are_flushed():
    stream = types.SimpleNamespace(sender=types.SimpleNamespace())
    assert quic_synthetic._has_unsent_stream_data(types.SimpleNamespace(_streams={0: stream})) is True
    assert quic_synthetic._has_unsent_stream_data(types.SimpleNamespace()) is False


def test_skipped_local_streams_are_left_alone_without_private_state():
    created = []
    connection = types.SimpleNamespace(_get_or_create_stream_for_send=created.append)
    quic_synthetic._open_skipped_local_streams(connection, 8)
    assert created == []
    connection._local_next_stream_id_bidi = 0
    quic_synthetic._open_skipped_local_streams(connection, 8)
    assert created == [0, 4]


def test_default_limit_skips_streams_beyond_it_without_breaking_the_connection(monkeypatch):
    monkeypatch.setattr(quic_synthetic, "_raise_stream_limits", lambda _c: 128)
    writer = SyntheticQuicWriter()

    assert writer.feed_stream("c", CLIENT, 4 * 127, b"last", now=1.0).packets
    assert writer.feed_stream("c", CLIENT, 4 * 128, b"over", now=2.0).packets == []
    assert "c" in writer
    assert writer.feed_stream("c", CLIENT, 4 * 127, b"more", now=3.0).packets


def test_server_first_stream_is_skipped_when_helpers_are_missing(monkeypatch, debug_log):
    monkeypatch.setattr(quic_synthetic, "_can_open_peer_streams", lambda _s, _r: False)
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 2, b"\x00\x04\x00", now=1.0)

    assert writer.feed_stream("c", SERVER, 0, b"early response", now=2.0).packets == []
    assert any("cannot open peer stream 0" in r.getMessage() for r in debug_log)
    assert writer.feed_stream("c", CLIENT, 4, b"request", now=3.0).packets
    assert writer.feed_stream("c", SERVER, 4, b"response", now=4.0).packets
