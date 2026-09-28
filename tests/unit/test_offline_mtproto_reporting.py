"""Reporting/accuracy tests for the offline MTProto decryptor (Workstream E).

Covers the four behaviours added in Workstream E, all hermetic (no device, no
Frida, and mostly no pcap — ``_process_stream`` is driven with hand-built
``StreamPair`` fixtures so each classification is exercised in isolation):

  * E1: an init-less stream to a NON-Telegram peer is NOT counted as an MTProto
    degraded stream (it lands in the separate non-MTProto bucket);
  * E2: a stream with a valid init block but a LATER gap decrypts its pre-gap
    records and is counted ``partial`` instead of being discarded whole;
  * E3: a mid-stream (no-SYN) session to a Telegram DC whose init we never saw is
    classified degraded (recoverable) rather than silently dropped;
  * E4: the ``--ms-emit-unconfirmed`` opt-in gates both the mtproto profile stamp
    and the writing of an unconfirmed candidate line to the .mtproto.keylog;
  * E5: the new ``MtprotoStats`` counters and the enriched CLI summary breakdown.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.decrypt import (
    _has_mtproto_evidence,
    _is_telegram_dc,
    _process_stream,
)
from friTap.offline.mtproto.reassembly import StreamPair
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import derive_obfuscation_keys
from friTap.protocols.mtproto_keylog_spec import MtprotoAuthKey
from tests.unit._mtproto_helpers import aes_ctr as _ctr
from tests.unit._mtproto_helpers import build_obf_init as _build_init
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

_TELEGRAM_DC = "149.154.167.51"   # inside 149.154.160.0/20
_NON_TELEGRAM = "93.184.216.34"   # example.com — not a Telegram DC
_CLIENT = ("10.0.0.5", 50000)


# --------------------------------------------------------------------------- #
# The Telegram-DC evidence heuristic (E1)
# --------------------------------------------------------------------------- #


def test_is_telegram_dc_recognizes_published_ranges():
    assert _is_telegram_dc(_TELEGRAM_DC) is True
    assert _is_telegram_dc("91.108.56.130") is True
    assert _is_telegram_dc(_NON_TELEGRAM) is False
    assert _is_telegram_dc("not-an-ip") is False


def test_evidence_is_true_when_either_endpoint_is_a_dc():
    dc_pair = StreamPair(_CLIENT, (_TELEGRAM_DC, 443), "AF_INET")
    plain_pair = StreamPair(_CLIENT, (_NON_TELEGRAM, 443), "AF_INET")
    assert _has_mtproto_evidence(dc_pair) is True
    assert _has_mtproto_evidence(plain_pair) is False


# --------------------------------------------------------------------------- #
# E1 — init-less streams are only MTProto-degraded with evidence
# --------------------------------------------------------------------------- #


def _init_less_pair(server_ip: str) -> StreamPair:
    """A client stream with a start gap (contiguous run < 64 bytes)."""
    pair = StreamPair(_CLIENT, (server_ip, 443), "AF_INET")
    pair.client.feed(1000, b"", syn=True)   # anchor at 1001
    pair.client.feed(1200, os.urandom(200))  # start gap -> contiguous empty
    return pair


def test_non_mtproto_degraded_stream_is_not_counted_as_mtproto_degraded():
    stats = MtprotoStats()
    out = list(_process_stream(_init_less_pair(_NON_TELEGRAM), {}, stats))
    assert out == []
    # The whole point of E1: this must NOT inflate the MTProto degraded number.
    assert stats.streams_degraded == 0
    assert stats.streams_degraded_non_mtproto == 1


def test_init_less_stream_to_a_dc_is_counted_short_not_mid_connection():
    # D3: a SYN was seen but a start gap swallowed the opening obfuscation bytes,
    # so the contiguous run never reached 64 bytes. This is a SHORT/lossy stream,
    # NOT a connection captured mid-flow — it must NOT inflate streams_degraded
    # (which the TUI/CLI report as "started mid-connection").
    stats = MtprotoStats()
    out = list(_process_stream(_init_less_pair(_TELEGRAM_DC), {}, stats))
    assert out == []
    assert stats.streams_short == 1
    assert stats.streams_degraded == 0
    assert stats.streams_degraded_non_mtproto == 0


# --------------------------------------------------------------------------- #
# E3 — no-SYN mid-stream to a DC is degraded (recoverable), not dropped
# --------------------------------------------------------------------------- #


def test_mid_stream_no_syn_to_dc_is_degraded_not_silently_dropped():
    # Full 64+ bytes but NO SYN and no valid transport tag: the bytes are not the
    # real init. To a Telegram DC this is a genuine mid-stream session.
    pair = StreamPair(_CLIENT, (_TELEGRAM_DC, 443), "AF_INET")
    pair.client.feed(1000, os.urandom(200))  # no SYN -> anchor untrusted
    stats = MtprotoStats()
    assert list(_process_stream(pair, {}, stats)) == []
    assert stats.streams_degraded == 1


def test_mid_stream_no_syn_to_non_dc_stays_a_silent_false_positive_skip():
    pair = StreamPair(_CLIENT, (_NON_TELEGRAM, 443), "AF_INET")
    pair.client.feed(1000, os.urandom(200))
    stats = MtprotoStats()
    assert list(_process_stream(pair, {}, stats)) == []
    assert stats.streams_degraded == 0
    assert stats.streams_degraded_non_mtproto == 0


# --------------------------------------------------------------------------- #
# E2 — valid init + later gap decrypts the pre-gap prefix and counts partial
# --------------------------------------------------------------------------- #


def test_valid_init_with_later_gap_decrypts_prefix_and_counts_partial():
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    aid = crypto.compute_auth_key_id(auth_key)
    keymap = {aid: MtprotoAuthKey(dc_id=2, auth_key_id=aid, auth_key=auth_key)}

    init = _build_init(b"\xee\xee\xee\xee")  # intermediate
    frame1 = _intermediate_frame(crypto.build_encrypted_record(auth_key, b"first", "write"))
    frame2 = _intermediate_frame(crypto.build_encrypted_record(auth_key, b"second", "write"))
    server_frame = _intermediate_frame(
        crypto.build_encrypted_record(auth_key, b"reply", "read")
    )

    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
    out = _ctr(key_out, iv_out)
    out.update(init)  # advance the keystream over the init block
    client_ct = out.update(frame1 + frame2)
    client_wire = init + client_ct
    server_wire = _ctr(key_in, iv_in).update(server_frame)

    pair = StreamPair(_CLIENT, (_TELEGRAM_DC, 443), "AF_INET")
    prefix_len = 64 + len(frame1)           # init + the FIRST record only
    pair.client.feed(99, b"", syn=True)     # anchor at 100
    pair.client.feed(100, client_wire[:prefix_len])
    # A hole, then the rest of the stream: a genuine mid-stream gap after the init.
    pair.client.feed(100 + prefix_len + 5, client_wire[prefix_len:])
    pair.server.feed(200, server_wire)

    stats = MtprotoStats()
    out_msgs = list(_process_stream(pair, keymap, stats))

    # Only the contiguous pre-gap records decrypt; ``second`` is past the gap.
    decrypted = {m.message for m in out_msgs}
    assert b"first" in decrypted
    assert b"reply" in decrypted
    assert b"second" not in decrypted
    # Counted as partial rather than discarded whole, and NOT as degraded.
    assert stats.streams_partial == 1
    assert stats.streams_degraded == 0
    assert stats.streams_degraded_non_mtproto == 0


# --------------------------------------------------------------------------- #
# D5 — a known-but-unsupported transport framing is NOT "mid-connection"
# --------------------------------------------------------------------------- #


def test_unsupported_framing_stream_is_not_counted_mid_connection():
    # A valid init block that de-obfuscates to the padded-intermediate tag: the
    # connection START was captured, only the framing is undecodable. It must land
    # in streams_unsupported_framing, NOT streams_degraded ("mid-connection").
    init = _build_init(b"\xdd\xdd\xdd\xdd")  # padded-intermediate tag
    key_out, iv_out, _key_in, _iv_in = derive_obfuscation_keys(init)
    out = _ctr(key_out, iv_out)
    out.update(init)                      # advance the keystream past the init
    client_wire = init + out.update(b"\x00" * 32)  # some obfuscated payload

    pair = StreamPair(_CLIENT, (_TELEGRAM_DC, 443), "AF_INET")
    pair.client.feed(99, b"", syn=True)   # anchor at 100
    pair.client.feed(100, client_wire)

    stats = MtprotoStats()
    assert list(_process_stream(pair, {}, stats)) == []
    assert stats.streams_unsupported_framing == 1
    assert stats.streams_degraded == 0
    assert stats.streams_short == 0


# --------------------------------------------------------------------------- #
# E5 — the new counters and the enriched CLI summary
# --------------------------------------------------------------------------- #


def test_new_counters_each_bump_their_own_field():
    stats = MtprotoStats()
    stats.add_degraded()
    stats.add_degraded_non_mtproto()
    stats.add_degraded_non_mtproto()
    stats.add_partial()
    stats.add_short_stream()
    stats.add_unsupported_framing()
    stats.add_unsupported_framing()
    assert stats.streams_degraded == 1            # kept name/semantics (TUI reads it)
    assert stats.streams_degraded_non_mtproto == 2
    assert stats.streams_partial == 1
    # The new honest-diagnostics counters each bump their OWN field and never the
    # mid-connection figure.
    assert stats.streams_short == 1
    assert stats.streams_unsupported_framing == 2
    # The new counters do not perturb the derived undecryptable total.
    assert stats.records_undecryptable == 0


def test_short_and_unsupported_framing_do_not_count_as_degraded_in_cli(capsys):
    from friTap.offline import cli

    result = SimpleNamespace(
        tap_path="out.tap", flow_count=0, decrypted_packet_count=0, stream_count=2,
        dropped_packet_count=0, encrypted_streams_skipped=0,
        per_protocol={
            "mtproto": {
                "messages": 0, "undecryptable": 0, "degraded": 0,
                "short": 3, "unsupported_framing": 2,
            }
        },
        findings_count=0,
    )
    cli._print_summary(result, run_scan=False)
    out = capsys.readouterr().out
    assert "short streams: 3" in out
    assert "unsupported-framing streams: 2" in out
    # Crucially NOT reported under the mid-connection "degraded streams" line.
    assert "degraded streams" not in out
    assert "started mid-stream" not in out


def test_cli_summary_prints_the_richer_degraded_breakdown(capsys):
    from friTap.offline import cli

    result = SimpleNamespace(
        tap_path="out.tap", flow_count=1, decrypted_packet_count=2, stream_count=3,
        dropped_packet_count=0, encrypted_streams_skipped=0,
        per_protocol={
            "mtproto": {
                "messages": 5, "undecryptable": 0, "degraded": 2,
                "degraded_non_mtproto": 7, "partial": 1,
            }
        },
        findings_count=0,
    )
    cli._print_summary(result, run_scan=False)
    out = capsys.readouterr().out
    assert "partial streams: 1" in out
    assert "degraded streams: 2" in out
    assert "non-mtproto degraded streams: 7" in out


def test_cli_summary_omits_new_lines_when_absent(capsys):
    # Back-compat: a bucket without the new keys prints exactly as before.
    from friTap.offline import cli

    result = SimpleNamespace(
        tap_path="out.tap", flow_count=1, decrypted_packet_count=2, stream_count=1,
        dropped_packet_count=0, encrypted_streams_skipped=0,
        per_protocol={"mtproto": {"messages": 3, "undecryptable": 0, "degraded": 0}},
        findings_count=0,
    )
    cli._print_summary(result, run_scan=False)
    out = capsys.readouterr().out
    assert "partial streams" not in out
    assert "non-mtproto degraded streams" not in out
