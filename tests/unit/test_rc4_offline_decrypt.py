"""End-to-end tests for the offline RC4 decryptor (both modes) + registration.

Mirrors ``research/memory_scan_lsass/tests/test_rc4_trial_decrypt.py``:

  * the FULL nested chain at record level — a TLS 1.3 application_data record is
    AEAD-built around an RC4 ciphertext (reusing the module's OWN key schedule),
    then peeled TLS-then-RC4 back to the exact fixture plaintext;
  * standalone-RC4 recovery straight off raw bytes;
  * key recovery from candidate BYTES when no key is supplied;
  * the dual-mode orchestrator (nested vs standalone) with the transport layer
    stubbed, so no tshark/scapy/pcap is needed;
  * the emitter emits ``DatalogEvent(protocol="rc4")`` chunks; and
  * the decryptor entry self-registers (the ``--rc4-keylog`` flag appears) with
    ``requires_tls_strip=False`` (so it runs independently but still gets the TLS
    keylog for the nested case).
"""
from __future__ import annotations

import pytest

import friTap.offline.pcap_to_tap  # noqa: F401 - import side effect: registers built-ins
from friTap.offline.rc4 import crypto
from friTap.offline.rc4 import decrypt as rc4d
from friTap.offline.rc4 import transport as rc4t
from friTap.offline.rc4.transport import Rc4Stream

KEY = b"fritap-rc4-demo-key"
PLAINTEXT = b"GET / rc4-over-tls13 nested-cipher fixture"


# --------------------------------------------------------------------------- #
# Trial decryption + candidate-byte key recovery (no key supplied)
# --------------------------------------------------------------------------- #

def test_trial_decrypt_recovers_key_from_list():
    ct = crypto.rc4(KEY, PLAINTEXT)
    cands = rc4d.materialize_candidates(
        [("x", b"wrong-key-one"), ("y", KEY), ("z", b"another-wrong")])
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["accepted"] is True
    assert r["key"] == KEY and r["plaintext"] == PLAINTEXT
    assert r["key_ascii"] == KEY.decode()


def test_key_recovered_from_candidate_bytes_when_none_supplied():
    # A fake heap page: noise, the key as an isolated allocation, more noise.
    blob = (b"\x00\x11\x22" + b"unrelated string data" + b"\x00"
            + KEY + b"\x00" + b"\x90" * 32 + b"another printable run here")
    ct = crypto.rc4(KEY, PLAINTEXT)
    cands = rc4d.materialize_candidates(
        ("candidate-bytes", k) for k in rc4d.extract_candidates(blob))
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["accepted"] is True
    assert r["key"] == KEY and r["plaintext"] == PLAINTEXT


def test_trial_decrypt_none_without_candidates():
    assert rc4d.trial_decrypt(b"whatever", []) is None


# --------------------------------------------------------------------------- #
# The full NESTED chain: TLS 1.3 record -> RC4 ciphertext -> plaintext
# --------------------------------------------------------------------------- #

def _make_app_record(secret_hex: str, suite: str, seq: int, inner: bytes):
    """One TLS 1.3 application_data record (ctype, header5, aead_fragment), built
    the same way crypto.decrypt_stream reads it."""
    key, iv = crypto.derive_key_iv(bytes.fromhex(secret_hex), suite)
    _hash, _klen, factory = crypto.SUITES[suite]
    aead = factory(key)
    length = len(inner) + 16                       # + AEAD tag
    hdr = bytes([0x17]) + b"\x03\x03" + length.to_bytes(2, "big")
    frag = aead.encrypt(crypto.record_nonce(iv, seq), inner, hdr)
    return (0x17, hdr, frag)


def test_full_nested_chain_record_level():
    pytest.importorskip("cryptography")
    secret = "22" * 48
    suite = "TLS_AES_256_GCM_SHA384"
    rc4_ct = crypto.rc4(KEY, PLAINTEXT)
    inner = rc4_ct + bytes([crypto.INNER_APPLICATION_DATA])   # content || type
    records = [_make_app_record(secret, suite, 0, inner)]

    cands = rc4d.materialize_candidates([("k", KEY), ("w", b"nope-nope-nope")])
    results = rc4d.decrypt_records_with_candidates(records, suite, secret, cands)
    assert len(results) == 1
    ct, r = results[0]
    assert ct == rc4_ct
    assert r["accepted"] is True and r["plaintext"] == PLAINTEXT


def test_rc4_cts_from_inners_filters_non_appdata():
    rc4_ct = crypto.rc4(KEY, PLAINTEXT)
    inners = [
        rc4_ct + bytes([0x17]) + b"\x00\x00",     # application_data (kept)
        b"\x04\x00\x00" + bytes([0x16]),          # handshake inner (dropped)
        b"\x00\x00",                               # all-zero padding (dropped)
    ]
    assert rc4d.rc4_cts_from_inners(inners) == [rc4_ct]


# --------------------------------------------------------------------------- #
# The dual-mode orchestrator (transport stubbed — no tshark/scapy)
# --------------------------------------------------------------------------- #

def test_orchestrator_standalone_recovers_plaintext(monkeypatch):
    rc4_ct = crypto.rc4(KEY, PLAINTEXT)
    stream = Rc4Stream(
        client_addr=("1.1.1.1", 5000), server_addr=("2.2.2.2", 8443),
        ss_family="AF_INET", directions={"write": rc4_ct},
    )
    monkeypatch.setattr(rc4t, "standalone_rc4_streams", lambda *a, **k: iter([stream]))

    cands = rc4d.materialize_candidates([("keylog", KEY)])
    stats = rc4d.Rc4Stats()
    msgs = list(rc4d.iter_decrypted_messages(
        "ignored.pcap", cands, tls_keylog_path=None, stats=stats))
    assert len(msgs) == 1
    m = msgs[0]
    assert m.message == PLAINTEXT and m.nested is False and m.direction == "write"
    assert (m.src_addr, m.src_port) == ("1.1.1.1", 5000)
    assert stats.messages == 1 and stats.streams == 1


def test_orchestrator_nested_uses_tls_keylog(monkeypatch):
    # In the nested mode the transport layer returns tshark's DECRYPTED TLS
    # plaintext, which is itself the RC4 ciphertext; only tls_keylog_path being
    # truthy selects this branch.
    rc4_ct = crypto.rc4(KEY, PLAINTEXT)
    stream = Rc4Stream(
        client_addr=("1.1.1.1", 5000), server_addr=("2.2.2.2", 443),
        ss_family="AF_INET", directions={"read": rc4_ct},
    )
    called = {}

    def fake_nested(pcap, keylog, **kw):
        called["keylog"] = keylog
        return iter([stream])

    monkeypatch.setattr(rc4t, "nested_rc4_streams", fake_nested)

    cands = rc4d.materialize_candidates([("keylog", KEY)])
    msgs = list(rc4d.iter_decrypted_messages(
        "ignored.pcap", cands, tls_keylog_path="tls.keylog"))
    assert called["keylog"] == "tls.keylog"
    assert len(msgs) == 1
    m = msgs[0]
    assert m.message == PLAINTEXT and m.nested is True and m.direction == "read"
    # read = server->client, so src is the server endpoint
    assert (m.src_addr, m.src_port) == ("2.2.2.2", 443)


def test_no_key_recovers_from_candidate_bytes(monkeypatch):
    # "recover keys from candidate bytes when no key is supplied": the trial-decrypt
    # path mines a candidate blob (e.g. an in-band key allocation) for the key and
    # keeps the one whose output looks like plaintext — no keylog needed.
    rc4_ct = crypto.rc4(KEY, PLAINTEXT)
    candidate_blob = b"\x00\x11" + KEY + b"\x00" + b"noise-run-here"
    cands = rc4d.materialize_candidates(
        ("candidate-bytes", k) for k in rc4d.extract_candidates(candidate_blob))
    r = rc4d.trial_decrypt(rc4_ct, cands)
    assert r is not None and r["accepted"] and r["plaintext"] == PLAINTEXT

    # The orchestrator's empty-candidates branch must not crash and must extract
    # candidates from the (per-direction) ciphertext blob itself.
    monkeypatch.setattr(
        rc4t, "standalone_rc4_streams",
        lambda *a, **k: iter([Rc4Stream(
            client_addr=("1.1.1.1", 5000), server_addr=("2.2.2.2", 8443),
            ss_family="AF_INET", directions={"write": rc4_ct})]))
    msgs = list(rc4d.iter_decrypted_messages("ignored.pcap", [], tls_keylog_path=None))
    assert isinstance(msgs, list)  # graceful: random ciphertext yields no key, no crash


# --------------------------------------------------------------------------- #
# Emitter emits DatalogEvent(protocol="rc4")
# --------------------------------------------------------------------------- #

class _FakeState:
    def ensure_open(self, *_a, **_k):
        return None


def test_emitter_emits_rc4_datalog_events(monkeypatch, tmp_path):
    from friTap.events import DatalogEvent, EventBus
    from friTap.offline.pcap_to_tap import ConvertResult
    from friTap.offline.rc4 import offline_decryptor as od

    msg = rc4d.DecryptedRc4Message(
        src_addr="1.1.1.1", src_port=5000, dst_addr="2.2.2.2", dst_port=8443,
        ss_family="AF_INET", direction="write", message=PLAINTEXT,
        key=KEY, source="keylog", nested=False,
    )
    # The emitter imports iter_decrypted_messages from the decrypt module at call
    # time, so patch it there. The stub records the message on the stats object the
    # emitter passes, exactly as the real orchestrator would.
    def fake_iter(*_a, stats=None, **_k):
        if stats is not None:
            stats.add_stream()
            stats.add_message()
        return iter([msg])

    monkeypatch.setattr(rc4d, "iter_decrypted_messages", fake_iter)

    keylog = tmp_path / "rc4.keylog"
    keylog.write_text(
        "RC4_KEY 6672697461702d7263342d64656d6f2d6b6579 19 RC4_set_key unknown 4711\n")

    bus = EventBus()
    seen = []
    bus.subscribe(DatalogEvent, lambda ev: seen.append(ev))
    result = ConvertResult(tap_path=str(tmp_path / "out.tap"))

    od._emit_rc4_streams(
        "ignored.pcap", str(keylog), None,
        tshark_bin="tshark", tls_ports=(443,),
        bus=bus, state=_FakeState(), result=result,
    )
    assert len(seen) == 1
    assert seen[0].protocol == "rc4" and seen[0].data == PLAINTEXT
    assert result.decrypted_packet_count == 1
    assert result.per_protocol["rc4"]["messages"] == 1


# --------------------------------------------------------------------------- #
# Registration / CLI / requires_tls_strip
# --------------------------------------------------------------------------- #

def test_rc4_entry_registered():
    from friTap.offline.registry import get_offline_decryptor_registry

    entry = get_offline_decryptor_registry().get("rc4")
    assert entry is not None
    assert entry.cli_flag == "--rc4-keylog"
    assert entry.cli_dest == "rc4_keylog"
    assert entry.requires_tls_strip is False   # independent, but still gets TLS keylog
    assert entry.layer_cls.__name__ == "Rc4Layer"
    assert entry.counter_prefix == "rc4"


def test_rc4_cli_flag_present():
    from friTap.offline.cli import _build_parser

    parser = _build_parser()
    help_text = parser.format_help()
    assert "--rc4-keylog" in help_text


# --------------------------------------------------------------------------- #
# S-box (memscan-sbox) consumption, known-plaintext acceptance, candidate shapes
# (the faster/reliable RC4-recovery workstream)
# --------------------------------------------------------------------------- #

def test_sbox_candidate_decrypts_via_skip_ksa():
    """A candidate flagged is_sbox is used as keystream directly (skip KSA)."""
    ct = crypto.rc4(KEY, PLAINTEXT)
    sbox = bytes(crypto.rc4_ksa(KEY))               # the post-KSA permutation
    cands = rc4d.materialize_candidates(
        [rc4d.Rc4Candidate("memscan-sbox", sbox, is_sbox=True)])
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["accepted"] is True
    assert r["plaintext"] == PLAINTEXT
    assert r["key_ascii"] is None                    # an S-box has no ASCII key form


def test_sbox_bytes_as_key_would_fail_without_flag():
    """Same 256 bytes without the flag are (wrongly) KSA'd -> does not recover."""
    ct = crypto.rc4(KEY, PLAINTEXT)
    sbox = bytes(crypto.rc4_ksa(KEY))
    cands = rc4d.materialize_candidates([("memscan-sbox", sbox)])  # is_sbox defaults False
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["plaintext"] != PLAINTEXT and r["accepted"] is False


def test_known_plaintext_exact_accept_overrides_score():
    ct = crypto.rc4(KEY, PLAINTEXT)
    cands = rc4d.materialize_candidates([("y", KEY), ("x", b"wrong-key-one")])
    r = rc4d.trial_decrypt(ct, cands, known_plaintext=b"GET /")
    assert r is not None and r["accepted"] is True and r["key"] == KEY


def test_known_plaintext_rejects_wrong_key_even_if_printable():
    # Only a wrong key is offered; a known-plaintext gate must NOT accept it.
    ct = crypto.rc4(KEY, PLAINTEXT)
    cands = rc4d.materialize_candidates([("x", b"totally-wrong-key")])
    r = rc4d.trial_decrypt(ct, cands, known_plaintext=b"GET /")
    assert r is not None and r["accepted"] is False


def test_strict_accept_rejects_single_token_noise():
    """Random-ish output containing a lone token byte must NOT be accepted."""
    ct = crypto.rc4(KEY, PLAINTEXT)
    # A wrong key yields ~random output; the strict combined-score rule rejects it.
    cands = rc4d.materialize_candidates([("x", b"definitely-not-the-key-xyz")])
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["accepted"] is False


def test_candidate_and_tuple_forms_both_accepted():
    ct = crypto.rc4(KEY, PLAINTEXT)
    mixed = [("tuple-form", b"wrong"), rc4d.Rc4Candidate("obj-form", KEY)]
    cands = rc4d.materialize_candidates(mixed)
    # unpacking still works (backward-compat), and the object carries is_sbox
    assert all(len(c) == 2 for c in cands)
    r = rc4d.trial_decrypt(ct, cands)
    assert r is not None and r["accepted"] is True and r["key"] == KEY


# --------------------------------------------------------------------------- #
# Defect 3: custom TLS-port plumbing through the nested RC4-in-TLS transport.
# The offline chain already honours tls_ports end-to-end; the capture-side fix
# ensures a non-standard port (e.g. 8443) actually reaches the manifest. These
# lock the transport contract so the recovered port drives tshark's Decode-As.
# (tshark's TLS dissector heuristically detects handshakes regardless of the
# Decode-As port, so an e2e "443 finds none / 8443 finds one" assertion is not
# reliable across environments; we assert the plumbing instead.)
# --------------------------------------------------------------------------- #

def test_nested_rc4_streams_passes_custom_tls_port_to_tshark(monkeypatch):
    """A non-standard tls_ports value (8443) is forwarded to both
    ``list_tls_streams`` and ``follow_tls_stream`` (tshark Decode-As)."""
    from friTap.offline import tshark as tshark_mod

    seen = {}

    def fake_list(bin_path, pcap, keylog, *, tls_ports):
        seen["list"] = tuple(tls_ports)
        return [0]

    def fake_follow(bin_path, pcap, stream_id, keylog, *, tls_ports):
        seen["follow"] = tuple(tls_ports)
        return (("1.1.1.1", 5000, "2.2.2.2", 8443), [("write", b"ciphertext")])

    monkeypatch.setattr(tshark_mod, "find_tshark", lambda _: "tshark")
    monkeypatch.setattr(tshark_mod, "list_tls_streams", fake_list)
    monkeypatch.setattr(tshark_mod, "follow_tls_stream", fake_follow)

    streams = list(rc4t.nested_rc4_streams(
        "x.pcap", "k.log", tls_ports=(8443,)))

    assert len(streams) == 1
    assert 8443 in seen["list"]
    assert 8443 in seen["follow"]


def test_nested_rc4_streams_defaults_to_443_when_no_ports(monkeypatch):
    """The documented fallback: an empty tls_ports still Decode-As 443, so
    standard-port captures keep working with an empty manifest."""
    from friTap.offline import tshark as tshark_mod

    seen = {}

    def fake_list(bin_path, pcap, keylog, *, tls_ports):
        seen["list"] = tuple(tls_ports)
        return []

    monkeypatch.setattr(tshark_mod, "find_tshark", lambda _: "tshark")
    monkeypatch.setattr(tshark_mod, "list_tls_streams", fake_list)

    list(rc4t.nested_rc4_streams("x.pcap", "k.log"))

    assert seen["list"] == (443,)
