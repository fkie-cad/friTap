"""Hardening of the MTProto/TL parsers against hostile (attacker-controlled) input.

Decrypted Telegram traffic and third-party pcaps are untrusted: these tests pin
the work / memory budgets added to the tolerant parsers (vector scan, gzip
budget, caches, key-id set, IGE fallback, E2E blob scan) while the existing
``test_mtproto_*`` / ``test_tl_*`` suites guard that normal output is unchanged.
"""

from __future__ import annotations

import os
import random
import time
import tracemalloc
import zlib

import pytest

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.content import (
    _INPUT_PEER_USER_FROM_MSG,
    _Reader,
    _skip_input_peer,
    _TLError,
    parse_mtproto_message,
)
from friTap.offline.mtproto.crossref import (
    MAX_STORED_ACKS,
    CrossRefIndex,
    extract_record_refs,
)
from friTap.offline.mtproto.e2e.decrypt import iter_e2e_blobs
from friTap.offline.mtproto.records import MAX_UNKNOWN_KEY_IDS, MtprotoStats
from friTap.offline.mtproto.tl import decoder as tl_decoder
from friTap.offline.mtproto.tl.decoder import (
    MAX_CACHED_PAYLOAD,
    TlLimits,
    decode_tl,
    decode_tl_cached,
    rpc_result_ctor_id,
)
from friTap.offline.mtproto.tl.nodes import TlNode, iter_nodes
from tests.unit._tl_helpers import (
    INPUT_PEER_EMPTY,
    PONG,
    VECTOR,
    container,
    gzip_packed,
    i32,
    i64,
    msgs_ack,
    pong,
    rpc_result,
    synthetic_user,
    u32,
)

_UPDATES = 0x74AE4240
_MIB = 1024 * 1024


# --------------------------------------------------------------------------- #
# 1. Vector scan: linear time, bounded work
# --------------------------------------------------------------------------- #

def test_vector_ctor_flood_completes_fast():
    """Vector ids at every offset (nested Vector-of-Vector chains) stay linear."""
    payload = u32(_UPDATES) + (u32(VECTOR) + i32(1)) * (2 * _MIB // 8)
    started = time.perf_counter()
    parse_mtproto_message(payload)
    assert time.perf_counter() - started < 2.0


def test_vector_count_zero_flood_completes_fast():
    payload = u32(_UPDATES) + (u32(VECTOR) + i32(0)) * (2 * _MIB // 8)
    started = time.perf_counter()
    parse_mtproto_message(payload)
    assert time.perf_counter() - started < 2.0


def test_misaligned_vector_ids_are_ignored_like_before():
    """Only 4-aligned Vector ids open a scan candidate (byte-shifted ones do not)."""
    user_vector = u32(VECTOR) + i32(1) + synthetic_user()
    aligned = parse_mtproto_message(u32(_UPDATES) + user_vector)
    shifted = parse_mtproto_message(u32(_UPDATES) + b"\x00" + user_vector)
    assert [m.kind for m in aligned if m.kind == "user"] == ["user"]
    assert not [m for m in shifted if m.kind == "user"]


def test_scan_still_surfaces_users_after_padding():
    payload = u32(_UPDATES) + i32(7) * 64 + u32(VECTOR) + i32(2) + synthetic_user() * 2
    users = [m for m in parse_mtproto_message(payload) if m.kind == "user"]
    assert len(users) == 2


# --------------------------------------------------------------------------- #
# 2. gzip_packed: total inflate budget + nesting depth
# --------------------------------------------------------------------------- #

def _zero_bomb(size: int) -> bytes:
    """A gzip_packed whose body inflates to *size* zero bytes (~KBs packed)."""
    return gzip_packed(b"\x00" * size, compress=lambda data: zlib.compress(data, 9))


def test_decode_tl_total_inflate_budget_bounds_memory():
    bomb = container(*[_zero_bomb(12 * _MIB) for _ in range(5)])
    tracemalloc.start()
    try:
        root = decode_tl(bomb)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    notes = [n.note for n in iter_nodes(root) if n.kind == "gzip"]
    assert any("budget" in note for note in notes)
    # Unbounded, five 12 MiB bodies would be kept in the tree (60+ MiB).
    assert peak < 48 * _MIB


def test_decode_tl_nested_gzip_depth_is_capped():
    two = decode_tl(gzip_packed(gzip_packed(pong())))
    three = decode_tl(gzip_packed(gzip_packed(gzip_packed(pong()))))
    assert any(n.name == "pong" for n in iter_nodes(two))
    assert not any(n.name == "pong" for n in iter_nodes(three))
    assert any("nested deeper" in n.note for n in iter_nodes(three) if n.kind == "gzip")


def test_decode_tl_skips_inflation_in_advance_only_mode(monkeypatch):
    calls = []
    real = tl_decoder.inflate_bounded_checked
    monkeypatch.setattr(tl_decoder, "inflate_bounded_checked",
                        lambda *a, **k: calls.append(1) or real(*a, **k))
    # Vector items past keep_vector_items are walked but never built.
    payload = u32(VECTOR) + i32(30) + gzip_packed(pong()) * 30
    root = decode_tl(payload, limits=TlLimits(keep_vector_items=2))
    assert root.fields[0].value.total == 30
    assert len(calls) == 2


def test_content_parser_respects_total_inflate_budget(monkeypatch):
    limits = []
    real = __import__("friTap.offline.mtproto.content", fromlist=["x"]).inflate_bounded_checked

    def spy(packed, limit):
        limits.append(limit)
        return real(packed, limit)

    monkeypatch.setattr("friTap.offline.mtproto.content.inflate_bounded_checked", spy)
    bomb = container(*[_zero_bomb(12 * _MIB) for _ in range(5)])
    started = time.perf_counter()
    parse_mtproto_message(bomb)
    assert time.perf_counter() - started < 5.0
    assert len(limits) == 3                   # 12 + 12 + (8 left → rejected), then none
    assert limits[2] == 8 * _MIB


def test_content_parser_nested_gzip_depth():
    two = parse_mtproto_message(gzip_packed(gzip_packed(pong())))
    three = parse_mtproto_message(gzip_packed(gzip_packed(gzip_packed(pong()))))
    assert any(m.method == "pong" for m in two)
    assert not any(m.method == "pong" for m in three)


# --------------------------------------------------------------------------- #
# 3. rpc_result_ctor_id inflates only 4 bytes
# --------------------------------------------------------------------------- #

def test_rpc_result_ctor_id_peeks_big_gzip_cheaply():
    payload = rpc_result(1, gzip_packed(pong() + b"\x00" * (15 * _MIB)))
    tracemalloc.start()
    try:
        started = time.perf_counter()
        ctor = rpc_result_ctor_id(payload)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert ctor == PONG
    assert elapsed < 0.5
    assert peak < len(payload) + _MIB


def test_rpc_result_ctor_id_edge_cases():
    assert rpc_result_ctor_id(rpc_result(1, pong())) == PONG
    assert rpc_result_ctor_id(rpc_result(1, gzip_packed(b"\x01\x02"))) is None  # < 4 B
    assert rpc_result_ctor_id(rpc_result(1, u32(0x3072CFA1) + b"\x08garbage!!!")) is None
    assert rpc_result_ctor_id(pong()) is None


# --------------------------------------------------------------------------- #
# 4. Caches skip large payloads
# --------------------------------------------------------------------------- #

def test_decode_tl_cached_skips_large_payloads():
    decode_tl_cached.cache_clear()
    small = pong(9, 9)
    assert decode_tl_cached(small) is decode_tl_cached(small)
    big = msgs_ack(*range(MAX_CACHED_PAYLOAD // 8 + 8))
    first = decode_tl_cached(big)
    assert first is not decode_tl_cached(big)
    assert first == decode_tl(big)
    assert decode_tl_cached.cache_info().currsize == 1


def test_rpc_result_name_cache_skips_large_payloads():
    from friTap.offline.mtproto import tl_parser

    tl_parser._rpc_result_name_cached.cache_clear()
    big = rpc_result(1, pong() + b"\x00" * (MAX_CACHED_PAYLOAD + 4))
    assert tl_parser._rpc_result_name(big) == "pong"
    assert tl_parser._rpc_result_name_cached.cache_info().currsize == 0
    assert tl_parser._rpc_result_name(rpc_result(1, pong())) == "pong"
    assert tl_parser._rpc_result_name_cached.cache_info().currsize == 1


# --------------------------------------------------------------------------- #
# 5. Cross-reference caps
# --------------------------------------------------------------------------- #

def test_ack_ids_are_capped_but_counted():
    ids = list(range(1, MAX_STORED_ACKS * 2 + 1))
    ref = extract_record_refs(msgs_ack(*ids), record_seq=1, auth_key_id="ak",
                              direction="write", msg_id=5)
    assert len(ref.acked_ids) == MAX_STORED_ACKS
    assert ref.acked_ids == tuple(ids[:MAX_STORED_ACKS])
    index = CrossRefIndex()
    index.add(ref)
    assert index.resolve(1)["acks_total"] == len(ids)


def test_telegram_refs_cap_users_and_chat_nodes(monkeypatch):
    from friTap.offline.mtproto import offline_decryptor as od

    monkeypatch.setattr(od, "MAX_USERS_PER_RECORD", 3)
    monkeypatch.setattr(od, "MAX_USERS_TOTAL", 5)
    monkeypatch.setattr(od, "MAX_CHAT_NODES_PER_RECORD", 2)
    monkeypatch.setattr(od, "MAX_CHAT_NODES_TOTAL", 3)
    refs = od._TelegramRefs()
    refs._keep_users(1, [{"id": i} for i in range(10)])
    refs._keep_users(2, [{"id": i} for i in range(10)])
    refs._keep_users(3, [{"id": 99}])
    assert [len(refs.users_by_seq[s]) for s in (1, 2)] == [3, 2]
    assert 3 not in refs.users_by_seq
    assert refs.users_dropped == 7 + 8 + 1
    refs._keep_chat_nodes(iter(range(5)))
    refs._keep_chat_nodes(iter(range(5)))
    assert refs.chat_nodes == [0, 1, 0]
    assert refs.chat_nodes_dropped == 7


# --------------------------------------------------------------------------- #
# 6. unknown_key_ids capped
# --------------------------------------------------------------------------- #

def test_unknown_key_ids_capped_with_overflow_counter():
    stats = MtprotoStats()
    for n in range(MAX_UNKNOWN_KEY_IDS + 100):
        stats.add_unknown_key(f"{n:016x}")
    stats.add_unknown_key(f"{0:016x}")            # already known: still counted
    assert len(stats.unknown_key_ids) == MAX_UNKNOWN_KEY_IDS
    assert stats.unknown_key_ids[f"{0:016x}"] == 2
    assert stats.unknown_key_ids_overflow == 100
    assert stats.records_unknown_key == MAX_UNKNOWN_KEY_IDS + 101


# --------------------------------------------------------------------------- #
# 7. Pure-Python IGE fallback + record size cap
# --------------------------------------------------------------------------- #

def _reference_ige(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """The previous per-block implementation (one ECB cipher per block)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def ecb(block: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        ctx = cipher.encryptor() if encrypt else cipher.decryptor()
        return ctx.update(block) + ctx.finalize()

    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    iv1, iv2 = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if encrypt:
            result = xor(ecb(xor(block, iv1)), iv2)
            iv1, iv2 = result, block
        else:
            result = xor(ecb(xor(block, iv2)), iv1)
            iv1, iv2 = block, result
        out += result
    return bytes(out)


@pytest.fixture
def python_ige(monkeypatch):
    crypto._resolve_backend()
    if crypto._ECB_CIPHER is None:
        pytest.skip("cryptography backend not installed")
    monkeypatch.setattr(crypto, "_TGCRYPTO", None)


# Known-answer vector (AES-256-IGE, key = 00..1f, iv = 20..3f, pt = 40..7f).
_KAT_KEY = bytes(range(32))
_KAT_IV = bytes(range(32, 64))
_KAT_PT = bytes(range(64, 128))


def test_ige_fallback_matches_reference_known_answer(python_ige):
    expected = _reference_ige(_KAT_KEY, _KAT_IV, _KAT_PT, encrypt=True)
    assert crypto.aes_ige_encrypt(_KAT_KEY, _KAT_IV, _KAT_PT) == expected
    assert crypto.aes_ige_decrypt(_KAT_KEY, _KAT_IV, expected) == _KAT_PT


def test_ige_fallback_matches_reference_on_random_data(python_ige):
    rng = random.Random(1234)
    for blocks in (1, 2, 7, 64):
        key, iv = rng.randbytes(32), rng.randbytes(32)
        data = rng.randbytes(16 * blocks)
        assert crypto.aes_ige_decrypt(key, iv, data) == _reference_ige(key, iv, data, False)
        assert crypto.aes_ige_encrypt(key, iv, data) == _reference_ige(key, iv, data, True)


def test_ige_fallback_matches_tgcrypto_when_installed():
    tgcrypto = pytest.importorskip("tgcrypto")
    key, iv, data = os.urandom(32), os.urandom(32), os.urandom(256)
    assert _reference_ige(key, iv, data, False) == tgcrypto.ige256_decrypt(data, key, iv)


def test_ige_fallback_works_with_per_call_ecb_helpers_only(python_ige, monkeypatch):
    monkeypatch.setattr(crypto, "_ECB_CIPHER", None)
    data = os.urandom(48)
    assert crypto.aes_ige_decrypt(_KAT_KEY, _KAT_IV, data) == \
        _reference_ige(_KAT_KEY, _KAT_IV, data, False)


def test_decrypt_record_rejects_oversized_frame_before_decrypting(monkeypatch):
    monkeypatch.setattr(crypto, "aes_ige_decrypt",
                        lambda *a: pytest.fail("oversized record was decrypted"))
    outer = bytes(crypto.MAX_RECORD_LEN + 16)
    with pytest.raises(crypto.MtprotoCryptoError, match="exceeds"):
        crypto.decrypt_record(bytes(256), outer, "read")


def test_secret_chat_fingerprint_rejects_wrong_length_with_value_error():
    with pytest.raises(ValueError):
        crypto.compute_secret_chat_fingerprint(bytes(10))


# --------------------------------------------------------------------------- #
# 8. iter_e2e_blobs equivalence
# --------------------------------------------------------------------------- #

def _reference_iter_e2e_blobs(data: bytes, fingerprints):
    """The previous byte-by-byte scanner, kept as the equivalence oracle."""
    if not fingerprints:
        return
    p, n = 0, len(data)
    while p + 8 <= n:
        fp = data[p:p + 8]
        if fp not in fingerprints:
            p += 1
            continue
        length = None
        if p >= 1 and data[p - 1] < 254:
            length = data[p - 1]
        elif p >= 4 and data[p - 4] == 0xFE:
            length = int.from_bytes(data[p - 3:p], "little")
        if length is not None and length >= 40 and (length - 24) % 16 == 0 and p + length <= n:
            yield fp, data[p:p + length]
            p += length
            continue
        p += 1


def _plant_blobs(rng: random.Random, fps) -> bytes:
    out = bytearray(rng.randbytes(rng.randrange(0, 64)))
    for _ in range(rng.randrange(1, 12)):
        fp = rng.choice(fps)
        body_blocks = rng.randrange(1, 20)
        length = 24 + 16 * body_blocks + rng.choice((0, 0, 0, 5))  # some invalid
        if rng.random() < 0.3:
            out += b"\xfe" + length.to_bytes(3, "little")
        else:
            out += bytes([length & 0xFF])
        out += fp + rng.randbytes(max(0, length - 8 - rng.choice((0, 0, 30))))
        out += fp[: rng.randrange(0, 9)]          # partial / overlapping copies
        out += rng.randbytes(rng.randrange(0, 40))
    return bytes(out)


def test_iter_e2e_blobs_equivalent_on_random_data():
    rng = random.Random(4242)
    fps = [rng.randbytes(8) for _ in range(3)] + [b"\x01" * 8]
    for _ in range(300):
        data = _plant_blobs(rng, fps)
        chosen = set(rng.sample(fps, rng.randrange(0, len(fps) + 1)))
        assert list(iter_e2e_blobs(data, chosen)) == \
            list(_reference_iter_e2e_blobs(data, chosen))


def test_iter_e2e_blobs_ignores_wrong_length_fingerprints():
    data = bytes([40]) + b"A" * 8 + bytes(32)
    assert list(iter_e2e_blobs(data, {b"A" * 7})) == []
    assert list(iter_e2e_blobs(data, {b"A" * 8})) == [(b"A" * 8, data[1:41])]


def test_iter_e2e_blobs_fast_on_large_input():
    data = os.urandom(8 * _MIB)
    started = time.perf_counter()
    list(iter_e2e_blobs(data, {os.urandom(8) for _ in range(4)}))
    assert time.perf_counter() - started < 1.0


# --------------------------------------------------------------------------- #
# 9. Small recursion / progress guards
# --------------------------------------------------------------------------- #

def test_skip_input_peer_from_message_chain_is_depth_capped():
    one = u32(_INPUT_PEER_USER_FROM_MSG) + u32(INPUT_PEER_EMPTY) + i32(1) + i64(2)
    reader = _Reader(one)
    _skip_input_peer(reader)
    assert reader.remaining == 0
    deep = u32(_INPUT_PEER_USER_FROM_MSG) * 50 + u32(INPUT_PEER_EMPTY)
    with pytest.raises(_TLError, match="too deep"):
        _skip_input_peer(_Reader(deep))


def test_vector_of_zero_size_elements_requires_progress():
    from friTap.offline.mtproto.tl.registry import load_schema
    from friTap.offline.mtproto.tl.schema import parse_type

    dec = tl_decoder._TlDecoder(load_schema("mtproto"), TlLimits(), None)
    reader = tl_decoder._Reader(i32(100_000) + bytes(400_000))
    with pytest.raises(tl_decoder._Abort) as info:
        dec._read_vector_body(reader, parse_type("true"), 0)
    assert "stopped at item 0" in info.value.partial.note


def test_hostile_inputs_never_raise():
    rng = random.Random(7)
    for _ in range(200):
        blob = rng.randbytes(rng.randrange(0, 512))
        parse_mtproto_message(blob)
        assert isinstance(decode_tl(blob), TlNode)
        rpc_result_ctor_id(blob)
