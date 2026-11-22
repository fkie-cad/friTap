"""Tests for the faster AppLovin salt scan: parallel windows, blob ordering, hooks."""

from __future__ import annotations

import base64
import hashlib
import random
import sys
import types
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from friTap.parsers.app_ciphers import applovin_keys as ak
from friTap.parsers.app_ciphers import salt_scan_pool as pool_mod

SALT21 = bytes(range(0xA1, 0xA1 + 21))
SALT32 = SALT21 + bytes(11)
PROTOCOL_ID = ak.protocol_id_for_salt(SALT32)
TARGET = bytes.fromhex(PROTOCOL_ID)
CANDIDATES_MODULE = "friTap.parsers.app_ciphers.salt_candidates"


def _blob_with_salt(size: int, offset: int, seed: int = 7) -> bytes:
    data = bytearray(random.Random(seed).randbytes(size))
    data[offset:offset + 21] = SALT21
    return bytes(data)


# --------------------------------------------------------------------------
# Parallel == serial
# --------------------------------------------------------------------------

CHUNK = 1000


@pytest.mark.parametrize("offset", [0, CHUNK - 10, CHUNK - 1, CHUNK, 2 * CHUNK - 5, 4096 - 21, 4096 - 3])
def test_parallel_matches_serial_incl_chunk_straddle(offset):
    blob = _blob_with_salt(4096, offset)
    with ThreadPoolExecutor(4) as pool:
        parallel = ak._scan_raw_windows_parallel(blob, TARGET, pool, chunk=CHUNK)
    assert parallel == ak._scan_raw_windows(blob, TARGET) == SALT32


def test_parallel_no_match():
    blob = random.Random(1).randbytes(5000)
    with ThreadPoolExecutor(3) as pool:
        assert ak._scan_raw_windows_parallel(blob, TARGET, pool, chunk=CHUNK) is None


def test_scan_window_range_reports_absolute_offset():
    blob = _blob_with_salt(200, 50)
    padded = ak._padded_for_windows(blob)
    assert ak._scan_window_range(padded[40:120], 40, 60, TARGET) == 50


def test_parallel_returns_lowest_offset_like_serial():
    blob = bytearray(_blob_with_salt(4096, 3 * CHUNK + 5))
    blob[CHUNK + 1:CHUNK + 22] = SALT21  # a second, lower occurrence
    with ThreadPoolExecutor(4) as pool:
        assert ak._scan_raw_windows_parallel(bytes(blob), TARGET, pool, chunk=CHUNK) == SALT32
    padded = ak._padded_for_windows(bytes(blob))
    assert ak._scan_window_range(padded, 0, len(blob), TARGET) == CHUNK + 1


def test_real_subprocess_workers_find_straddling_salt():
    blob = _blob_with_salt(6000, 2 * CHUNK - 7)
    with ak._WindowScanner(workers=2, min_parallel_bytes=1, chunk=CHUNK) as scanner:
        assert scanner.scan(blob, TARGET) == SALT32
        assert scanner._parallel_ok and scanner.parallel_scans == 1  # really ran in the workers


def test_scanner_falls_back_to_serial_when_workers_cannot_start(monkeypatch):
    def broken(*_a, **_k):
        raise OSError("no subprocesses here")

    monkeypatch.setattr(pool_mod.subprocess, "Popen", broken)
    blob = _blob_with_salt(3000, 1500)
    scanner = ak._WindowScanner(workers=4, min_parallel_bytes=1, chunk=CHUNK)
    assert scanner.scan(blob, TARGET) == SALT32
    assert scanner._parallel_ok is False


def test_small_blob_and_single_worker_stay_serial(monkeypatch):
    monkeypatch.setattr(pool_mod.subprocess, "Popen", lambda *a, **k: pytest.fail("worker used"))
    blob = _blob_with_salt(3000, 100)
    assert ak._WindowScanner(workers=8, min_parallel_bytes=10_000).scan(blob, TARGET) == SALT32
    assert ak._WindowScanner(workers=1, min_parallel_bytes=1).scan(blob, TARGET) == SALT32


def test_worker_count_env(monkeypatch):
    monkeypatch.setenv(ak.ENV_SCAN_WORKERS, "1")
    assert ak._scan_worker_count() == 1


# --------------------------------------------------------------------------
# Encoded-token scan: fast run regexes == original lookaround regexes
# --------------------------------------------------------------------------

def _old_tokens(blob: bytes) -> list[bytes]:
    return ([m.group() for m in ak._HEX_SALT_RE.finditer(blob)]
            + [m.group() for m in ak._BASE64_SALT_RE.finditer(blob)])


def _new_tokens(blob: bytes) -> list[bytes]:
    return list(ak._iter_hex_salt_tokens(blob)) + list(ak._iter_base64_salt_tokens(blob))


def test_run_regexes_equal_original_on_fuzz():
    rng = random.Random(42)
    alphabet = b"aF09+/_-=\x00 "
    pieces = [b"a" * n for n in (27, 28, 29, 42, 43, 44, 64, 65)]
    for _ in range(400):
        parts = [rng.choice(pieces) if rng.random() < 0.5 else bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 4)))
                 for _ in range(6)]
        blob = b"".join(parts)
        assert _new_tokens(blob) == _old_tokens(blob), blob


def test_run_regexes_equal_original_on_real_tokens():
    b64 = base64.b64encode(SALT32)  # 43 chars + '='
    cases = [b" " + SALT32.hex().encode() + b" ", b"x" + SALT21.hex().encode(), b"=" + b64 + b"!",
             b64 + b"=", b64[:-1] + b"=A", base64.b64encode(SALT21) + b"=",
             base64.urlsafe_b64encode(SALT21) + b"\x00"]
    for blob in cases:
        assert _new_tokens(blob) == _old_tokens(blob), blob


# --------------------------------------------------------------------------
# Marker ordering
# --------------------------------------------------------------------------

def test_marker_blobs_come_first(tmp_path):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex\n" + b"plain")
        zf.writestr("classes2.dex", b"dex\n" + b"Lcom/applovin/sdk/AppLovinSdk;")
        zf.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"ALSdk")
        zf.writestr("lib/arm64-v8a/libapplovin_named.so", b"\x7fELF")
    labels = [label for label, _ in ak.iter_sdk_binary_blobs(str(path))]
    assert labels[:2] == ["classes2.dex", "lib/arm64-v8a/libfoo.so"]
    assert set(labels[2:]) == {"classes.dex", "lib/arm64-v8a/libapplovin_named.so"}
    assert labels[2] == "lib/arm64-v8a/libapplovin_named.so"  # name rank still applies


def test_ipa_marker_blobs_come_first(tmp_path):
    path = tmp_path / "app.ipa"
    macho = b"\xcf\xfa\xed\xfe" + bytes(5000)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("Payload/A.app/A", macho)
        zf.writestr("Payload/A.app/Frameworks/X.framework/X", macho + b"AppLovinSDK")
    labels = [label for label, _ in ak.iter_sdk_binary_blobs(str(path))]
    assert labels == ["Payload/A.app/Frameworks/X.framework/X", "Payload/A.app/A"]


# --------------------------------------------------------------------------
# extra_candidates hook + salt_candidates module hook
# --------------------------------------------------------------------------

def _xor(data: bytes) -> bytes:
    return bytes(b ^ 0x5A for b in data)


def test_recover_salt_uses_extra_candidates():
    seen = []

    def candidates(label, blob):
        seen.append(label)
        yield b"junk"
        yield _xor(blob[10:31])  # 21 bytes -> padded form must be tried

    blob = bytes(10) + _xor(SALT21) + bytes(10)
    assert ak.recover_salt([("lbl", blob)], PROTOCOL_ID, extra_candidates=candidates) == SALT32
    assert seen == ["lbl"]
    assert ak.recover_salt([blob], PROTOCOL_ID) is None  # obfuscated: window scan cannot see it


def test_failing_candidate_generator_is_skipped():
    def boom(_label, _blob):
        raise RuntimeError("bad hook")

    blob = _blob_with_salt(500, 77)
    assert ak.recover_salt([blob], PROTOCOL_ID, extra_candidates=boom) == SALT32


def _write_apk(path, members: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return str(path)


def test_bundle_runs_structured_candidates_over_all_blobs_before_windows(tmp_path, monkeypatch):
    apk = _write_apk(tmp_path / "a.apk", {
        "classes.dex": _blob_with_salt(400, 40),         # raw salt: window scan would find it
        "classes2.dex": b"dex\n" + _xor(SALT21),          # obfuscated: only the hook finds it
    })
    scanned = []
    monkeypatch.setattr(ak._WindowScanner, "scan", lambda self, blob, target: scanned.append(blob))
    hook = lambda _label, blob: [_xor(blob[4:25])] if blob.startswith(b"dex\n") else []
    assert ak.recover_salt_from_bundle(apk, PROTOCOL_ID, extra_candidates=hook) == SALT32
    assert scanned == []


def test_bundle_consults_salt_candidates_module(tmp_path, monkeypatch):
    module = types.ModuleType(CANDIDATES_MODULE)
    module.iter_salt_candidates = lambda label, blob: [_xor(blob[4:25])] if blob.startswith(b"dex\n") else []
    monkeypatch.setitem(sys.modules, CANDIDATES_MODULE, module)
    apk = _write_apk(tmp_path / "a.apk", {"classes.dex": b"dex\n" + _xor(SALT21)})
    assert ak.recover_salt_from_bundle(apk, PROTOCOL_ID) == SALT32


def test_bundle_without_salt_candidates_module_still_scans(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, CANDIDATES_MODULE, None)  # import -> ImportError
    apk = _write_apk(tmp_path / "a.apk", {"classes.dex": _blob_with_salt(600, 300)})
    assert ak.recover_salt_from_bundle(apk, PROTOCOL_ID) == SALT32


def test_sha1_oracle_consistency():
    assert hashlib.sha1(SALT32).hexdigest() == PROTOCOL_ID
