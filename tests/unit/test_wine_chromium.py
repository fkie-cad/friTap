"""Unit tests for friTap/wine_chromium.py — host-side pre-resolution of
bssl::ssl_log_secret in Chromium-family PE modules (fkie-cad/friTap#52).

The locator (locate_ssl_log_secret_rva) is the Python mirror of the agent's
x86-64 tier-4 anchor locator (agent/shared/x64_xref.ts): it finds the NSS keylog
label strings in a PE's data, the RIP-relative LEAs of them in code, the first
direct call after each, and accepts the callee only when >= 2 labels agree.

These tests build a minimal-but-valid PE image in memory so no real DLL is
needed, and exercise the pure helpers plus the caching path (with an explicit
cache_file in tmp_path, never the real user cache).

Run: pytest tests/unit/test_wine_chromium.py
"""

import struct

import pytest

from friTap.wine_chromium import (
    KEYLOG_LABELS,
    chromium_offsets,
    locate_ssl_log_secret_rva,
    merge_offsets,
    pe_sections,
    pick_agreed_callee,
    resolve_rva_cached,
    wine_path_to_unix,
)

IMAGE_BASE_SIZE = 0x200000  # SizeOfImage; callees must be below this to count

_IMAGE_SCN_CNT_CODE = 0x20000000


def _build_pe(text_bytes: bytes, text_va: int, rdata_blob: bytes, rdata_va: int) -> bytes:
    """A minimal PE32+ image: DOS stub, PE/COFF/optional headers, and two
    sections (.text executable, .rdata non-executable). Raw data is laid out
    contiguously after the headers; raw_ptr == file offset, va == rva."""
    pe_off = 0x80
    optsz = 0xF0
    sect_tbl = pe_off + 24 + optsz
    headers_end = sect_tbl + 2 * 40
    # Raw data regions (file offsets), aligned loosely.
    text_raw = (headers_end + 0x1FF) & ~0x1FF
    rdata_raw = (text_raw + len(text_bytes) + 0x1FF) & ~0x1FF
    total = rdata_raw + len(rdata_blob)

    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b"PE\0\0"
    # COFF header: machine, NumberOfSections, ..., SizeOfOptionalHeader @ pe+20.
    struct.pack_into("<H", buf, pe_off + 4, 0x8664)      # machine x64
    struct.pack_into("<H", buf, pe_off + 6, 2)           # NumberOfSections
    struct.pack_into("<H", buf, pe_off + 20, optsz)      # SizeOfOptionalHeader
    # Optional header: magic PE32+ (0x20B) at +24; SizeOfImage at +24+56.
    struct.pack_into("<H", buf, pe_off + 24, 0x20B)
    struct.pack_into("<I", buf, pe_off + 24 + 56, IMAGE_BASE_SIZE)
    # Section table (40 bytes each): name, vsize, va, raw_size, raw_ptr, +ch@36.
    struct.pack_into("<8sIIII", buf, sect_tbl, b".text", len(text_bytes), text_va,
                     len(text_bytes), text_raw)
    struct.pack_into("<I", buf, sect_tbl + 36, _IMAGE_SCN_CNT_CODE)
    struct.pack_into("<8sIIII", buf, sect_tbl + 40, b".rdata", len(rdata_blob), rdata_va,
                     len(rdata_blob), rdata_raw)
    struct.pack_into("<I", buf, sect_tbl + 40 + 36, 0x40000000)  # readable, not code
    buf[text_raw:text_raw + len(text_bytes)] = text_bytes
    buf[rdata_raw:rdata_raw + len(rdata_blob)] = rdata_blob
    return bytes(buf)


def _lea_rdx(site_va: int, target_va: int) -> bytes:
    """`lea rdx,[rip+disp32]` (48 8d 15 disp32) whose target is target_va."""
    disp = target_va - (site_va + 7)
    return b"\x48\x8d\x15" + struct.pack("<i", disp)


def _call(site_va: int, callee_va: int) -> bytes:
    """`call rel32` (e8 rel32)."""
    rel = callee_va - (site_va + 5)
    return b"\xe8" + struct.pack("<i", rel)


def _image_with_labels(labels, callee_va, text_va=0x1000):
    """Build a PE where each label string is NUL-delimited in .rdata and
    referenced by a lea+call to `callee_va` in .text."""
    rdata_va = 0x100000
    blob = bytearray(b"\x00")
    label_rva = {}
    for lab in labels:
        label_rva[lab] = rdata_va + len(blob)
        blob += lab + b"\x00"
    code = bytearray()
    for lab in labels:
        site = text_va + len(code)
        code += _lea_rdx(site, label_rva[lab])
        code += _call(text_va + len(code), callee_va)
    return _build_pe(bytes(code), text_va, bytes(blob), rdata_va)


def test_locate_ssl_log_secret_rva_majority():
    callee = 0x1800
    pe = _image_with_labels(list(KEYLOG_LABELS), callee)
    assert locate_ssl_log_secret_rva(pe) == callee


def test_locate_requires_two_agreeing_labels():
    # Only one label present -> fewer than 2 votes -> None.
    pe = _image_with_labels([b"CLIENT_RANDOM"], 0x1800)
    assert locate_ssl_log_secret_rva(pe) is None


def test_locate_none_when_no_labels():
    pe = _build_pe(b"\x90" * 32, 0x1000, b"not a keylog label\x00", 0x100000)
    assert locate_ssl_log_secret_rva(pe) is None


def test_locate_rejects_callee_outside_image():
    # Point the call at an address beyond SizeOfImage: no in-module callee.
    pe = _image_with_labels(list(KEYLOG_LABELS)[:3], IMAGE_BASE_SIZE + 0x1000)
    assert locate_ssl_log_secret_rva(pe) is None


def test_locate_not_a_pe():
    assert locate_ssl_log_secret_rva(b"not a pe at all") is None


def test_pe_sections_parses_two_sections():
    pe = _image_with_labels(list(KEYLOG_LABELS)[:2], 0x1800)
    secs = pe_sections(pe)
    names = {s.name for s in secs}
    assert names == {".text", ".rdata"}
    assert next(s for s in secs if s.name == ".text").executable
    assert not next(s for s in secs if s.name == ".rdata").executable


def test_pick_agreed_callee():
    assert pick_agreed_callee({b"A": 0x10, b"B": 0x10, b"C": 0x20}) == 0x10
    assert pick_agreed_callee({b"A": 0x10}) is None                      # < 2
    assert pick_agreed_callee({b"A": 0x10, b"B": 0x20}) is None          # tie
    assert pick_agreed_callee({}) is None


def test_chromium_offsets_and_cache(tmp_path):
    callee = 0x2a40
    dll = tmp_path / "libcef.dll"
    dll.write_bytes(_image_with_labels(list(KEYLOG_LABELS), callee))
    cache = tmp_path / "cache.json"

    offs = chromium_offsets([str(dll)], cache_file=str(cache))
    assert offs == {"libcef.dll": {"ssl_log_secret": {"address": hex(callee), "absolute": False}}}
    assert cache.is_file()

    # Second call is served from cache (same answer) without re-reading the PE.
    assert resolve_rva_cached(str(dll), cache_file=str(cache)) == callee


def test_resolve_rva_cached_negative_is_cached(tmp_path):
    f = tmp_path / "notcef.dll"
    f.write_bytes(_build_pe(b"\x90" * 16, 0x1000, b"nothing\x00", 0x100000))
    cache = tmp_path / "c.json"
    assert resolve_rva_cached(str(f), cache_file=str(cache)) is None
    assert resolve_rva_cached(str(f), cache_file=str(cache)) is None  # cached None


def test_merge_offsets_user_wins():
    existing = '{"libcef.dll": {"ssl_log_secret": {"address": "0xdead", "absolute": false}}}'
    extra = {"libcef.dll": {"ssl_log_secret": {"address": "0xbeef", "absolute": False}},
             "chrome.dll": {"ssl_log_secret": {"address": "0x1", "absolute": False}}}
    import json
    merged = json.loads(merge_offsets(existing, extra))
    # user's existing libcef entry preserved; new chrome.dll added.
    assert merged["libcef.dll"]["ssl_log_secret"]["address"] == "0xdead"
    assert merged["chrome.dll"]["ssl_log_secret"]["address"] == "0x1"


def test_merge_offsets_empty_extra_is_noop():
    assert merge_offsets('{"a": 1}', {}) == '{"a": 1}'
    assert merge_offsets(None, {}) is None


@pytest.mark.parametrize("win,prefix,expected_suffix", [
    ("Z:\\home\\u\\app.exe", None, "/home/u/app.exe"),
    ("/already/unix/app.exe", None, "/already/unix/app.exe"),
])
def test_wine_path_to_unix_z_and_unix(win, prefix, expected_suffix):
    assert wine_path_to_unix(win, prefix).endswith(expected_suffix)


def test_wine_path_to_unix_c_drive_via_prefix(tmp_path):
    prefix = tmp_path / "prefix"
    (prefix / "dosdevices" / "c:").mkdir(parents=True)
    out = wine_path_to_unix("C:\\Games\\app.exe", str(prefix))
    assert out.endswith("/dosdevices/c:/Games/app.exe")
