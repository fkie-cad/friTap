"""Tests for friTap.parsers.app_ciphers.applovin_keys (static key extraction)."""

from __future__ import annotations

import base64
import os
import plistlib
import struct
import zipfile

import pytest

from friTap.parsers.app_ciphers import applovin_keys as ak

SDK_KEY = ("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-" * 3)[:86]
OTHER_KEY = ("Zyxwvutsrqponmlkjihgfedcba9876543210-_" * 3)[:86]
SALT21 = bytes(range(0xA1, 0xA1 + 21))
SALT32 = SALT21 + bytes(11)
PROTOCOL_ID = ak.protocol_id_for_salt(SALT32)
MACHO_HEADER = b"\xcf\xfa\xed\xfe"


# --------------------------------------------------------------------------
# Minimal binary-AXML builder
# --------------------------------------------------------------------------

def _utf8_pool_length(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])


def _encode_pool_entry(text: str, utf8: bool) -> bytes:
    if utf8:
        raw = text.encode("utf-8")
        return _utf8_pool_length(len(text)) + _utf8_pool_length(len(raw)) + raw + b"\x00"
    return struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"


def build_string_pool(strings: list[str], utf8: bool) -> bytes:
    entries = [_encode_pool_entry(s, utf8) for s in strings]
    offsets, pos = [], 0
    for entry in entries:
        offsets.append(pos)
        pos += len(entry)
    data = b"".join(entries)
    data += b"\x00" * (-len(data) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    flags = 0x100 if utf8 else 0
    header = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(data),
                         len(strings), 0, flags, strings_start, 0)
    return header + struct.pack(f"<{len(strings)}I", *offsets) + data


def build_start_element(element_name: int, attrs: list[tuple[int, int, int, int]]) -> bytes:
    """attrs: (name_idx, raw_value_idx, data_type, data)."""
    attr_blob = b"".join(struct.pack("<IIIHBBI", 0xFFFFFFFF, n, raw, 8, 0, dt, d)
                         for n, raw, dt, d in attrs)
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, element_name, 20, 20, len(attrs), 0, 0, 0)
    body = struct.pack("<II", 1, 0xFFFFFFFF) + ext + attr_blob
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body


def build_manifest(value: str | None, utf8: bool = False, typed_only: bool = False) -> bytes:
    strings = ["manifest", "meta-data", "name", "value", ak.ANDROID_META_DATA_NAME, value or ""]
    pool = build_string_pool(strings, utf8)
    raw = 0xFFFFFFFF if typed_only else 5
    value_attr = (3, raw, 0x03, 5) if value is not None else (3, 0xFFFFFFFF, 0x01, 0x7F010001)
    chunks = pool + build_start_element(0, []) + build_start_element(1, [(2, 4, 0x03, 4), value_attr])
    return struct.pack("<HHI", 0x0003, 8, 8 + len(chunks)) + chunks


def write_zip(path, members: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return str(path)


# --------------------------------------------------------------------------
# AXML / string pool
# --------------------------------------------------------------------------

@pytest.mark.parametrize("utf8", [False, True])
def test_parse_string_pool_roundtrip(utf8):
    strings = ["a", "applovin.sdk.key", "x" * 200, "ü"]
    assert ak.parse_string_pool(build_string_pool(strings, utf8)) == strings


@pytest.mark.parametrize("utf8", [False, True])
def test_find_manifest_sdk_key(utf8):
    assert ak.find_manifest_sdk_key(build_manifest(SDK_KEY, utf8)) == SDK_KEY


def test_find_manifest_sdk_key_typed_string_value():
    assert ak.find_manifest_sdk_key(build_manifest(SDK_KEY, typed_only=True)) == SDK_KEY


def test_find_manifest_sdk_key_resource_reference_is_none():
    assert ak.find_manifest_sdk_key(build_manifest(None)) is None


def test_find_manifest_sdk_key_garbage_is_none():
    assert ak.find_manifest_sdk_key(b"\x03\x00\x08\x00" + os.urandom(64)) is None


# --------------------------------------------------------------------------
# SDK key candidates
# --------------------------------------------------------------------------

def test_scan_sdk_key_tokens_ascii_and_utf16():
    data = b"xx " + SDK_KEY.encode() + b" yy" + OTHER_KEY.encode("utf-16-le")
    assert ak.scan_sdk_key_tokens(data) == [SDK_KEY, OTHER_KEY]


def test_scan_sdk_key_tokens_rejects_longer_runs():
    assert ak.scan_sdk_key_tokens((SDK_KEY + "A").encode()) == []


def test_apk_manifest_candidate_ranked_first(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {
        "AndroidManifest.xml": build_manifest(SDK_KEY),
        "classes.dex": b"dex\n" + OTHER_KEY.encode() + b"\x00",
    })
    assert ak.find_sdk_key_candidates(apk) == [
        ak.SdkKeyCandidate(SDK_KEY, "manifest"), ak.SdkKeyCandidate(OTHER_KEY, "dex-string")]


def test_apk_resource_reference_falls_back_to_resources(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {
        "AndroidManifest.xml": build_manifest(None),
        "resources.arsc": b"\x00\x00" + SDK_KEY.encode() + b"\x00",
    })
    assert ak.find_sdk_key_candidates(apk) == [ak.SdkKeyCandidate(SDK_KEY, "resources")]


def test_split_apks_bundle_reads_nested_apk(tmp_path):
    inner = write_zip(tmp_path / "base.apk", {"AndroidManifest.xml": build_manifest(SDK_KEY)})
    with open(inner, "rb") as handle:
        bundle = write_zip(tmp_path / "app.apks", {"base.apk": handle.read(), "toc.pb": b""})
    assert ak.find_sdk_key_candidates(bundle) == [ak.SdkKeyCandidate(SDK_KEY, "manifest")]


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_ipa_info_plist_candidate(tmp_path, fmt):
    plist = plistlib.dumps({"CFBundleIdentifier": "x", ak.IOS_PLIST_KEY: SDK_KEY}, fmt=fmt)
    ipa = write_zip(tmp_path / "app.ipa", {"Payload/App.app/Info.plist": plist})
    assert ak.find_sdk_key_candidates(ipa)[0] == ak.SdkKeyCandidate(SDK_KEY, "info.plist")


def test_ipa_without_plist_key_falls_back_to_binary(tmp_path):
    binary = MACHO_HEADER + bytes(5000) + SDK_KEY.encode() + b"\x00"
    ipa = write_zip(tmp_path / "app.ipa", {
        "Payload/App.app/Info.plist": plistlib.dumps({"CFBundleIdentifier": "x"}),
        "Payload/App.app/App": binary,
    })
    assert ak.find_sdk_key_candidates(ipa) == [ak.SdkKeyCandidate(SDK_KEY, "binary-string")]


def test_no_candidates(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {"AndroidManifest.xml": build_manifest(None)})
    assert ak.find_sdk_key_candidates(apk) == []


# --------------------------------------------------------------------------
# Salt recovery
# --------------------------------------------------------------------------

def _noise(size: int) -> bytes:
    return bytes((i * 37 + 11) % 251 + 1 for i in range(size))  # no zero bytes


def test_recover_salt_full_32_at_odd_offset():
    blob = _noise(1001) + SALT32 + _noise(333)
    assert ak.recover_salt([blob], PROTOCOL_ID) == SALT32


def test_recover_salt_21_without_zero_tail():
    blob = _noise(777) + SALT21 + _noise(500)
    assert ak.recover_salt([b"", _noise(64), blob], PROTOCOL_ID) == SALT32


def test_recover_salt_21_at_end_of_blob():
    assert ak.recover_salt([_noise(3) + SALT21], PROTOCOL_ID) == SALT32


@pytest.mark.parametrize("encoded", [
    SALT21.hex().encode(), SALT32.hex().upper().encode(),
    base64.b64encode(SALT21), base64.b64encode(SALT32), base64.urlsafe_b64encode(SALT32).rstrip(b"="),
])
def test_recover_salt_text_encoded(encoded):
    blob = _noise(99) + b'"' + encoded + b'"' + _noise(99)
    assert ak.recover_salt([blob], PROTOCOL_ID.upper()) == SALT32


def test_recover_salt_no_match():
    assert ak.recover_salt([_noise(4096), SALT21[:-1]], PROTOCOL_ID) is None


def test_recover_salt_rejects_bad_protocol_id():
    with pytest.raises(ValueError):
        ak.recover_salt([b""], "not-hex")


# --------------------------------------------------------------------------
# Bundle binaries
# --------------------------------------------------------------------------

def test_iter_sdk_binary_blobs_apk(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {
        "AndroidManifest.xml": b"m", "classes.dex": b"d1", "classes2.dex": b"d2",
        "lib/arm64-v8a/libapplovin-native.so": b"so", "assets/x.bin": b"no",
    })
    labels = [label for label, _ in ak.iter_sdk_binary_blobs(apk)]
    assert labels[0] == "lib/arm64-v8a/libapplovin-native.so"
    assert sorted(labels) == ["classes.dex", "classes2.dex", "lib/arm64-v8a/libapplovin-native.so"]


def test_iter_sdk_binary_blobs_ipa_machos_only(tmp_path):
    macho = MACHO_HEADER + bytes(5000)
    ipa = write_zip(tmp_path / "app.ipa", {
        "Payload/App.app/App": macho,
        "Payload/App.app/Frameworks/AppLovinSDK.framework/AppLovinSDK": macho,
        "Payload/App.app/Assets.car": b"\x00" * 5000,
        "Payload/App.app/Info.plist": plistlib.dumps({}),
    })
    labels = [label for label, _ in ak.iter_sdk_binary_blobs(ipa)]
    assert labels == ["Payload/App.app/Frameworks/AppLovinSDK.framework/AppLovinSDK",
                      "Payload/App.app/App"]


def test_recover_salt_from_bundle_apk_and_ipa(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {"classes.dex": _noise(513) + SALT21 + _noise(9)})
    ipa = write_zip(tmp_path / "app.ipa", {
        "Payload/App.app/Frameworks/AppLovinSDK.framework/AppLovinSDK":
            MACHO_HEADER + _noise(5001) + SALT32 + _noise(7)})
    assert ak.recover_salt_from_bundle(apk, PROTOCOL_ID) == SALT32
    assert ak.recover_salt_from_bundle(ipa, PROTOCOL_ID) == SALT32


def test_recover_salt_from_bundle_absent(tmp_path):
    apk = write_zip(tmp_path / "app.apk", {"classes.dex": _noise(2048)})
    assert ak.recover_salt_from_bundle(apk, PROTOCOL_ID) is None
