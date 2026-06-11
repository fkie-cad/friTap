"""Guard tests for libwebviewchromium.so (Android System WebView) key extraction.

libwebviewchromium.so is the Android System WebView monolith — a full Chromium
build with BoringSSL statically linked (the same shape as libmonochrome_*.so).
friTap extracts its TLS keys via ssl_log_secret(), reusing the BoringSSL/Cronet
executor and the wildcard ssl_log_secret prologue pattern friTap already ships.

Two premises must hold for that reuse to keep working:

1. The shipped wildcard ssl_log_secret pattern must still match the concrete
   WebView prologue bytes. If someone later tightens the wildcard and breaks
   WebView coverage, ``test_shipped_wildcard_matches_webview_prologue`` fails.
2. ``libwebviewchromium.so`` must be registered in the Android hook registry and
   routed to the Cronet/BoringSSL executor. The registry lives in TypeScript
   (no JS test harness in-repo), so ``test_webviewchromium_registered`` asserts
   the source entry exists.
"""

import json
import re

import pytest


# Verified concrete arm64 ssl_log_secret prologue from a real libwebviewchromium.so
# build (user-supplied, 2026-06). The FF 03 02 D1 frame (sub sp, #0x80) is the
# *fallback* branch of the shipped wildcard.
WEBVIEW_ARM64_PROLOGUE = (
    "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 "
    "F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 29 41 F9 C8 05 00 B4"
)


def _wildcard_matches(pattern: str, concrete: str) -> bool:
    """True if a friTap wildcard pattern matches concrete hex bytes, nibble-wise.

    Both inputs are space-separated 2-char tokens; ``?`` in the pattern matches
    any nibble. Lengths must be equal token-for-token.
    """
    pat_tokens = pattern.split()
    cand_tokens = concrete.split()
    if len(pat_tokens) != len(cand_tokens):
        return False
    for pt, ct in zip(pat_tokens, cand_tokens):
        if len(pt) != 2 or len(ct) != 2:
            return False
        for pn, cn in zip(pt, ct):
            if pn == "?":
                continue
            if pn.lower() != cn.lower():
                return False
    return True


def test_shipped_wildcard_matches_webview_prologue(fritap_root):
    """At least one shipped openssl arm64 ssl_log_secret pattern must match the
    concrete WebView prologue — this is what makes pattern reuse valid."""
    path = fritap_root / "friTap" / "patterns" / "default_patterns.json"
    if not path.exists():
        pytest.skip("default_patterns.json not present")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    patterns = data["openssl"]["arm64"]["ssl_log_secret"]
    assert any(_wildcard_matches(p, WEBVIEW_ARM64_PROLOGUE) for p in patterns), (
        "No shipped openssl arm64 ssl_log_secret pattern matches the verified "
        "libwebviewchromium.so prologue. If the wildcard was tightened, WebView "
        "key extraction is now broken on the pattern path."
    )


def test_matcher_rejects_mismatch():
    """Sanity check: the nibble matcher does not match unrelated bytes."""
    assert not _wildcard_matches("3F 23 03 D5", "00 11 22 33")
    assert not _wildcard_matches("3F 23 03 D5", "3F 23 03")  # length mismatch
    assert _wildcard_matches("3F ?3 02 D1", "3F 03 02 D1")


def test_webviewchromium_registered(fritap_root):
    """libwebviewchromium.so must be in the Android hook registry, routed to the
    Cronet/BoringSSL executor (cronet_execute / cronet_execute_modern)."""
    android_ts = fritap_root / "agent" / "platforms" / "android.ts"
    assert android_ts.exists(), "agent/platforms/android.ts missing"
    src = android_ts.read_text(encoding="utf-8")

    entry = re.search(r"^.*libwebviewchromium.*hookFn.*$", src, re.MULTILINE)
    assert entry is not None, "no libwebviewchromium registry entry in android.ts"
    line = entry.group(0)
    assert "cronet_execute" in line, "WebView entry must route to the Cronet executor"
    assert 'libraryType: "boringssl"' in line, "WebView entry must be libraryType boringssl"
    assert 'protocol: "tls"' in line, "WebView entry must be a TLS-family hook"
