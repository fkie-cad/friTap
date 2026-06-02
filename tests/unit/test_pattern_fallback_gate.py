"""Regression tests for the per-library, emptiness-aware pattern gate.

Background
----------
friTap ships hardcoded byte-patterns inside the legacy TLS lib executors (e.g.
``default_pattern`` / ``default_pattern_12`` in ``rustls_linux.ts``). The agent
also auto-loads ``friTap/patterns/default_patterns.json`` on every run, which used
to flip the global ``isPatternReplaced()`` flag to true unconditionally. Several
legacy libs branched purely on that global flag::

    if (isPatternReplaced()) { ...JSON patterns... } else { ...shipped hardcoded... }

Because default_patterns.json is the flat "Schema A" (``{lib:{arch:{fn:[...]}}}``)
while the legacy ``PatternBasedHooking`` consumer expects the "Schema B"
(``{modules:{lib:{platform:{arch:{Action:{primary,fallback}}}}}}``), feeding the
auto-loaded defaults into the JSON branch threw a TypeError that the loader
swallowed — silently bypassing the shipped hardcoded patterns.

The fix gates each legacy lib on a strict, throw-safe predicate
``hasUsablePatternsFor(...)`` so that the shipped hardcoded default is used unless
a *real, non-empty* Schema-B pattern exists for the current platform/arch:

    if (isPatternReplaced() && hasUsablePatternsFor(...)) { JSON } else { hardcoded }

These tests lock the invariants the fix relies on and verify the gate is wired
into every affected lib (source) and into the shipped bundle (artifact).
"""

import json

import pytest


# Legacy lib executors that ship hardcoded byte-patterns and previously gated the
# JSON-vs-hardcoded decision on the global isPatternReplaced() flag alone.
AFFECTED_LEGACY_LIBS = [
    "agent/legacy/tls/platforms/linux/rustls_linux.ts",
    "agent/legacy/tls/platforms/android/rustls_android.ts",
    "agent/legacy/tls/platforms/linux/cronet_linux.ts",
    "agent/legacy/tls/platforms/android/cronet_android.ts",
    "agent/legacy/tls/platforms/ios/cronet_ios.ts",
    "agent/legacy/tls/platforms/macos/cronet_macos.ts",
    "agent/legacy/tls/platforms/windows/cronet_windows.ts",
    "agent/legacy/tls/platforms/android/flutter_android.ts",
    "agent/legacy/tls/platforms/ios/flutter_ios.ts",
    "agent/legacy/tls/platforms/android/gotls_android.ts",
    "agent/legacy/tls/platforms/linux/gotls_linux.ts",
    "agent/legacy/tls/platforms/android/metartc.ts",
    "agent/legacy/tls/platforms/android/mono_btls_android.ts",
    "agent/legacy/tls/platforms/linux/openssl_boringssl_linux.ts",
]

# default_patterns.json entries that are intentional empty stubs ("Empty until
# extracted from target binaries"). These are exactly the case the gate must treat
# as "no usable pattern" so it falls back to the library's shipped hardcoded default.
KNOWN_STUB_LIBRARIES = [
    "openssh",
    "strongswan",
    "gnutls",
    "wolfssl",
    "mbedtls",
    "nss",
    "s2n",
]

# Lib families with shipped hardcoded patterns but NO entry in default_patterns.json.
# For these the gate must always fall back to the hardcoded default.
LIBS_WITHOUT_DEFAULT_PATTERN_ENTRY = [
    "rustls",
    "cronet",
    "flutter",
    "gotls",
    "metartc",
    "mono",
]


@pytest.fixture
def default_patterns(fritap_root):
    path = fritap_root / "friTap" / "patterns" / "default_patterns.json"
    assert path.exists(), f"default_patterns.json not found at {path}"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _iter_pattern_lists(lib_entry):
    """Yield every leaf pattern list under a Schema-A library entry."""
    for arch, fns in lib_entry.items():
        if arch.startswith("_") or not isinstance(fns, dict):
            continue
        for fn, pats in fns.items():
            if fn.startswith("_"):
                continue
            if isinstance(pats, list):
                yield pats


def test_default_patterns_is_schema_a_without_modules_wrapper(default_patterns):
    """default_patterns.json must stay Schema A (no top-level ``modules`` key).

    The legacy ``PatternBasedHooking`` consumer reads ``patterns.modules[...]``.
    As long as default_patterns.json has no ``modules`` wrapper, the emptiness gate
    correctly resolves to "no usable Schema-B pattern" and falls back to hardcoded.
    If someone reshapes this file into Schema B, the gate's assumptions change and
    this guard should force a deliberate review.
    """
    assert "modules" not in default_patterns, (
        "default_patterns.json gained a top-level 'modules' key; the legacy "
        "fallback gate assumes the flat Schema-A layout — review hasUsablePatternsFor."
    )


def test_known_stub_libraries_have_only_empty_patterns(default_patterns):
    """The documented empty stubs must contain no byte-patterns.

    This is the exact 'entry exists but is empty' scenario the gate guards: such an
    entry must NOT suppress a library's shipped hardcoded default.
    """
    for lib in KNOWN_STUB_LIBRARIES:
        if lib not in default_patterns:
            continue
        for pats in _iter_pattern_lists(default_patterns[lib]):
            assert pats == [], (
                f"stub library '{lib}' unexpectedly contains patterns {pats!r}; "
                "if this is intentional, update the gate's regression expectations."
            )


def test_libs_with_hardcoded_defaults_absent_from_default_patterns(default_patterns):
    """Libs that rely on shipped hardcoded patterns have no default_patterns.json entry.

    With no entry, hasUsablePatternsFor() returns false and the gate falls back to the
    library's hardcoded default — the intended behaviour for these libs today.
    """
    keys = {k for k in default_patterns if not k.startswith("_")}
    for lib in LIBS_WITHOUT_DEFAULT_PATTERN_ENTRY:
        assert lib not in keys, (
            f"'{lib}' gained a default_patterns.json entry; ensure it is a real, "
            "non-empty Schema-B pattern (or the gate will keep using the hardcoded "
            "default for it)."
        )


@pytest.mark.parametrize("rel_path", AFFECTED_LEGACY_LIBS)
def test_legacy_lib_gate_uses_emptiness_predicate(fritap_root, rel_path):
    """Every affected legacy lib must gate the JSON branch on hasUsablePatternsFor.

    Guards against a regression where a lib reverts to gating on the global
    ``isPatternReplaced()`` alone (which silently bypasses the hardcoded default).
    """
    src = (fritap_root / rel_path).read_text(encoding="utf-8")
    assert "hasUsablePatternsFor" in src, (
        f"{rel_path} no longer references hasUsablePatternsFor — the per-library "
        "emptiness gate was removed; the shipped hardcoded default may be bypassed."
    )
    # No JSON branch should be guarded by the bare global flag anymore.
    assert "if (isPatternReplaced()) {" not in src and "if (isPatternReplaced()){" not in src, (
        f"{rel_path} still has a bare `if (isPatternReplaced())` gate; it must be "
        "combined with hasUsablePatternsFor(...) so empty/absent JSON falls back to "
        "the hardcoded default."
    )


def test_get_cpu_specific_pattern_is_throw_safe(fritap_root):
    """The shipped-default arch lookup must not throw on a missing arch.

    A throw there would abort sibling hook installs for the same library; the fix
    makes it return null and lets callers no-op instead.
    """
    for rel in [
        "agent/tls/shared/pattern_based_hooking.ts",
        "agent/legacy/tls/shared/pattern_based_hooking.ts",
    ]:
        src = (fritap_root / rel).read_text(encoding="utf-8")
        assert "No patterns found for CPU architecture" not in src, (
            f"{rel} still throws on a missing arch in get_CPU_specific_pattern; it "
            "should return null so the caller no-ops safely."
        )


def test_compiled_bundle_wires_the_gate(fritap_root):
    """The shipped, compiled agent bundle must contain the emptiness gate.

    Ensures the fix is present in the artifact that actually runs (not just source).
    """
    bundle = fritap_root / "friTap" / "fritap_agent.js"
    if not bundle.exists():
        pytest.skip("compiled agent bundle not found; run `npm run build`")
    content = bundle.read_text(encoding="utf-8")
    assert "hasUsablePatternsFor" in content, (
        "compiled fritap_agent.js does not contain hasUsablePatternsFor — rebuild "
        "the agent (`npm run build`) after changing the gate."
    )
