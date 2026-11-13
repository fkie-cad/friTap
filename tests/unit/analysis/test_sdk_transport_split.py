"""Unit tests for the SDK transport-vs-originator split.

Covers ``classify_transport`` (basename matching, the chrome-or-webview and
GMS Cronet rules), the native transport deny-list in ``classify_frames``,
signature overlays (constructor and ``FRITAP_SDK_SIGNATURES``), and the
shipped table's ``entry_count`` invariant.

Pure Python — no device/Frida/tshark, no network.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Iterator, List

import pytest

from friTap.analysis.attribution import sdk as sdk_module
from friTap.analysis.attribution.sdk import (
    DEFAULT_SDK_SIGNATURES_PATH,
    SDK_CATEGORIES,
    SDK_SIGNATURES_ENV,
    Sdk,
    SdkResolver,
)

GMS_CRONET_PATH = (
    "/data/user_de/0/com.google.android.gms/app_chimera/m/00000123/"
    "dl-CronetDynamite.integ_1234/lib/arm64-v8a/libcronet.143.7445.0.so"
)


@pytest.fixture(scope="module")
def resolver() -> SdkResolver:
    return SdkResolver()


@pytest.fixture
def clean_singleton(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the module singleton around a test that changes the env var."""
    monkeypatch.delenv(SDK_SIGNATURES_ENV, raising=False)
    sdk_module.reset_default_resolver()
    yield
    sdk_module.reset_default_resolver()


class _ListHandler(logging.Handler):
    """Collects records; caplog can't see this repo's loggers."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def sdk_log() -> Iterator[_ListHandler]:
    handler = _ListHandler()
    sdk_module.logger.addHandler(handler)
    yield handler
    sdk_module.logger.removeHandler(handler)


def _write_overlay(path: Path, entries: object) -> Path:
    path.write_text(json.dumps({"schema": "fritap.sdk_signatures/1", "entries": entries}))
    return path


# --------------------------------------------------------------------------- #
# Sdk dataclass / categories
# --------------------------------------------------------------------------- #

def test_transport_kind_defaults_empty_and_stays_out_of_as_dict() -> None:
    entry = Sdk(sdk="Cronet", vendor="Google", category="networking", transport_kind="cronet")
    assert Sdk(sdk="a", vendor="b", category="c").transport_kind == ""
    assert entry.as_dict() == {"sdk": "Cronet", "vendor": "Google", "category": "networking"}


def test_transport_is_a_category() -> None:
    assert "transport" in SDK_CATEGORIES


# --------------------------------------------------------------------------- #
# classify_transport: kinds
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "module, kind",
    [
        ("libwebviewchromium.so", "webview"),
        ("libmainlinecronet.143.0.7445.0.so", "httpengine"),
        ("libhttpengine.so", "httpengine"),
        ("stable_cronet_libssl.so", "httpengine"),
        ("libsignal_jni.so", "libsignal"),
        ("Google Chrome Framework", "chrome"),
        ("chrome.dll", "chrome"),
        ("CHROME.DLL", "chrome"),
        ("Electron Framework", "electron"),
        ("Chromium Embedded Framework", "cef"),
        ("libcef.so", "cef"),
        ("libcronet.143.7445.0.so", "cronet"),
        ("libflutter.so", "flutter"),
        ("libmonochrome.so", "webview"),
        ("libchrome.so", "webview"),
    ],
)
def test_classify_transport_kinds(resolver: SdkResolver, module: str, kind: str) -> None:
    assert resolver.classify_transport(module) == {"module": module, "kind": kind}


def test_classify_transport_strips_directories(resolver: SdkResolver) -> None:
    result = resolver.classify_transport(
        "/Applications/Google Chrome.app/Contents/Frameworks/"
        "Google Chrome Framework.framework/Versions/1/Google Chrome Framework"
    )
    assert result == {"module": "Google Chrome Framework", "kind": "chrome"}
    win = resolver.classify_transport("C:\\Program Files\\Google\\Chrome\\Application\\chrome.dll")
    assert win == {"module": "chrome.dll", "kind": "chrome"}


@pytest.mark.parametrize("module", ["", "libc.so", "libchromium_net.so", "libflutter.so.1", "xchrome.dll"])
def test_classify_transport_unknown_returns_none(resolver: SdkResolver, module: str) -> None:
    assert resolver.classify_transport(module) is None


# --------------------------------------------------------------------------- #
# chrome-or-webview rule
# --------------------------------------------------------------------------- #

def test_monochrome_in_chrome_package_is_chrome(resolver: SdkResolver) -> None:
    result = resolver.classify_transport("libmonochrome_64.so", package_name="com.android.chrome")
    assert result == {"module": "libmonochrome_64.so", "kind": "chrome"}


def test_monochrome_in_other_app_is_webview(resolver: SdkResolver) -> None:
    result = resolver.classify_transport("libmonochrome_64.so", package_name="com.example.app")
    assert result == {"module": "libmonochrome_64.so", "kind": "webview"}


def test_monochrome_in_chrome_subprocess_is_chrome(resolver: SdkResolver) -> None:
    result = resolver.classify_transport(
        "libmonochrome_64.so", process_name="com.android.chrome:privileged_process0"
    )
    assert result["kind"] == "chrome"


@pytest.mark.parametrize("package", ["com.chrome.beta", "com.chrome.canary", "com.google.android.apps.chrome"])
def test_chrome_channels_are_chrome(resolver: SdkResolver, package: str) -> None:
    assert resolver.classify_transport("libchrome.so", package_name=package)["kind"] == "chrome"



@pytest.mark.parametrize("name", [
    "Chrome", "chrome", "CHROME", "org.chromium.chrome", "Org.Chromium.Chrome",
    "Com.Android.Chrome", "com.chrome.dev", "Chrome:sandboxed_process0",
    "org.chromium.chrome:privileged_process1",
])
def test_chrome_friendly_and_chromium_names_are_chrome(resolver: SdkResolver, name: str) -> None:
    assert resolver.classify_transport("libmonochrome_64.so", process_name=name)["kind"] == "chrome"
    assert resolver.classify_transport("libmonochrome_64.so", package_name=name)["kind"] == "chrome"


@pytest.mark.parametrize("name", ["chromecast", "com.example.chrome", "1234", "org.chromium.webview"])
def test_chrome_lookalikes_and_pids_are_webview(resolver: SdkResolver, name: str) -> None:
    assert resolver.classify_transport("libmonochrome_64.so", process_name=name)["kind"] == "webview"


def test_chrome_names_mirror_cli_chrome_family_targets() -> None:
    """Every ``_CHROME_FAMILY_TARGETS`` entry in friTap/friTap.py is Chrome here too."""
    import re
    source = (Path(sdk_module.__file__).resolve().parents[2] / "friTap.py").read_text(encoding="utf-8")
    block = re.search(r"_CHROME_FAMILY_TARGETS = \{(.*?)\}", source, re.S)
    assert block is not None
    targets = re.findall(r'"([^"]+)"', block.group(1))
    assert "Chrome" in targets and "org.chromium.chrome" in targets
    browsers = sdk_module.ChromiumBrowserPackages.from_patterns(
        sdk_module.DEFAULT_CHROMIUM_BROWSER_PACKAGES)
    for target in targets:
        assert sdk_module._is_chrome_process(target, "", browsers), target


# --------------------------------------------------------------------------- #
# Data-driven Chromium browser list (chromium_browser_packages)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("package", [
    "com.brave.browser", "com.brave.browser_beta", "com.brave.browser_nightly",
    "com.microsoft.emmx", "com.microsoft.emmx.beta", "com.microsoft.emmx.canary",
    "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta",
    "com.vivaldi.browser", "com.opera.browser", "com.kiwibrowser.browser",
    "com.yandex.browser", "COM.BRAVE.BROWSER:sandboxed_process0",
])
def test_chromium_browsers_are_chrome(resolver: SdkResolver, package: str) -> None:
    assert resolver.classify_transport("libmonochrome_64.so", package_name=package)["kind"] == "chrome"
    assert resolver.classify_transport("libchrome.so", process_name=package)["kind"] == "chrome"


@pytest.mark.parametrize("package", [
    "com.example.app", "com.duckduckgo.mobile.android", "com.opera.mini.native",
    "com.microsoft.emmxfoo", "com.brave.browserx", "com.microsoft",
])
def test_non_browsers_and_near_misses_are_webview(resolver: SdkResolver, package: str) -> None:
    assert resolver.classify_transport("libmonochrome_64.so", package_name=package)["kind"] == "webview"


def test_bundled_table_lists_chromium_browsers() -> None:
    payload = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))
    patterns = payload[sdk_module.CHROMIUM_BROWSER_PACKAGES_KEY]
    assert set(sdk_module.DEFAULT_CHROMIUM_BROWSER_PACKAGES) <= set(patterns)
    assert patterns == sorted(set(patterns))  # canonical (dev/update_sdk_signatures.py)


def test_browser_matcher_prefix_pattern() -> None:
    matcher = sdk_module.ChromiumBrowserPackages.from_patterns(["Com.Acme.*", "org.exact"])
    assert matcher.matches("com.acme.browser") and matcher.matches("COM.ACME.x:sub")
    assert not matcher.matches("com.acme")  # the prefix includes the trailing dot
    assert matcher.matches("org.exact") and not matcher.matches("org.exact.beta")
    assert not matcher.matches("") and not matcher.matches(":sub")


def test_overlay_adds_a_browser_package(tmp_path: Path) -> None:
    overlay = tmp_path / "browsers.json"
    overlay.write_text(json.dumps({
        "schema": "fritap.sdk_signatures/1",
        "chromium_browser_packages": ["com.acme.browser", "net.acme.*"],
    }))
    resolver = SdkResolver(extra_paths=[overlay])
    for package in ("com.acme.browser", "net.acme.nightly", "com.brave.browser", "com.android.chrome"):
        assert resolver.classify_transport("libmonochrome.so", package_name=package)["kind"] == "chrome"
    assert SdkResolver().classify_transport(
        "libmonochrome.so", package_name="com.acme.browser")["kind"] == "webview"


def test_env_overlay_browser_package_and_cache_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_singleton: None
) -> None:
    assert sdk_module.classify_transport("libmonochrome.so", package_name="com.acme.browser")["kind"] == "webview"
    overlay = tmp_path / "browsers.json"
    overlay.write_text(json.dumps({"chromium_browser_packages": ["com.acme.browser"]}))
    monkeypatch.setenv(SDK_SIGNATURES_ENV, str(overlay))
    sdk_module.reset_default_resolver()
    assert sdk_module.classify_transport("libmonochrome.so", package_name="com.acme.browser")["kind"] == "chrome"


def test_missing_browser_key_falls_back_to_default_list(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))
    del payload[sdk_module.CHROMIUM_BROWSER_PACKAGES_KEY]
    table = tmp_path / "no_browsers.json"
    table.write_text(json.dumps(payload))
    resolver = SdkResolver(signatures_path=table)
    assert resolver.classify_transport("libmonochrome.so", package_name="com.chrome.beta")["kind"] == "chrome"
    assert resolver.classify_transport("libmonochrome.so", package_name="com.brave.browser")["kind"] == "webview"


def test_invalid_browser_patterns_are_warned_and_dropped(
    tmp_path: Path, sdk_log: _ListHandler
) -> None:
    overlay = tmp_path / "bad.json"
    overlay.write_text(json.dumps({"chromium_browser_packages": ["*", "a*b", 7, "", "x:y", "com.ok.browser"]}))
    resolver = SdkResolver(extra_paths=[overlay])
    assert resolver.classify_transport("libmonochrome.so", package_name="com.ok.browser")["kind"] == "chrome"
    assert resolver.classify_transport("libmonochrome.so", package_name="anything")["kind"] == "webview"
    assert any("chromium_browser_packages" in r.getMessage() for r in sdk_log.records)
    overlay.write_text(json.dumps({"chromium_browser_packages": "com.ok.browser"}))
    assert SdkResolver(extra_paths=[overlay]).classify_transport(
        "libmonochrome.so", package_name="com.ok.browser")["kind"] == "webview"


# --------------------------------------------------------------------------- #
# Cronet / GMS rule
# --------------------------------------------------------------------------- #

def test_app_cronet_is_cronet(resolver: SdkResolver) -> None:
    result = resolver.classify_transport(
        "libcronet.143.7445.0.so", path="/data/app/com.example.app/lib/arm64/libcronet.143.7445.0.so"
    )
    assert result == {"module": "libcronet.143.7445.0.so", "kind": "cronet"}


def test_gms_path_cronet_is_gms_cronet(resolver: SdkResolver) -> None:
    result = resolver.classify_transport("libcronet.143.7445.0.so", path=GMS_CRONET_PATH)
    assert result == {"module": "libcronet.143.7445.0.so", "kind": "gms-cronet"}


def test_dynamite_path_is_gms_cronet_case_insensitive(resolver: SdkResolver) -> None:
    result = resolver.classify_transport("libcronet.so", path="/data/X/DYNAMITE/libcronet.so")
    assert result["kind"] == "gms-cronet"


# --------------------------------------------------------------------------- #
# Deny-list in classify_frames
# --------------------------------------------------------------------------- #

def test_native_transport_is_never_originator(resolver: SdkResolver) -> None:
    assert resolver.classify_frames(native_modules=["libcronet.143.so"]) is None
    assert resolver.classify_frames(native_modules=["libflutter.so", "libmonochrome.so"]) is None


def test_java_sdk_still_wins_over_native_transport(resolver: SdkResolver) -> None:
    result = resolver.classify_frames(
        java_frames=["com.adjust.sdk.Adjust"], native_modules=["libcronet.143.so"]
    )
    assert result is not None and result.sdk == "Adjust"


def test_non_transport_native_after_transport_still_matches(resolver: SdkResolver) -> None:
    result = resolver.classify_frames(native_modules=["libcronet.143.so", "libhermes.so"])
    assert result is not None and result.sdk == "React Native"


CRONET_JAVA_FRAMES = [
    "org.chromium.net.impl.CronetUrlRequest.start",
    "org.chromium.net.impl.JavaUrlRequest$1.run",
]


def test_cronet_java_frames_are_not_an_sdk(resolver: SdkResolver) -> None:
    assert resolver.classify_frames(java_frames=CRONET_JAVA_FRAMES) is None


def test_real_sdk_frame_below_cronet_java_frames_wins(resolver: SdkResolver) -> None:
    result = resolver.classify_frames(
        java_frames=CRONET_JAVA_FRAMES + ["com.facebook.GraphRequest.executeAndWait"])
    assert result is not None and result.sdk == "Facebook SDK"


def test_java_frame_matching_a_transport_entry_is_skipped(tmp_path: Path) -> None:
    """Mirrors the native deny-list: a Java frame whose best match carries a
    ``transport_kind`` is the transport, so the SDK frame below it wins."""
    overlay = _write_overlay(tmp_path / "java_transport.json", {
        "org.chromium.net": {"sdk": "Cronet (Java)", "vendor": "Google",
                             "category": "transport", "transport_kind": "cronet"},
    })
    resolver = SdkResolver(extra_paths=[overlay])
    assert resolver.classify_package("org.chromium.net.impl.X").transport_kind == "cronet"
    assert resolver.classify_frames(java_frames=CRONET_JAVA_FRAMES) is None
    result = resolver.classify_frames(
        java_frames=CRONET_JAVA_FRAMES + ["com.facebook.GraphRequest.executeAndWait"])
    assert result is not None and result.sdk == "Facebook SDK"


# --------------------------------------------------------------------------- #
# Overlays
# --------------------------------------------------------------------------- #

def test_constructor_overlay_merges_and_wins(tmp_path: Path) -> None:
    overlay = _write_overlay(tmp_path / "o.json", {
        "libmytransport": {"sdk": "Mine", "vendor": "Me", "category": "transport",
                           "transport_kind": "other"},
        "com.adjust.sdk": {"sdk": "Adjust Override", "vendor": "X", "category": "analytics"},
    })
    resolver = SdkResolver(extra_paths=[overlay])
    assert resolver.classify_transport("libmytransport.so") == {
        "module": "libmytransport.so", "kind": "other"}
    assert resolver.classify_package("com.adjust.sdk.Adjust").sdk == "Adjust Override"
    assert resolver.classify_package("com.facebook.appevents.X").sdk == "Facebook SDK"


def test_env_overlay_reaches_module_singleton(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_singleton: None
) -> None:
    overlay = _write_overlay(tmp_path / "o.json", {
        "libenvtransport": {"sdk": "Env", "vendor": "Me", "category": "transport",
                            "transport_kind": "other"},
    })
    monkeypatch.setenv(SDK_SIGNATURES_ENV, os.pathsep.join(["", str(overlay), ""]))
    sdk_module.reset_default_resolver()
    assert sdk_module.classify_transport("libenvtransport.so")["kind"] == "other"
    assert sdk_module.classify_package("com.adjust.sdk.Adjust").sdk == "Adjust"


def test_module_wrapper_without_env(clean_singleton: None) -> None:
    assert sdk_module.classify_transport("libenvtransport.so") is None
    assert sdk_module.classify_transport("libcronet.so")["kind"] == "cronet"


def test_reset_default_resolver_clears_the_transport_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_singleton: None
) -> None:
    assert sdk_module.classify_transport("libcachedtransport.so") is None
    overlay = _write_overlay(tmp_path / "o.json", {
        "libcachedtransport": {"sdk": "Cached", "vendor": "Me", "category": "transport",
                               "transport_kind": "foo-bar"},
    })
    monkeypatch.setenv(SDK_SIGNATURES_ENV, str(overlay))
    # Memoised: the cached miss survives until the resolver is reset.
    assert sdk_module.classify_transport("libcachedtransport.so") is None
    sdk_module.reset_default_resolver()
    assert sdk_module.classify_transport("libcachedtransport.so") == {
        "module": "libcachedtransport.so", "kind": "foo-bar"}


def test_overlay_kind_survives_tap_sanitize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_singleton: None
) -> None:
    from friTap.flow.attribution import sanitize_attribution, transport_attribution

    overlay = _write_overlay(tmp_path / "o.json", {
        "libslugtransport": {"sdk": "Slug", "vendor": "Me", "category": "transport",
                             "transport_kind": "foo-bar"},
    })
    monkeypatch.setenv(SDK_SIGNATURES_ENV, str(overlay))
    sdk_module.reset_default_resolver()
    transport = transport_attribution("/data/app/lib/libslugtransport.so")
    assert transport == {"module": "libslugtransport.so", "kind": "foo-bar"}
    assert sanitize_attribution({"transport": transport}) == {"transport": transport}


def test_classify_transport_hands_out_fresh_dicts(clean_singleton: None) -> None:
    first = sdk_module.classify_transport("libcronet.so")
    second = sdk_module.classify_transport("libcronet.so")
    assert first == second and first is not second
    first["kind"] = "mutated"
    assert sdk_module.classify_transport("libcronet.so")["kind"] == "cronet"
    assert sdk_module._cached_transport.cache_info().hits >= 2


def test_classify_transport_cache_is_bounded() -> None:
    assert sdk_module._cached_transport.cache_info().maxsize == 256


def test_unreadable_base_signature_file_still_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        SdkResolver(signatures_path=tmp_path / "missing.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(ValueError):
        SdkResolver(signatures_path=broken)


def test_base_signature_file_without_entries_is_empty(tmp_path: Path) -> None:
    for content in ("[]", "{}", '{"entries": []}'):
        path = tmp_path / "base.json"
        path.write_text(content)
        assert SdkResolver(signatures_path=path).classify_transport("libcronet.so") is None


@pytest.mark.parametrize("content", [None, "{not json", "[]", '{"entries": []}'])
def test_bad_overlay_warns_and_is_skipped(
    tmp_path: Path, sdk_log: _ListHandler, content: object
) -> None:
    path = tmp_path / "bad.json"
    if content is not None:
        path.write_text(content)
    resolver = SdkResolver(extra_paths=[path])
    assert resolver.classify_package("com.adjust.sdk.Adjust").sdk == "Adjust"
    warnings = [r for r in sdk_log.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and str(path) in warnings[0].getMessage()



@pytest.mark.parametrize("bad_kind", ["Evil Kind!", "UPPER", "-lead", "a" * 33, 7, ["cronet"]])
def test_overlay_invalid_transport_kind_warns_and_is_dropped(
    tmp_path: Path, sdk_log: _ListHandler, bad_kind: object
) -> None:
    overlay = _write_overlay(tmp_path / "o.json", {
        "libbadtransport": {"sdk": "Bad", "vendor": "X", "category": "networking",
                            "transport_kind": bad_kind},
        "libgoodtransport": {"sdk": "Good", "vendor": "X", "category": "networking",
                             "transport_kind": "good-kind"},
        "libshared": {"sdk": "Shared", "vendor": "X", "category": "networking",
                      "transport_kind": "chrome-or-webview"},
    })
    resolver = SdkResolver(extra_paths=[overlay])
    assert resolver.classify_transport("libbadtransport.so") is None
    assert resolver.classify_package("libbadtransport").transport_kind == ""
    assert resolver.classify_transport("libgoodtransport.so")["kind"] == "good-kind"
    assert resolver.classify_transport("libshared.so")["kind"] == "webview"
    warnings = [r for r in sdk_log.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "libbadtransport" in warnings[0].getMessage()


def test_base_table_invalid_transport_kind_warns_without_raising(
    tmp_path: Path, sdk_log: _ListHandler
) -> None:
    base = _write_overlay(tmp_path / "base.json", {
        "libweird": {"sdk": "Weird", "vendor": "X", "category": "networking",
                     "transport_kind": "Not A Slug"},
        "libcronet": {"sdk": "Cronet", "vendor": "Google", "category": "networking",
                      "transport_kind": "cronet"},
    })
    resolver = SdkResolver(signatures_path=base)
    assert resolver.classify_transport("libweird.so") is None
    assert resolver.classify_transport("libcronet.so")["kind"] == "cronet"
    assert any("libweird" in r.getMessage() for r in sdk_log.records
               if r.levelno == logging.WARNING)


# --------------------------------------------------------------------------- #
# Shipped data
# --------------------------------------------------------------------------- #

def test_shipped_entry_count_matches_entries() -> None:
    payload = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))
    assert payload["schema"] == "fritap.sdk_signatures/1"
    assert payload["entry_count"] == len(payload["entries"])


def test_shipped_transport_entries_are_well_formed() -> None:
    entries = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))["entries"]
    assert entries["libcronet"] == {"sdk": "Cronet", "vendor": "Google",
                                    "category": "networking", "transport_kind": "cronet"}
    assert entries["libflutter.so"]["category"] == "framework"
    assert entries["libflutter.so"]["transport_kind"] == "flutter"
    for key, meta in entries.items():
        if meta.get("category") == "transport":
            assert meta.get("transport_kind"), key
