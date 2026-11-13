"""The ``chromium_internal_hosts`` signature list: matcher, bundled list, overlays, cache, and update script."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Iterator, List

import pytest

from friTap.analysis.attribution import sdk as sdk_module
from friTap.analysis.attribution.sdk import (
    CHROMIUM_INTERNAL_HOSTS_KEY,
    DEFAULT_SDK_SIGNATURES_PATH,
    SDK_SIGNATURES_ENV,
    ChromiumInternalHosts,
    SdkResolver,
    normalize_host,
)

_UPDATE_SCRIPT = Path(__file__).resolve().parents[3] / "dev" / "update_sdk_signatures.py"


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


@pytest.fixture
def clean_singleton(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(SDK_SIGNATURES_ENV, raising=False)
    sdk_module.reset_default_resolver()
    yield
    sdk_module.reset_default_resolver()


@pytest.fixture(scope="module")
def resolver() -> SdkResolver:
    return SdkResolver()


def _overlay(path: Path, hosts: object) -> Path:
    path.write_text(json.dumps({CHROMIUM_INTERNAL_HOSTS_KEY: hosts}))
    return path


# --------------------------------------------------------------------------- #
# Matcher
# --------------------------------------------------------------------------- #

def test_matcher_exact_and_suffix() -> None:
    matcher = ChromiumInternalHosts.from_patterns(["Update.GoogleAPIs.com", "*.GVT1.com"])
    assert matcher.matches("update.googleapis.com")
    assert matcher.matches("redirector.gvt1.com") and matcher.matches("a.b.gvt1.com")
    assert not matcher.matches("gvt1.com")  # *.suffix needs a label before it
    assert not matcher.matches("xgvt1.com")  # suffix is on a dot boundary
    assert not matcher.matches("") and not matcher.matches(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("host", [
    "safebrowsing.googleapis.com", "SAFEBROWSING.googleapis.COM",
    "safebrowsing.googleapis.com:443", "safebrowsing.googleapis.com.",
    " safebrowsing.googleapis.com ", "update.googleapis.com",
    "optimizationguide-pa.googleapis.com", "clientservices.googleapis.com",
    "content-autofill.googleapis.com", "dns.google", "clients2.google.com",
    "clients4.google.com", "redirector.gvt1.com", "edgedl.me.gvt1.com",
    "r1---sn-abc.gvt1.com:443",
])
def test_bundled_internal_hosts_match(resolver: SdkResolver, host: str) -> None:
    assert resolver.is_chromium_internal_host(host)


@pytest.mark.parametrize("host", [
    "evil-safebrowsing.googleapis.com.example", "safebrowsing.googleapis.com.example",
    "evil-safebrowsing.googleapis.com", "xsafebrowsing.googleapis.com",
    "googleapis.com", "gvt1.com", "dns.google.evil", "notdns.google",
    "clients3.google.com", "www.gstatic.com", "accounts.google.com",
    "android.clients.google.com", "example.com", "", "[::1]:443", "::1",
    "safebrowsing.googleapis.com/path",
])
def test_near_misses_do_not_match(resolver: SdkResolver, host: str) -> None:
    assert not resolver.is_chromium_internal_host(host)


def test_normalize_host() -> None:
    assert normalize_host("Example.COM:8443") == "example.com"
    assert normalize_host("example.com.") == "example.com"
    assert normalize_host("[2001:DB8::1]:443") == "[2001:db8::1]"
    assert normalize_host("[broken") == ""
    assert normalize_host(None) == ""  # type: ignore[arg-type]


def test_normalize_host_shares_the_tracker_core_but_strips_the_port() -> None:
    from friTap.analysis.attribution.resolver import normalize_hostname
    assert normalize_host(" Example.COM. ") == normalize_hostname(" Example.COM. ") == "example.com"
    assert normalize_host("Example.com:443") == "example.com"
    assert normalize_hostname("Example.com:443") == "example.com:443"  # tracker keeps the port


def test_bundled_list_is_canonical_and_valid() -> None:
    payload = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))
    hosts = payload[CHROMIUM_INTERNAL_HOSTS_KEY]
    assert hosts and hosts == sorted(set(hosts))  # canonical (dev/update_sdk_signatures.py)
    assert all(sdk_module._is_valid_host_pattern(host) for host in hosts)
    for app_level in ("www.gstatic.com", "accounts.google.com", "android.clients.google.com"):
        assert app_level not in hosts


# --------------------------------------------------------------------------- #
# Overlays, fallback, invalid patterns
# --------------------------------------------------------------------------- #

def test_overlay_union_keeps_bundled_hosts(tmp_path: Path) -> None:
    overlay = _overlay(tmp_path / "hosts.json", ["telemetry.acme.example", "*.acme-cdn.example"])
    resolver = SdkResolver(extra_paths=[overlay])
    for host in ("telemetry.acme.example", "x.acme-cdn.example", "safebrowsing.googleapis.com"):
        assert resolver.is_chromium_internal_host(host), host
    assert not SdkResolver().is_chromium_internal_host("telemetry.acme.example")


def test_hosts_only_overlay_is_usable(tmp_path: Path, sdk_log: _ListHandler) -> None:
    overlay = _overlay(tmp_path / "hosts.json", ["telemetry.acme.example"])
    assert SdkResolver(extra_paths=[overlay]).is_chromium_internal_host("telemetry.acme.example")
    assert not any("Skipping" in r.getMessage() for r in sdk_log.records)


def test_missing_key_falls_back_to_empty_default(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_SDK_SIGNATURES_PATH.read_text(encoding="utf-8"))
    del payload[CHROMIUM_INTERNAL_HOSTS_KEY]
    table = tmp_path / "no_hosts.json"
    table.write_text(json.dumps(payload))
    resolver = SdkResolver(signatures_path=table)
    assert not resolver.is_chromium_internal_host("safebrowsing.googleapis.com")
    # the rest of the table still loads
    assert resolver.classify_transport("libcronet.so")["kind"] == "cronet"


def test_invalid_host_patterns_are_warned_and_dropped(
    tmp_path: Path, sdk_log: _ListHandler
) -> None:
    bad = ["*", "*.", "a*b.com", "*.*.x.com", 7, "", "host.com:443", "https://x.com",
           "a b.com", "a..b.com", ".lead.com", "ok.acme.example"]
    resolver = SdkResolver(extra_paths=[_overlay(tmp_path / "bad.json", bad)])
    assert resolver.is_chromium_internal_host("ok.acme.example")
    assert not resolver.is_chromium_internal_host("host.com")
    assert not resolver.is_chromium_internal_host("anything.example")
    assert any(CHROMIUM_INTERNAL_HOSTS_KEY in r.getMessage() for r in sdk_log.records)


def test_non_list_value_is_warned_and_ignored(tmp_path: Path, sdk_log: _ListHandler) -> None:
    resolver = SdkResolver(extra_paths=[_overlay(tmp_path / "bad.json", "ok.acme.example")])
    assert not resolver.is_chromium_internal_host("ok.acme.example")
    assert resolver.is_chromium_internal_host("safebrowsing.googleapis.com")
    assert any("non-list" in r.getMessage() for r in sdk_log.records)


# --------------------------------------------------------------------------- #
# Module-level cached function
# --------------------------------------------------------------------------- #

def test_module_function_env_overlay_and_cache_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_singleton: None
) -> None:
    assert sdk_module.is_chromium_internal_host("update.googleapis.com:443")
    assert not sdk_module.is_chromium_internal_host("telemetry.acme.example")
    monkeypatch.setenv(SDK_SIGNATURES_ENV, str(_overlay(tmp_path / "h.json", ["telemetry.acme.example"])))
    assert not sdk_module.is_chromium_internal_host("telemetry.acme.example")  # cached
    sdk_module.reset_default_resolver()
    assert sdk_module.is_chromium_internal_host("telemetry.acme.example")
    assert not sdk_module.is_chromium_internal_host("") and not sdk_module.is_chromium_internal_host(None)


# --------------------------------------------------------------------------- #
# dev/update_sdk_signatures.py preserves the list
# --------------------------------------------------------------------------- #

def _load_update_script():
    spec = importlib.util.spec_from_file_location("update_sdk_signatures", _UPDATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_update_script_preserves_internal_hosts(tmp_path: Path) -> None:
    script = _load_update_script()
    source = tmp_path / "src.json"
    source.write_text(json.dumps({
        "entries": {"okhttp3": {"sdk": "OkHttp", "vendor": "Square", "category": "networking"}},
        CHROMIUM_INTERNAL_HOSTS_KEY: [" b.example ", "*.a.example", "b.example", 3, ""],
    }))
    hosts = script.load_internal_hosts(source)
    assert hosts == ["*.a.example", "b.example"]
    out = tmp_path / "out.json"
    script.write_signatures(script.load_entries(source), out, merged_exodus=False,
                            browser_packages=["com.android.chrome"], internal_hosts=hosts)
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written[CHROMIUM_INTERNAL_HOSTS_KEY] == hosts
    assert list(written)[-3:] == ["chromium_browser_packages", CHROMIUM_INTERNAL_HOSTS_KEY, "entries"]
    assert script.load_internal_hosts(tmp_path / "missing.json") is None


def test_update_script_applies_the_resolver_validation(tmp_path: Path, sdk_log: _ListHandler) -> None:
    script = _load_update_script()
    source = tmp_path / "src.json"
    source.write_text(json.dumps({
        "entries": {},
        CHROMIUM_INTERNAL_HOSTS_KEY: ["ok.example", "host.example:443", "https://x.example", "a.*.example"],
        "chromium_browser_packages": ["com.android.chrome", "org.*.browser", "com.brave.*", "a:b"],
    }))
    assert script.load_internal_hosts(source) == ["ok.example"]
    assert script.load_browser_packages(source) == ["com.android.chrome", "com.brave.*"]
    assert sdk_log.records  # dropped items are warned about, as the resolver does


def test_update_script_keeps_an_intentionally_empty_list(tmp_path: Path) -> None:
    script = _load_update_script()
    source = tmp_path / "src.json"
    source.write_text(json.dumps({"entries": {}, CHROMIUM_INTERNAL_HOSTS_KEY: []}))
    hosts = script.load_internal_hosts(source)
    assert hosts == []
    assert script.load_browser_packages(source) is None
    out = tmp_path / "out.json"
    script.write_signatures({}, out, merged_exodus=False,
                            browser_packages=script.load_browser_packages(source), internal_hosts=hosts)
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written[CHROMIUM_INTERNAL_HOSTS_KEY] == []
    assert "chromium_browser_packages" not in written


def test_update_script_regenerates_the_bundled_file_byte_identically(tmp_path: Path) -> None:
    script = _load_update_script()
    out = tmp_path / "regen.json"
    assert script.main(["--out", str(out)]) == 0
    assert out.read_bytes() == DEFAULT_SDK_SIGNATURES_PATH.read_bytes()
