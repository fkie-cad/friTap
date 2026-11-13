"""Unit tests for the offline SDK call-stack attribution module.

Covers longest-prefix resolution, dot-boundary safety, top-down backtrace
scanning (skipping platform/transport noise), native module resolution,
the unknown case, and the guarantee that loading and classifying perform no
network I/O.

Pure Python — no device/Frida/tshark, and (asserted below) no network.
"""

from __future__ import annotations

import socket

import pytest

from friTap.analysis.attribution import sdk as sdk_module
from friTap.analysis.attribution.sdk import Sdk, SdkResolver


@pytest.fixture(scope="module")
def resolver() -> SdkResolver:
    """A resolver built once from the bundled seed signatures."""
    return SdkResolver()


# --------------------------------------------------------------------------- #
# Sdk dataclass
# --------------------------------------------------------------------------- #

def test_sdk_as_dict_stable_keys() -> None:
    entry = Sdk(sdk="Facebook SDK", vendor="Meta", category="social")
    assert entry.as_dict() == {
        "sdk": "Facebook SDK",
        "vendor": "Meta",
        "category": "social",
    }


# --------------------------------------------------------------------------- #
# classify_package: longest-prefix match
# --------------------------------------------------------------------------- #

def test_longest_prefix_prefers_specific_over_generic(resolver: SdkResolver) -> None:
    generic = resolver.classify_package("com.google.firebase.messaging.FirebaseMessaging")
    assert generic is not None and generic.sdk == "Firebase"

    specific = resolver.classify_package("com.google.firebase.crashlytics.FirebaseCrashlytics")
    assert specific is not None
    assert specific.sdk == "Crashlytics"
    assert specific.vendor == "Google"
    assert specific.category == "crash_reporting"


def test_facebook_class_resolves_to_facebook_sdk(resolver: SdkResolver) -> None:
    result = resolver.classify_package("com.facebook.appevents.AppEventsLogger")
    assert result is not None
    assert result.sdk == "Facebook SDK"
    assert result.vendor == "Meta"
    assert result.category == "social"


def test_gms_ads_beats_generic_play_services(resolver: SdkResolver) -> None:
    result = resolver.classify_package("com.google.android.gms.ads.AdView")
    assert result is not None and result.sdk == "Google Mobile Ads"
    assert result.category == "advertising"

    generic = resolver.classify_package("com.google.android.gms.common.GoogleApiAvailability")
    assert generic is not None and generic.sdk == "Google Play Services"


@pytest.mark.parametrize(
    "name, expected_sdk",
    [
        ("okhttp3.Call", "OkHttp"),
        ("retrofit2.Retrofit", "Retrofit"),
        ("com.appsflyer.AppsFlyerLib", "AppsFlyer"),
        ("io.branch.referral.Branch", "Branch"),
        ("io.sentry.Sentry", "Sentry"),
    ],
)
def test_assorted_packages(resolver: SdkResolver, name: str, expected_sdk: str) -> None:
    result = resolver.classify_package(name)
    assert result is not None and result.sdk == expected_sdk


# --------------------------------------------------------------------------- #
# dot-boundary safety
# --------------------------------------------------------------------------- #

def test_dot_boundary_prevents_false_prefix_match(resolver: SdkResolver) -> None:
    assert resolver.classify_package("com.facebookx.Foo") is None


def test_unknown_package_returns_none(resolver: SdkResolver) -> None:
    assert resolver.classify_package("com.example.myapp.MainActivity") is None
    assert resolver.classify_package("") is None


# --------------------------------------------------------------------------- #
# classify_frames: top-down backtrace scan
# --------------------------------------------------------------------------- #

def test_classify_frames_skips_noise_returns_topmost_sdk(resolver: SdkResolver) -> None:
    frames = [
        "java.lang.Thread.run",
        "android.os.Handler.dispatchMessage",
        "okhttp3.internal.connection.RealConnection.connect",
        "org.conscrypt.ConscryptEngine.doHandshake",
        "com.facebook.appevents.AppEventsLogger.logEvent",
        "com.google.firebase.crashlytics.FirebaseCrashlytics.log",
    ]
    result = resolver.classify_frames(java_frames=frames)
    assert result is not None and result.sdk == "Facebook SDK"


def test_classify_frames_real_sdk_frame_never_skipped_as_noise(resolver: SdkResolver) -> None:
    # okhttp3 (the SDK) must match even though okhttp3.internal is noise.
    frames = ["okhttp3.internal.http.RealInterceptorChain.proceed", "okhttp3.RealCall.execute"]
    result = resolver.classify_frames(java_frames=frames)
    assert result is not None and result.sdk == "OkHttp"


def test_classify_frames_native_module_resolves(resolver: SdkResolver) -> None:
    # libflutter.so is now a transport (deny-listed); use a non-transport
    # native SDK module to exercise native resolution.
    result = resolver.classify_frames(native_modules=["libhermes.so"])
    assert result is not None
    assert result.sdk == "React Native"
    assert result.category == "framework"


def test_classify_frames_native_transport_prefix_is_denied(resolver: SdkResolver) -> None:
    # libcronet still prefix-matches its entry, but it is a transport
    # (transport_kind="cronet"), so it is never the originator.
    assert resolver.classify_package("libcronet.109.0.5386.0.so").sdk == "Cronet"
    assert resolver.classify_frames(native_modules=["libcronet.109.0.5386.0.so"]) is None


def test_classify_frames_java_precedes_native(resolver: SdkResolver) -> None:
    result = resolver.classify_frames(
        java_frames=["com.adjust.sdk.Adjust"],
        native_modules=["libflutter.so"],
    )
    assert result is not None and result.sdk == "Adjust"


def test_classify_frames_only_noise_returns_none(resolver: SdkResolver) -> None:
    frames = [
        "java.lang.Thread.run",
        "android.os.Handler.dispatchMessage",
        "okhttp3.internal.connection.RealConnection.connect",
    ]
    assert resolver.classify_frames(java_frames=frames) is None


def test_classify_frames_empty_returns_none(resolver: SdkResolver) -> None:
    assert resolver.classify_frames() is None


# --------------------------------------------------------------------------- #
# module-level convenience over the cached default resolver
# --------------------------------------------------------------------------- #

def test_module_level_helpers() -> None:
    pkg = sdk_module.classify_package("com.mixpanel.android.mpmetrics.MixpanelAPI")
    assert pkg is not None and pkg.sdk == "Mixpanel"

    frames = sdk_module.classify_frames(
        java_frames=["android.os.Handler.dispatchMessage", "com.appsflyer.AppsFlyerLib.start"]
    )
    assert frames is not None and frames.sdk == "AppsFlyer"


# --------------------------------------------------------------------------- #
# no network
# --------------------------------------------------------------------------- #

def test_no_network_during_load_and_classify(monkeypatch) -> None:
    """Building a resolver and classifying must not open any socket."""

    def _blocked(*args, **kwargs):  # pragma: no cover - only runs on failure
        raise AssertionError("SDK attribution performed network I/O")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    local_resolver = SdkResolver()
    result = local_resolver.classify_package("com.facebook.appevents.AppEventsLogger")
    assert result is not None and result.vendor == "Meta"
