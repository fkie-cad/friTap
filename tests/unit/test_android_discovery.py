"""Unit tests for friTap.android_discovery (tlsLibHunter discovery-profile adapter)."""

import builtins
import json
import sys
import types

import pytest

from friTap import android_discovery as ad

GEMINI_PROFILE = {
    "schema": "tlslibhunter.profile/1",
    "target": "com.google.android.apps.bard",
    "target_package": "com.google.android.apps.bard",
    "gate_packages": ["com.google.android.apps.bard", "com.google.android.googlequicksearchbox"],
    "process_patterns": ["com.google.android.apps.bard",
                         "com.google.android.googlequicksearchbox:googleapp"],
    "device_fingerprint": "google/redfin/redfin:14",
    "version_code": 353,
    "candidates": [
        {"pid": 18278, "process": "com.google.android.apps.bard",
         "package": "com.google.android.apps.bard", "uid": 10298, "role": "target", "evidence": []},
        {"pid": 18124, "process": "com.google.android.googlequicksearchbox:googleapp",
         "package": "com.google.android.googlequicksearchbox", "uid": 10156, "role": "delegate",
         "evidence": ["net:tcp:443"]},
        {"pid": 900, "process": "com.google.android.gms.persistent",
         "package": "com.google.android.gms", "uid": 10100, "role": "shared_system", "evidence": []},
    ],
}


@pytest.fixture
def profile_file(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(GEMINI_PROFILE))
    return str(path)


@pytest.fixture
def no_tlslibhunter(monkeypatch):
    """Make every ``tlslibhunter`` import fail, as if it were not installed."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("tlslibhunter"):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    for name in [m for m in sys.modules if m.startswith("tlslibhunter")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(builtins, "__import__", fake_import)


class TestLoadProfile:
    def test_parses_the_fields_fritap_needs(self, profile_file):
        profile = ad.load_profile(profile_file)
        assert profile.target_package == "com.google.android.apps.bard"
        assert profile.gate_packages[1] == "com.google.android.googlequicksearchbox"
        assert [c.role for c in profile.candidates] == ["target", "delegate", "shared_system"]
        assert profile.candidates[1].pid == 18124

    def test_works_without_tlslibhunter(self, profile_file, no_tlslibhunter):
        assert ad.load_profile(profile_file).candidates[0].process == "com.google.android.apps.bard"

    def test_rejects_unknown_schema(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text(json.dumps({**GEMINI_PROFILE, "schema": "other/9"}))
        with pytest.raises(ValueError, match="unsupported profile schema"):
            ad.load_profile(str(path))

    def test_rejects_malformed_candidate(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text(json.dumps({**GEMINI_PROFILE, "candidates": [{"pid": 1}]}))
        with pytest.raises(ValueError, match="malformed"):
            ad.load_profile(str(path))

    def test_rejects_non_json(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text("not json")
        with pytest.raises(ValueError, match="not a JSON"):
            ad.load_profile(str(path))

    def test_real_profile_parses(self):
        """A profile tlsLibHunter's own Profile.to_dict() would write round-trips."""
        assert ad.profile_from_dict(json.loads(json.dumps(GEMINI_PROFILE))).process_patterns


class TestHelpers:
    def test_non_shared_packages_excludes_shared_system(self, profile_file):
        assert ad.non_shared_packages(ad.load_profile(profile_file)) == [
            "com.google.android.apps.bard", "com.google.android.googlequicksearchbox"]

    def test_running_candidates_excludes_main_and_shared(self, profile_file):
        names = [c.process for c in ad.running_candidates(ad.load_profile(profile_file))]
        assert names == ["com.google.android.googlequicksearchbox:googleapp"]

    def test_role_by_process_has_no_shared_entries(self, profile_file):
        roles = ad.load_profile(profile_file).role_by_process()
        assert "com.google.android.gms.persistent" not in roles
        assert roles["com.google.android.googlequicksearchbox:googleapp"] == "delegate"


class TestDiscoverProfile:
    def test_missing_tlslibhunter_raises_clear_error(self, no_tlslibhunter):
        with pytest.raises(ad.DiscoveryUnavailableError, match="--profile"):
            ad.discover_profile("serial", "com.example.app", 5)

    def test_uses_engine_runner_and_converts(self, monkeypatch):
        calls = {}

        class FakeProfile:
            def to_dict(self):
                return GEMINI_PROFILE

        def discover(runner, target, duration, interval):
            calls.update(runner=runner, target=target, duration=duration, interval=interval)
            return FakeProfile()

        engine = types.SimpleNamespace(make_adb_runner=lambda serial: f"runner:{serial}",
                                       discover=discover)
        monkeypatch.setattr(ad, "_import_discovery", lambda: engine)
        profile = ad.discover_profile("SER", "com.google.android.apps.bard", 12)
        assert calls == {"runner": "runner:SER", "target": "com.google.android.apps.bard",
                         "duration": 12, "interval": ad.DISCOVERY_SAMPLE_INTERVAL}
        assert profile.target_package == "com.google.android.apps.bard"


def _profile_with(**overrides):
    return {**GEMINI_PROFILE, **overrides}


def _with_candidate(**fields):
    cand = {**GEMINI_PROFILE["candidates"][1], **fields}
    return _profile_with(candidates=[GEMINI_PROFILE["candidates"][0], cand])


class TestPackageValidation:
    @pytest.mark.parametrize("name", ["com.example.app", "a.b", "com.x_y.z1", "x.1y"])
    def test_accepts_package_names(self, name):
        assert ad.is_valid_android_package(name)

    @pytest.mark.parametrize("name", ["", "app", "com.x;reboot", "com.x y", "com.$(id).x",
                                      "1com.x", ".com.x", "com..x", "com.x\n", None, 5])
    def test_rejects_non_package_names(self, name):
        assert not ad.is_valid_android_package(name)

    @pytest.mark.parametrize("name,ok", [
        ("com.example.app", True), ("com.example.app:remote", True),
        ("com.example.app:a.b_1", True), ("com.example.app:", False),
        ("com.example.app:x;id", False), ("system_server", False), ("com.x:a:b", False),
    ])
    def test_process_names(self, name, ok):
        assert ad.is_valid_android_process(name) is ok

    def test_rejects_injected_gate_package(self):
        with pytest.raises(ValueError, match="gate_packages"):
            ad.profile_from_dict(_profile_with(gate_packages=["com.x; reboot"]))

    def test_rejects_injected_target_package(self):
        with pytest.raises(ValueError, match="target_package"):
            ad.profile_from_dict(_profile_with(target_package="$(reboot)"))

    def test_rejects_injected_candidate_package(self):
        with pytest.raises(ValueError, match="candidate package"):
            ad.profile_from_dict(_with_candidate(package="com.x`id`"))

    def test_rejects_injected_candidate_process(self):
        with pytest.raises(ValueError, match="process name"):
            ad.profile_from_dict(_with_candidate(process="com.x:y;id"))

    def test_shared_system_names_are_not_checked(self):
        shared = {"pid": 1000, "process": "system_server", "package": "android",
                  "role": "shared_system"}
        profile = ad.profile_from_dict(_profile_with(candidates=[shared]))
        assert profile.shared_candidates()[0].process == "system_server"

    def test_error_excerpt_is_escaped_and_capped(self):
        with pytest.raises(ValueError) as info:
            ad.profile_from_dict(_profile_with(gate_packages=["\x1b[2J" + "a" * 500]))
        message = str(info.value)
        assert "\x1b" not in message and "\\x1b" in message
        assert len(message) < 250


class TestDiscoverFailures:
    def _engine(self, error):
        def discover(*_args):
            raise error
        return types.SimpleNamespace(make_adb_runner=lambda serial: None, discover=discover)

    def test_unexpected_engine_error_becomes_discovery_failed(self, monkeypatch):
        monkeypatch.setattr(ad, "_import_discovery", lambda: self._engine(KeyError("boom")))
        with pytest.raises(ad.DiscoveryFailedError, match="KeyError"):
            ad.discover_profile("SER", "com.example.app", 1)

    def test_value_error_keeps_its_message(self, monkeypatch):
        monkeypatch.setattr(ad, "_import_discovery",
                            lambda: self._engine(ValueError("invalid Android package name")))
        with pytest.raises(ValueError, match="invalid Android package name"):
            ad.discover_profile("SER", "com.example.app", 1)

    def test_shared_only_packages(self):
        profile = ad.profile_from_dict(GEMINI_PROFILE)
        assert ad.shared_only_packages(profile) == {"com.google.android.gms"}
