"""Tests for zero-config external-analyzer discovery.

Covers the drop-in directory scan, the env opt-out, registry integration
(``available_analyzers`` / ``resolve_analyzers`` picking up discovered
analyzers), the detailed listing, and the built-in-name shadowing guard.
"""

import textwrap

import pytest

import friTap.analysis.discovery as discovery
import friTap.analysis.registry as registry


TOY = textwrap.dedent(
    """
    class DropInAnalyzer:
        name = "dropin"
        is_fritap_analyzer = True
        description = "Drop-in demo analyzer"

        def analyze_flow(self, flow):
            return []
    """
)

SHADOW = textwrap.dedent(
    """
    class ShadowAnalyzer:
        name = "credentials"  # tries to shadow a built-in
        is_fritap_analyzer = True

        def analyze_flow(self, flow):
            return []
    """
)


@pytest.fixture
def analyzers_dir(tmp_path, monkeypatch):
    """Point discovery at a temp analyzers dir and isolate caches/bridge."""
    monkeypatch.setattr(discovery, "_ANALYZER_DIR", tmp_path)
    monkeypatch.setattr(discovery, "_CACHE", None)
    # Keep the test hermetic: ignore any real plugins / entry points.
    monkeypatch.setattr(discovery, "_load_plugin_bridge_analyzers", lambda found: None)
    monkeypatch.setattr(discovery, "_load_entrypoint_analyzers", lambda found: None)
    # Reset the registry discovery cache so refresh_discovered re-scans.
    monkeypatch.setattr(registry, "_DISCOVERED", {})
    monkeypatch.setattr(registry, "_DISCOVERY_DONE", False)
    return tmp_path


def test_dropin_analyzer_is_discovered(analyzers_dir):
    (analyzers_dir / "toy.py").write_text(TOY)

    found = discovery.discover_external_analyzers(force=True)
    assert "dropin" in found
    assert found["dropin"].source.startswith("dir:")
    assert found["dropin"].instance.name == "dropin"


def test_discovery_feeds_registry(analyzers_dir):
    (analyzers_dir / "toy.py").write_text(TOY)
    registry.refresh_discovered()

    assert "dropin" in registry.available_analyzers()
    # Selectable by name and included in "all".
    assert [a.name for a in registry.resolve_analyzers("dropin")] == ["dropin"]
    assert "dropin" in {a.name for a in registry.resolve_analyzers("all")}


def test_env_opt_out_disables_discovery(analyzers_dir, monkeypatch):
    (analyzers_dir / "toy.py").write_text(TOY)
    monkeypatch.setenv("FRITAP_DISABLE_ANALYZER_DISCOVERY", "1")

    assert discovery.discover_external_analyzers(force=True) == {}
    registry.refresh_discovered()
    assert "dropin" not in registry.available_analyzers()


def test_discovered_cannot_shadow_builtin(analyzers_dir):
    (analyzers_dir / "shadow.py").write_text(SHADOW)
    registry.refresh_discovered()

    # The built-in credentials factory must still win.
    from friTap.analysis.credentials import CredentialAnalyzer

    resolved = registry.resolve_analyzers("credentials")
    assert isinstance(resolved[0], CredentialAnalyzer)


def test_builtin_collision_not_double_listed(analyzers_dir):
    # A discovered analyzer whose name collides with a built-in must appear
    # once (as the built-in), never twice, in the detailed listing.
    (analyzers_dir / "shadow.py").write_text(SHADOW)  # name="credentials"
    registry.refresh_discovered()

    from friTap.commands.analyze import list_analyzers_detailed

    infos = list_analyzers_detailed()
    creds = [i for i in infos if i.name == "credentials"]
    assert len(creds) == 1
    assert creds[0].source == "builtin"


def test_list_analyzers_detailed_includes_externals(analyzers_dir):
    (analyzers_dir / "toy.py").write_text(TOY)
    registry.refresh_discovered()

    from friTap.commands.analyze import list_analyzers_detailed

    infos = list_analyzers_detailed()
    by_name = {i.name: i for i in infos}
    assert {"credentials", "ioc", "privacy", "protobuf"} <= set(by_name)
    assert by_name["credentials"].source == "builtin"
    assert "dropin" in by_name
    assert by_name["dropin"].source.startswith("dir:")


INVALID_NAME = textwrap.dedent(
    """
    class NoName:
        name = None  # invalid — must be a non-empty string
        is_fritap_analyzer = True

        def analyze_flow(self, flow):
            return []
    """
)


def test_invalid_name_is_skipped_and_does_not_poison_enumeration(analyzers_dir):
    # A None/empty name must be rejected — otherwise sorting the discovered
    # names (in available_analyzers / --list-analyzers) crashes on None.
    (analyzers_dir / "bad.py").write_text(INVALID_NAME)
    (analyzers_dir / "good.py").write_text(TOY)  # name="dropin"

    found = discovery.discover_external_analyzers(force=True)
    assert "dropin" in found
    assert None not in found

    registry.refresh_discovered()
    names = registry.available_analyzers()  # must not raise
    assert "dropin" in names
    assert None not in names


def test_concurrent_cold_resolve_is_consistent(analyzers_dir):
    # Publish-after-populate + lock: a cold concurrent resolve must always see
    # the full set, never a partial (built-ins-only) result.
    import threading

    n_external = 12
    for i in range(n_external):
        (analyzers_dir / f"a{i}.py").write_text(
            f"class A{i}:\n"
            f"    name = 'ext{i}'\n"
            f"    is_fritap_analyzer = True\n"
            f"    def analyze_flow(self, flow):\n        return []\n"
        )
    expected = len(registry.ANALYZER_REGISTRY) + n_external

    seen: set = set()
    for _ in range(10):
        registry._DISCOVERED.clear()
        registry._DISCOVERY_DONE = False
        discovery._CACHE = None
        out: list = []

        def _resolve() -> None:
            out.append(len(registry.resolve_analyzers("all")))

        threads = [threading.Thread(target=_resolve) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        seen.update(out)

    assert seen == {expected}, f"inconsistent concurrent resolve counts: {seen}"
