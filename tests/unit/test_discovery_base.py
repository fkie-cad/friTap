"""Unit tests for the shared discovery scaffolding (friTap/discovery_base.py)."""

from __future__ import annotations

import logging

from friTap import discovery_base

logger = logging.getLogger("test.discovery_base")


# --- discovery_disabled --------------------------------------------------- #

def test_discovery_disabled_unset_is_false(monkeypatch):
    monkeypatch.delenv("FRITAP_TEST_DISCOVERY", raising=False)
    assert discovery_base.discovery_disabled("FRITAP_TEST_DISCOVERY") is False


def test_discovery_disabled_falsey_values_are_false(monkeypatch):
    for val in ("", "0", "false", "False"):
        monkeypatch.setenv("FRITAP_TEST_DISCOVERY", val)
        assert discovery_base.discovery_disabled("FRITAP_TEST_DISCOVERY") is False


def test_discovery_disabled_truthy_values_are_true(monkeypatch):
    for val in ("1", "true", "yes", "on"):
        monkeypatch.setenv("FRITAP_TEST_DISCOVERY", val)
        assert discovery_base.discovery_disabled("FRITAP_TEST_DISCOVERY") is True


# --- resolve_dropin_dir --------------------------------------------------- #

def test_resolve_dropin_dir_uses_legacy_when_only_legacy_exists(monkeypatch, tmp_path):
    native_root = tmp_path / "native"
    legacy_home = tmp_path / "home"
    legacy_dir = legacy_home / ".fritap" / "analyzers"
    legacy_dir.mkdir(parents=True)
    monkeypatch.setattr(discovery_base.platformdirs, "user_data_dir",
                        lambda app: str(native_root))
    monkeypatch.setattr(discovery_base.Path, "home", staticmethod(lambda: legacy_home))

    resolved = discovery_base.resolve_dropin_dir("analyzers", logger)
    assert resolved == legacy_dir


def test_resolve_dropin_dir_creates_native_when_no_legacy(monkeypatch, tmp_path):
    native_root = tmp_path / "native"
    legacy_home = tmp_path / "home"  # no .fritap created
    monkeypatch.setattr(discovery_base.platformdirs, "user_data_dir",
                        lambda app: str(native_root))
    monkeypatch.setattr(discovery_base.Path, "home", staticmethod(lambda: legacy_home))

    resolved = discovery_base.resolve_dropin_dir("offline_decryptors", logger)
    assert resolved == native_root / "offline_decryptors"
    assert resolved.is_dir()  # created


# --- get_entry_points ----------------------------------------------------- #

def test_get_entry_points_unknown_group_is_empty():
    assert discovery_base.get_entry_points("fritap.no_such_group_xyz") == []


# --- iter_dropin_modules -------------------------------------------------- #

def test_iter_dropin_modules_missing_dir_yields_nothing(tmp_path):
    missing = tmp_path / "nope"
    assert list(discovery_base.iter_dropin_modules(missing, "t_", logger)) == []


def test_iter_dropin_modules_loads_py_skips_underscore_and_nonpy(tmp_path):
    (tmp_path / "good.py").write_text("VALUE = 42\n")
    (tmp_path / "_private.py").write_text("VALUE = 1\n")   # underscore -> skipped
    (tmp_path / "notes.txt").write_text("ignore me\n")      # non-.py -> skipped

    results = list(discovery_base.iter_dropin_modules(tmp_path, "t_", logger))
    assert [p.name for p, _ in results] == ["good.py"]
    _, mod = results[0]
    assert mod.VALUE == 42


def test_iter_dropin_modules_bad_file_is_skipped_not_raised(tmp_path, caplog):
    (tmp_path / "ok.py").write_text("OK = True\n")
    (tmp_path / "broken.py").write_text("this is not valid python :::\n")

    with caplog.at_level(logging.ERROR):
        results = list(discovery_base.iter_dropin_modules(
            tmp_path, "t_", logger, label="widget"))
    # The good module still loads; the broken one is logged and skipped.
    assert [p.name for p, _ in results] == ["ok.py"]
    assert any("widget" in r.message and "broken.py" in r.message for r in caplog.records)
