"""Per-source offline-decryptor discovery failures reach ``extension_load_errors()``.

``friTap.offline.discovery`` logs every failing source (entry-point enumeration,
``ep.load()``, registration, drop-in import) and now also collects it as a
``(source, error)`` pair (``offline_discovery_errors()``). ``load_extensions()``
reports each pair live as ``ExtensionLoadError("offline-decryptor:<source>", error)``,
whoever triggered the scan.
"""

import subprocess
import sys
import types

import pytest

import friTap.offline.discovery as disc
from friTap import discovery_base
from friTap import extensions as ext
from friTap.offline.registry import OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP
from tests.unit._ext_helpers import FakeEntryPoint as _EP
from tests.unit._offline_helpers import make_offline_entry

OFFLINE_DISABLE_ENV = "FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY"
UI_GROUP = ext.UI_EXTENSION_ENTRY_POINT_GROUP
OFFLINE_GROUP = OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Offline discovery on, no cached scan; discovery state restored after the test."""
    monkeypatch.delenv(OFFLINE_DISABLE_ENV, raising=False)
    monkeypatch.setattr(disc, "_DISCOVERED", None)
    monkeypatch.setattr(disc, "_DISCOVERY_ERRORS", ())


@pytest.fixture
def dropin_dir(monkeypatch, tmp_path):
    directory = tmp_path / "offline_decryptors"
    directory.mkdir()
    monkeypatch.setattr(disc, "_OFFLINE_DECRYPTOR_DIR", directory)
    return directory


@pytest.fixture
def entry_points(monkeypatch):
    """Group -> entry points (or an exception to raise on enumeration)."""
    groups: dict = {UI_GROUP: [], OFFLINE_GROUP: []}

    def fake_get_entry_points(group, **kwargs):
        value = groups[group]
        if isinstance(value, BaseException):
            raise value
        return list(value)

    monkeypatch.setattr(discovery_base, "get_entry_points", fake_get_entry_points)
    return groups


def _decryptor_module(**attrs):
    module = types.ModuleType("fake_decryptor_ext")
    module.is_fritap_offline_decryptor = True
    for name, value in attrs.items():
        setattr(module, name, value)
    return module


def _boom(entry, **kwargs):
    raise RuntimeError("registry says no")


# ---------------------------------------------------------------------------
# offline_discovery_errors(): each failing source is collected
# ---------------------------------------------------------------------------

def test_failing_entry_point_load_is_collected(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]

    disc.discover_external_offline_decryptors(force=True)

    assert disc.offline_discovery_errors() == [
        ("entrypoint:bad-ep", "ImportError: no module")]


def test_failing_registration_of_entry_point_entry_is_collected(
        monkeypatch, dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("entry-ep", make_offline_entry("errproto"))]
    monkeypatch.setattr(disc, "register_offline_decryptor", _boom)

    found = disc.discover_external_offline_decryptors(force=True)

    assert found == {}
    assert disc.offline_discovery_errors() == [
        ("entrypoint:entry-ep", "RuntimeError: registry says no")]


def test_failing_registration_inside_module_is_collected(
        monkeypatch, dropin_dir, entry_points):
    module = _decryptor_module(ENTRY=make_offline_entry("errproto"))
    entry_points[OFFLINE_GROUP] = [_EP("module-ep", module)]
    monkeypatch.setattr(disc, "register_offline_decryptor", _boom)

    disc.discover_external_offline_decryptors(force=True)

    assert disc.offline_discovery_errors() == [
        ("entrypoint:module-ep", "RuntimeError: registry says no")]


def test_broken_dropin_file_is_collected_and_still_logged(
        dropin_dir, entry_points, fritap_log_records):
    broken = dropin_dir / "broken.py"
    broken.write_text('raise ValueError("kaboom")\n')
    records = fritap_log_records("friTap.offline.discovery")

    disc.discover_external_offline_decryptors(force=True)

    assert disc.offline_discovery_errors() == [(f"dir:{broken}", "ValueError: kaboom")]
    assert any("broken.py" in r.getMessage() and "kaboom" in r.getMessage()
               for r in records)


def test_unreadable_module_attribute_is_collected(dropin_dir, entry_points):
    flaky = dropin_dir / "flaky.py"
    flaky.write_text(
        "is_fritap_offline_decryptor = True\n"
        "def __dir__():\n    return ['boom']\n"
        "def __getattr__(name):\n    raise RuntimeError('descriptor')\n")

    disc.discover_external_offline_decryptors(force=True)

    assert disc.offline_discovery_errors() == [
        (f"dir:{flaky}", "RuntimeError: descriptor")]


def test_entry_point_enumeration_failure_is_collected(
        dropin_dir, entry_points, fritap_log_records):
    entry_points[OFFLINE_GROUP] = OSError("metadata unreadable")
    records = fritap_log_records("friTap.offline.discovery")

    disc.discover_external_offline_decryptors(force=True)

    assert disc.offline_discovery_errors() == [
        ("entrypoints", "OSError: metadata unreadable")]
    assert any("enumerate" in r.getMessage() for r in records)


def test_no_failures_means_no_errors(dropin_dir, entry_points):
    disc.discover_external_offline_decryptors(force=True)
    assert disc.offline_discovery_errors() == []


# ---------------------------------------------------------------------------
# caching, forced re-scan, disabled, copy semantics
# ---------------------------------------------------------------------------

def test_cached_call_keeps_the_errors(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    disc.discover_external_offline_decryptors(force=True)
    first = disc.offline_discovery_errors()

    entry_points[OFFLINE_GROUP] = []  # a re-scan would now find nothing wrong
    disc.discover_external_offline_decryptors()

    assert first == [("entrypoint:bad-ep", "ImportError: no module")]
    assert disc.offline_discovery_errors() == first


def test_forced_rescan_replaces_the_errors(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    disc.discover_external_offline_decryptors(force=True)

    entry_points[OFFLINE_GROUP] = [_EP("other-ep", exc=ValueError("later"))]
    disc.discover_external_offline_decryptors(force=True)
    assert disc.offline_discovery_errors() == [
        ("entrypoint:other-ep", "ValueError: later")]

    entry_points[OFFLINE_GROUP] = []
    disc.discover_external_offline_decryptors(force=True)
    assert disc.offline_discovery_errors() == []


def test_disabled_discovery_reports_no_errors(monkeypatch, dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    disc.discover_external_offline_decryptors(force=True)
    assert disc.offline_discovery_errors()

    monkeypatch.setenv(OFFLINE_DISABLE_ENV, "1")

    assert disc.offline_discovery_errors() == []


def test_disabled_discovery_collects_nothing(monkeypatch, dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    monkeypatch.setenv(OFFLINE_DISABLE_ENV, "1")

    assert disc.discover_external_offline_decryptors(force=True) == {}
    monkeypatch.delenv(OFFLINE_DISABLE_ENV)

    assert disc.offline_discovery_errors() == []


def test_offline_discovery_errors_returns_a_copy(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    disc.discover_external_offline_decryptors(force=True)

    disc.offline_discovery_errors().clear()

    assert len(disc.offline_discovery_errors()) == 1


def test_errors_do_not_leak_into_the_next_scan_buffer(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    disc.discover_external_offline_decryptors(force=True)

    assert disc._SCAN_ERRORS == []


# ---------------------------------------------------------------------------
# load_extensions() -> extension_load_errors()
# ---------------------------------------------------------------------------

def _offline_error_sources():
    return [e.source for e in ext.extension_load_errors()
            if e.source.startswith("offline-decryptor")]


def test_failures_reach_extension_load_errors_with_prefix(
        monkeypatch, dropin_dir, entry_points):
    broken = dropin_dir / "broken.py"
    broken.write_text('raise ValueError("kaboom")\n')
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]

    ext.load_extensions()

    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError(f"offline-decryptor:dir:{broken}", "ValueError: kaboom"),
        ext.ExtensionLoadError("offline-decryptor:entrypoint:bad-ep",
                               "ImportError: no module"),
    ]


def test_enumeration_failure_reaches_extension_load_errors(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = OSError("metadata unreadable")

    ext.load_extensions()

    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("offline-decryptor:entrypoints",
                               "OSError: metadata unreadable")]


def test_registration_failure_reaches_extension_load_errors(
        monkeypatch, dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("entry-ep", make_offline_entry("errproto"))]
    monkeypatch.setattr(disc, "register_offline_decryptor", _boom)

    ext.load_extensions()

    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("offline-decryptor:entrypoint:entry-ep",
                               "RuntimeError: registry says no")]


def test_whole_step_failure_keeps_its_own_source(monkeypatch):
    def fail(force=False):
        raise ValueError("disc")

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", fail)

    ext.load_extensions()

    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("offline-decryptors", "ValueError: disc")]


def test_cached_load_keeps_and_forced_load_replaces_offline_errors(
        dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    ext.load_extensions()
    ext.load_extensions()  # idempotent: no re-run, errors kept, not duplicated
    assert _offline_error_sources() == ["offline-decryptor:entrypoint:bad-ep"]

    entry_points[OFFLINE_GROUP] = [_EP("other-ep", exc=ImportError("no module"))]
    ext.load_extensions(force=True)  # replaced, not accumulated
    assert _offline_error_sources() == ["offline-decryptor:entrypoint:other-ep"]

    entry_points[OFFLINE_GROUP] = []
    ext.load_extensions(force=True)
    assert ext.extension_load_errors() == []


# ---------------------------------------------------------------------------
# re-runs: the UI step replaces its own errors; offline errors are read live
# ---------------------------------------------------------------------------

@pytest.fixture
def failing_both(monkeypatch, dropin_dir, entry_points):
    """One failing UI entry point and one failing offline entry point."""
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)
    entry_points[UI_GROUP] = [_EP("bad-ui", exc=ImportError("ui"))]
    entry_points[OFFLINE_GROUP] = [_EP("bad-off", exc=ImportError("off"))]
    return entry_points


def _sources():
    return [e.source for e in ext.extension_load_errors()]


def test_ui_only_rerun_keeps_offline_errors(failing_both):
    ext.load_extensions()
    assert _sources() == ["bad-ui", "offline-decryptor:entrypoint:bad-off"]

    failing_both[UI_GROUP] = [_EP("bad-ui-2", exc=ImportError("ui"))]
    failing_both[OFFLINE_GROUP] = []  # would clear the offline error if it re-ran
    ext.load_extensions(force=True, offline_decryptors=False)

    assert _sources() == ["bad-ui-2", "offline-decryptor:entrypoint:bad-off"]


def test_ui_only_rerun_keeps_whole_step_offline_error(monkeypatch, failing_both):
    def fail(force=False):
        raise ValueError("disc")

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", fail)
    ext.load_extensions()
    assert _sources() == ["bad-ui", "offline-decryptors"]

    failing_both[UI_GROUP] = []
    ext.load_extensions(force=True, offline_decryptors=False)

    assert _sources() == ["offline-decryptors"]


def test_scan_triggered_outside_load_extensions_is_reported_and_keeps_ui(
        failing_both):
    """The viewer's decrypt path calls discovery directly; its errors show up."""
    ext.load_extensions()

    failing_both[UI_GROUP] = []  # would clear the UI error if the UI step re-ran
    failing_both[OFFLINE_GROUP] = [_EP("bad-off-2", exc=ImportError("off"))]
    disc.discover_external_offline_decryptors(force=True)

    assert _sources() == ["bad-ui", "offline-decryptor:entrypoint:bad-off-2"]


def test_first_scan_by_decrypt_path_is_reported(dropin_dir, entry_points):
    entry_points[OFFLINE_GROUP] = [_EP("bad-ep", exc=ImportError("no module"))]
    ext.load_extensions(offline_decryptors=False)  # screen-style: no scan
    assert ext.extension_load_errors() == []

    disc.discover_external_offline_decryptors()  # as the decrypt worker does

    assert _offline_error_sources() == ["offline-decryptor:entrypoint:bad-ep"]


def test_repeated_default_loads_on_cached_scan_do_not_duplicate_errors(
        failing_both):
    ext.load_extensions()
    ext.load_extensions()  # discovery scan is cached: same errors, listed once

    assert _sources() == ["bad-ui", "offline-decryptor:entrypoint:bad-off"]


def test_force_rerun_of_both_steps_replaces_everything(failing_both):
    ext.load_extensions()

    failing_both[UI_GROUP] = []
    failing_both[OFFLINE_GROUP] = []
    ext.load_extensions(force=True)

    assert ext.extension_load_errors() == []


def test_ui_errors_are_listed_before_offline_errors(failing_both):
    ext.load_extensions(offline_decryptors=False)
    ext.load_extensions()  # offline step appended after the UI step

    failing_both[UI_GROUP] = [_EP("bad-ui-2", exc=ImportError("ui"))]
    ext.load_extensions(force=True, offline_decryptors=False)  # UI error re-added last

    assert _sources() == ["bad-ui-2", "offline-decryptor:entrypoint:bad-off"]


def test_later_successful_offline_step_clears_whole_step_error(monkeypatch):
    def fail(force=False):
        raise ValueError("disc")

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", fail)
    ext.load_extensions()
    assert _sources() == ["offline-decryptors"]

    monkeypatch.setattr(disc, "discover_external_offline_decryptors",
                        lambda force=False: {})
    ext.load_extensions()

    assert ext.extension_load_errors() == []


def test_reporting_does_not_import_offline_discovery():
    code = (
        "import sys\n"
        "from friTap.extensions import extension_load_errors\n"
        "assert 'friTap.offline.discovery' not in sys.modules\n"
        "assert extension_load_errors() == []\n"
        "assert 'friTap.offline.discovery' not in sys.modules\n"
    )
    result = subprocess.run([sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
