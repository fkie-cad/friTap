"""``load_extensions()`` also discovers third-party offline decryptors (task 6.6).

Offline-decryptor discovery belongs in the viewer's decrypt path and in
``load_extensions()`` (so ``TapViewerScreen`` / ``fritap -r`` get it), never in
the ``pcap_to_tap`` library function. It has its own switch, independent of
``FRITAP_DISABLE_UI_EXTENSIONS``.
"""

import pytest

import friTap.offline.discovery as disc
from friTap import extensions as ext
from tests.unit._ext_helpers import FakeEntryPoint

OFFLINE_DISABLE_ENV = "FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)
    monkeypatch.delenv(OFFLINE_DISABLE_ENV, raising=False)
    monkeypatch.setattr(disc, "_DISCOVERY_ERRORS", ())


@pytest.fixture
def discovery_calls(monkeypatch):
    """Replace offline discovery with a recorder; returns the list of kwargs."""
    calls: list = []
    monkeypatch.setattr(
        disc, "discover_external_offline_decryptors",
        lambda **kwargs: calls.append(kwargs) or {},
    )
    return calls


@pytest.fixture
def ui_ran(monkeypatch):
    """Stub the UI entry-point lookup with one entry point; returns its run log."""
    ran: list = []
    monkeypatch.setattr(
        ext.discovery_base, "get_entry_points",
        lambda *a, **kw: [FakeEntryPoint("ui-ep", lambda: ran.append("ui"))],
    )
    return ran


@pytest.fixture
def scans(monkeypatch):
    """Real (cached) discovery with both sources stubbed; returns the scan log."""
    log: list = []
    monkeypatch.setattr(disc, "_DISCOVERED", None)
    monkeypatch.setattr(disc, "_load_dir_decryptors", lambda found: log.append("dir"))
    monkeypatch.setattr(disc, "_load_entrypoint_decryptors",
                        lambda found: log.append("ep"))
    return log


def test_load_extensions_triggers_offline_discovery_once(scans, ui_ran):
    ext.load_extensions()
    ext.load_extensions()
    assert scans == ["dir", "ep"]
    assert ui_ran == ["ui"]


def test_force_is_passed_through_to_offline_discovery(discovery_calls, ui_ran):
    ext.load_extensions()
    ext.load_extensions(force=True)
    assert discovery_calls == [{"force": False}, {"force": True}]


def test_raising_discovery_is_swallowed_and_ui_entry_points_still_run(
        monkeypatch, ui_ran, fritap_log_records):
    def boom(**kwargs):
        raise RuntimeError("bad decryptor plugin")

    monkeypatch.setattr(disc, "discover_external_offline_decryptors", boom)
    records = fritap_log_records("friTap.extensions")

    ext.load_extensions()

    assert ui_ran == ["ui"]
    assert any("offline decryptors" in r.getMessage()
               and "bad decryptor plugin" in r.getMessage() for r in records)


def test_failing_ui_entry_points_do_not_skip_offline_discovery(
        monkeypatch, discovery_calls):
    def fail(*a, **kw):
        raise OSError("metadata unreadable")

    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions()
    assert discovery_calls == [{"force": False}]


def test_ui_switch_skips_ui_entry_points_but_not_offline_discovery(
        monkeypatch, discovery_calls, ui_ran):
    monkeypatch.setenv(ext.DISABLE_ENV_VAR, "1")
    ext.load_extensions()
    assert ui_ran == []
    assert discovery_calls == [{"force": False}]


def test_offline_switch_is_honoured_by_the_discovery_module_itself(
        monkeypatch, ui_ran):
    """The offline switch lives in the discovery module; the UI part still runs."""
    scans: list = []
    monkeypatch.setattr(disc, "_DISCOVERED", None)
    monkeypatch.setattr(disc, "_load_dir_decryptors", lambda found: scans.append("dir"))
    monkeypatch.setattr(disc, "_load_entrypoint_decryptors",
                        lambda found: scans.append("ep"))
    monkeypatch.setenv(OFFLINE_DISABLE_ENV, "1")

    ext.load_extensions()

    assert scans == []
    assert ui_ran == ["ui"]


def test_real_discovery_scans_both_sources_when_ui_extensions_disabled(
        monkeypatch, ui_ran):
    scans: list = []
    monkeypatch.setattr(disc, "_DISCOVERED", None)
    monkeypatch.setattr(disc, "_load_dir_decryptors", lambda found: scans.append("dir"))
    monkeypatch.setattr(disc, "_load_entrypoint_decryptors",
                        lambda found: scans.append("ep"))
    monkeypatch.setenv(ext.DISABLE_ENV_VAR, "1")

    ext.load_extensions()

    assert scans == ["dir", "ep"]
    assert ui_ran == []


def test_screen_style_call_skips_offline_discovery(discovery_calls, ui_ran):
    ext.load_extensions(offline_decryptors=False)
    assert ui_ran == ["ui"]
    assert discovery_calls == []


def test_later_default_call_runs_offline_step_only(scans, ui_ran):
    ext.load_extensions(offline_decryptors=False)
    assert scans == []
    ext.load_extensions()
    ext.load_extensions()
    assert ui_ran == ["ui"]
    assert scans == ["dir", "ep"]


def test_force_reruns_both_steps(discovery_calls, ui_ran):
    ext.load_extensions()
    ext.load_extensions(force=True)
    assert ui_ran == ["ui", "ui"]
    assert len(discovery_calls) == 2


def test_system_exit_from_entry_point_is_recorded(monkeypatch, discovery_calls):
    class _Exiting:
        name = "exiting"

        def load(self):
            def register():
                raise SystemExit(3)
            return register

    monkeypatch.setattr(ext.discovery_base, "get_entry_points",
                        lambda *a, **kw: [_Exiting()])
    ext.load_extensions()
    errors = ext.extension_load_errors()
    assert [e.source for e in errors] == ["exiting"]
    assert "SystemExit" in errors[0].error


def test_constructing_main_screen_does_not_run_offline_discovery(discovery_calls):
    from friTap.tui.screens.main_screen import MainScreen

    MainScreen()
    assert discovery_calls == []
