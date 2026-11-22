"""Tests for friTap.tui.theme_install.install_theme under a FOREIGN host app.

The host is a plain ``textual.app.App`` with its own theme and CSS variables
and no ``$fritap-*`` definitions -- the situation an embedding app is in.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.css.errors import UnresolvedVariableError  # noqa: E402
from textual.theme import Theme  # noqa: E402
from textual.widgets import Static  # noqa: E402

from friTap.tui import themes  # noqa: E402
from friTap.tui.modals.alert_modal import AlertModal  # noqa: E402
from friTap.tui.theme_install import install_theme  # noqa: E402

HOST_DARK = Theme(
    name="host-dark",
    primary="#123456",
    dark=True,
    variables={"host-accent": "#abcdef"},
)
HOST_LIGHT = Theme(
    name="host-light",
    primary="#654321",
    dark=False,
    variables={"host-accent": "#abcdef"},
)
HOST_DEFAULT_BORDER = "#fedcba"
HOST_MODAL_BG = "#010203"


class _HostApp(App):
    """Foreign app: own theme, own variables, no friTap variables."""

    CSS = """
    #host-label { color: $host-accent; border: solid $host-border; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.register_theme(HOST_DARK)
        self.register_theme(HOST_LIGHT)
        self.theme = "host-dark"

    def get_theme_variable_defaults(self) -> dict[str, str]:
        return {"host-border": HOST_DEFAULT_BORDER}

    def compose(self):
        yield Static("host", id="host-label")


class _HostOverridingFritapApp(_HostApp):
    """Host that deliberately defines one friTap variable itself."""

    def get_theme_variable_defaults(self) -> dict[str, str]:
        return {"host-border": HOST_DEFAULT_BORDER, "fritap-bg-modal": HOST_MODAL_BG}


@pytest.fixture(autouse=True)
def _restore_inline_palette(monkeypatch):
    """install_theme syncs the process-global c() palette; undo it per test."""
    monkeypatch.setattr(themes, "_current", dict(themes._current))


def _run(coro_factory) -> None:
    asyncio.run(coro_factory())


async def _push_alert(app: App, pilot) -> AlertModal:
    modal = AlertModal("hello", severity="info")
    app.push_screen(modal)
    await pilot.pause()
    assert app.screen is modal
    return modal


def test_theme_variable_defaults_match_registered_themes():
    assert themes.theme_variable_defaults(True) == dict(themes.FRITAP_DARK.variables)
    assert themes.theme_variable_defaults(False) == dict(themes.FRITAP_LIGHT.variables)
    copy = themes.theme_variable_defaults(True)
    copy["fritap-info"] = "#000000"
    assert themes.FRITAP_DARK.variables["fritap-info"] != "#000000"


def test_alert_modal_fails_in_foreign_app_without_install():
    """Pins the bug: $fritap-* is unresolved in a foreign app."""

    async def scenario() -> None:
        app = _HostApp()
        async with app.run_test() as pilot:
            app.push_screen(AlertModal("hello"))
            await pilot.pause()

    with pytest.raises(UnresolvedVariableError, match=r"\$fritap-"):
        _run(scenario)


def test_alert_modal_renders_after_install_and_c_follows_host():
    async def scenario() -> None:
        app = _HostApp()
        install_theme(app)
        async with app.run_test() as pilot:
            modal = await _push_alert(app, pilot)
            container = modal.query_one("#modal-container")
            dark_bg = themes.FRITAP_DARK.variables["fritap-bg-modal"]
            assert container.styles.background.hex.lower() == dark_bg
            assert themes.c("primary").lower() == HOST_DARK.primary.lower()
            assert themes.c("bg-modal") == dark_bg

    _run(scenario)


def test_install_after_mount_works():
    async def scenario() -> None:
        app = _HostApp()
        async with app.run_test() as pilot:
            install_theme(app)
            await _push_alert(app, pilot)

    _run(scenario)


def test_theme_switch_dark_to_light_keeps_modal_and_c_in_sync():
    async def scenario() -> None:
        app = _HostApp()
        install_theme(app)
        async with app.run_test() as pilot:
            modal = await _push_alert(app, pilot)
            app.theme = "host-light"
            await pilot.pause()
            assert app.screen is modal
            light = themes.FRITAP_LIGHT.variables
            container = modal.query_one("#modal-container")
            assert container.styles.background.hex.lower() == light["fritap-bg-modal"]
            assert app.get_css_variables()["fritap-info"] == light["fritap-info"]
            assert themes.c("info") == light["fritap-info"]
            # c() follows the resolved CSS colour system (Textual may nudge
            # the raw theme colour slightly in light mode).
            assert themes.c("primary") == app.get_css_variables()["primary"]
            assert themes.c("primary").lower() != HOST_DARK.primary.lower()
            modal.dismiss(None)
            await pilot.pause()
            await _push_alert(app, pilot)

    _run(scenario)


def test_install_twice_is_harmless():
    app = _HostApp()
    install_theme(app)
    defaults_wrapper = app.get_theme_variable_defaults
    css_wrapper = app.get_css_variables
    install_theme(app)
    assert app.get_theme_variable_defaults is defaults_wrapper
    assert app.get_css_variables is css_wrapper

    async def scenario() -> None:
        async with app.run_test() as pilot:
            await _push_alert(app, pilot)

    _run(scenario)


def test_host_variables_unchanged():
    before = _HostApp().get_css_variables()
    app = _HostApp()
    install_theme(app)
    after = app.get_css_variables()
    assert {k: v for k, v in after.items() if not k.startswith("fritap-")} == before
    assert after["host-accent"] == "#abcdef"
    assert after["host-border"] == HOST_DEFAULT_BORDER
    assert set(themes.theme_variable_defaults(True)) <= set(after)


def test_host_definition_wins_on_collision():
    async def scenario() -> None:
        app = _HostOverridingFritapApp()
        install_theme(app)
        assert app.get_css_variables()["fritap-bg-modal"] == HOST_MODAL_BG
        async with app.run_test() as pilot:
            modal = await _push_alert(app, pilot)
            container = modal.query_one("#modal-container")
            assert container.styles.background.hex.lower() == HOST_MODAL_BG

    _run(scenario)


def test_sync_skips_set_theme_when_unchanged_and_resyncs_on_switch(monkeypatch):
    from friTap.tui import theme_install

    monkeypatch.setattr(theme_install, "_last_sync", None)
    calls = []
    real = themes.set_theme
    monkeypatch.setattr(
        themes, "set_theme", lambda t: (calls.append(t), real(t))[1],
    )
    app = _HostApp()
    install_theme(app)
    app.get_css_variables()
    baseline = len(calls)
    assert baseline >= 1
    app.get_css_variables()
    app.get_css_variables()
    assert len(calls) == baseline

    app.theme = "host-light"
    app.get_css_variables()
    assert len(calls) == baseline + 1
    app.get_css_variables()
    assert len(calls) == baseline + 1

    # Another party replacing the global palette forces a re-sync.
    real(themes.FRITAP_DARK)
    app.get_css_variables()
    assert len(calls) == baseline + 2
    assert themes.c("primary") == app.get_css_variables()["primary"]

    # A second host app with different values re-syncs too.
    other = _HostApp()
    install_theme(other)
    other.theme = "host-dark"
    app.theme = "host-light"
    other.get_css_variables()
    n = len(calls)
    app.get_css_variables()
    assert len(calls) == n + 1
