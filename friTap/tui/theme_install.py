#!/usr/bin/env python3

"""Make friTap widgets usable inside a foreign Textual app.

friTap widgets reference ``$fritap-*`` CSS variables that only ``FriTapApp``'s
themes define, so elsewhere Textual raises ``UnresolvedVariableError`` on mount.
:func:`install_theme` teaches a host app *instance* those variables without
touching its themes, CSS or class.

Hooks (verified on Textual 8.2.8, APIs since 0.86):

* ``App.get_theme_variable_defaults()`` (the documented fallback) is wrapped on the
  instance to add the friTap defaults for the current dark/light mode.
* ``App.get_css_variables()``, re-queried by ``refresh_css()`` on every theme change,
  is wrapped to re-sync the inline ``c()`` palette from the values the CSS sees before
  ``theme_changed_signal`` fires. No signal subscription, so installing before ``app.run()`` works.

The host wins: friTap only fills variables the host does not define, so a host can
restyle friTap widgets by defining e.g. ``fritap-bg-modal``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from friTap.tui import themes

_INSTALLED_MARKER = "_fritap_theme_installed"
_FRITAP_PREFIX = "fritap-"
_PALETTE_ROLES = (
    "primary", "secondary", "warning", "error", "success",
    "accent", "foreground", "background", "surface", "panel",
)


def install_theme(app: Any) -> None:
    """Install friTap's CSS variables and inline palette into *app*.

    Idempotent: a second call on the same instance is a no-op.
    """
    if getattr(app, _INSTALLED_MARKER, False):
        return
    _wrap_theme_variable_defaults(app)
    _wrap_css_variables(app)
    setattr(app, _INSTALLED_MARKER, True)
    app.stylesheet.set_variables(app.get_css_variables())


def _wrap_theme_variable_defaults(app: Any) -> None:
    host_defaults = app.get_theme_variable_defaults

    def get_theme_variable_defaults() -> dict[str, str]:
        fritap_defaults = themes.theme_variable_defaults(app.current_theme.dark)
        return {**fritap_defaults, **host_defaults()}

    app.get_theme_variable_defaults = get_theme_variable_defaults


def _wrap_css_variables(app: Any) -> None:
    host_css_variables = app.get_css_variables

    def get_css_variables() -> dict[str, str]:
        variables = host_css_variables()
        _sync_inline_palette(app, variables)
        return variables

    app.get_css_variables = get_css_variables


# Last pushed into ``themes``: (key, resulting ``themes._current`` dict). ``c()`` is process-global,
# so the cache is too: another host (different values) changes the key, ``themes.set_theme`` swaps ``_current``.
_last_sync: tuple[tuple, dict[str, str]] | None = None


def _sync_inline_palette(app: Any, variables: dict[str, str]) -> None:
    """Point ``themes.c()`` at the host theme's resolved colours; skipped when the palette came from identical values."""
    global _last_sync
    theme = app.current_theme
    roles = {
        role: variables.get(role, getattr(theme, role, None))
        for role in _PALETTE_ROLES
    }
    fritap_variables = {
        name: value for name, value in variables.items()
        if name.startswith(_FRITAP_PREFIX)
    }
    key = (
        tuple(roles.values()),
        tuple(sorted(fritap_variables.items())),
    )
    if _last_sync is not None and _last_sync[0] == key and _last_sync[1] is themes._current:
        return
    resolved = {role: value for role, value in roles.items() if role in variables}
    palette_theme = dataclasses.replace(theme, **resolved, variables=fritap_variables)
    themes.set_theme(palette_theme)
    _last_sync = (key, themes._current)
