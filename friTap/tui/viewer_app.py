#!/usr/bin/env python3

"""
Mode A of the embeddable viewer: a host project launches friTap's ``.tap``
viewer from its own CLI via :func:`open_tap`.

Unlike ``run_tui`` this never touches the root logger, never persists
preferences and never calls ``sys.exit``.  It imports no capture code.
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Iterator, Optional

try:
    from textual.app import App
    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatch
    App = object  # type: ignore[assignment,misc]
    TEXTUAL_AVAILABLE = False

_TEXTUAL_HINT = (
    "The friTap .tap viewer requires the 'textual' package. "
    "Install it with: pip install fritap[tui]  or  pip install textual>=0.86.0"
)
_DEFAULT_THEME = "fritap-dark"


def friTap_logger_names() -> list[str]:
    """Return the names of all currently known friTap loggers (never root)."""
    known = logging.root.manager.loggerDict
    names = {n for n in known if n == "friTap" or n.startswith("friTap.")}
    names.update(("friTap", "friTap.no_prefix"))
    return sorted(names)


@contextlib.contextmanager
def muted_fritap_console() -> Iterator[None]:
    """Mute console handlers of friTap loggers only; restore them on exit.

    ``mute_console_handlers`` restores the saved handler levels itself in its
    ``finally`` block, so no extra restore handle is needed.
    """
    from friTap.fritap_utility import mute_console_handlers

    with mute_console_handlers(logger_names=friTap_logger_names()):
        yield


class TapViewerApp(App):
    """Minimal host app showing a single ``TapViewerScreen``; ``q`` exits."""

    def __init__(
        self,
        tap_path: str,
        *,
        title: Optional[str] = None,
        sub_title: Optional[str] = None,
        theme: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._tap_path = tap_path
        self._output_dir = output_dir
        self.title = title or "friTap"
        self.sub_title = sub_title or os.path.basename(tap_path)
        self._register_fritap_themes()
        self.theme = theme or _DEFAULT_THEME

    def _register_fritap_themes(self) -> None:
        """Register friTap's themes and variables so ``$fritap-*`` resolve."""
        from friTap.tui.theme_install import install_theme
        from friTap.tui.themes import register_fritap_themes

        register_fritap_themes(self)
        install_theme(self)

    def on_mount(self) -> None:
        """Push the replay-only viewer."""
        from friTap.tui.screens.tap_viewer import TapViewerScreen

        self.push_screen(TapViewerScreen(self._tap_path, output_dir=self._output_dir))

    def on_tap_viewer_screen_closed(self, message) -> None:
        """The viewer closed: leave mode A cleanly."""
        self.exit()


def open_tap(
    path: str,
    *,
    title: Optional[str] = None,
    sub_title: Optional[str] = None,
    theme: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> None:
    """Open *path* in the interactive viewer and block until it is closed.

    Raises:
        FileNotFoundError: *path* does not exist.
        ImportError: textual is not installed.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such .tap file: {path}")
    if not TEXTUAL_AVAILABLE:
        raise ImportError(_TEXTUAL_HINT)
    app = TapViewerApp(
        path, title=title, sub_title=sub_title, theme=theme, output_dir=output_dir
    )
    with muted_fritap_console():
        app.run()
