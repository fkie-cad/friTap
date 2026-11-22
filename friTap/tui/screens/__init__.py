#!/usr/bin/env python3
"""TUI screen modules.

Lazy (PEP 562): ``from friTap.tui.screens import MainScreen`` still works,
and importing a sibling such as ``friTap.tui.screens.tap_viewer`` does not
load ``main_screen`` (and with it the capture controller and wizard).
"""


def __getattr__(name: str):
    if name == "MainScreen":
        from .main_screen import MainScreen
        return MainScreen
    if name == "SCREENS_AVAILABLE":
        try:
            from .main_screen import MainScreen  # noqa: F401
        except ImportError:
            return False
        return True
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
