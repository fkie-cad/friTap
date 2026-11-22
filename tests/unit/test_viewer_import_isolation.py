"""Import isolation: the embeddable viewer must not drag in capture code.

Each case imports a module in a fresh interpreter and reports which forbidden
modules ended up in ``sys.modules``.

The ``friTap.ui`` facade is covered at the bottom (lazy attribute access).
"""
import functools
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

CAPTURE_MODULES = (
    "frida",
    "friTap.tui.capture_controller",
    "friTap.tui.wizard",
    "friTap.tui.screens.main_screen",
    "friTap.ssl_logger",
    "friTap.friTap",
)
CAPTURE_PREFIXES = ("friTap.legacy",)

_PROBE = """
import importlib, json, sys
importlib.import_module({module!r})
before = set(sys.modules)
for attr in {attrs!r}:
    getattr(sys.modules[{module!r}], attr)
print(json.dumps({{"before": sorted(before), "after": sorted(sys.modules)}}))
"""


@functools.lru_cache(maxsize=None)
def _probe(module, attrs=()):
    """Import *module* (then touch *attrs*) in a fresh interpreter.

    Returns ``(modules_before_attrs, modules_after)``; cached per arguments.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE.format(module=module, attrs=attrs)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    return frozenset(data["before"]), frozenset(data["after"])


def _loaded_modules(module):
    return _probe(module)[1]


def _leaks(loaded):
    found = [m for m in CAPTURE_MODULES if m in loaded]
    found += sorted(
        m for m in loaded
        if any(m == p or m.startswith(p + ".") for p in CAPTURE_PREFIXES)
    )
    return found


ISOLATED_MODULES = [
    "friTap.tui.screens.tap_viewer",
    "friTap.tui.screens.viewer_mixins",
    "friTap.tui.theme_install",
    "friTap.tui.viewer_app",
    "friTap.tui.screens.viewer_css",
    "friTap.ui",
    "friTap.ui.extensions",
    "friTap.extensions",
    "friTap.flow.replay",
    "friTap.flow.replay_rows",
]


@pytest.mark.parametrize("module", ISOLATED_MODULES)
def test_no_capture_modules_loaded(module):
    assert _leaks(_loaded_modules(module)) == []


@pytest.mark.parametrize(
    "module",
    ["friTap.ui.extensions", "friTap.extensions", "friTap.flow.replay",
     "friTap.flow.replay_rows"],
)
def test_textual_not_loaded(module):
    loaded = _loaded_modules(module)
    assert "textual" not in loaded


def test_positive_control_main_screen_loads_capture_controller():
    loaded = _loaded_modules("friTap.tui.screens.main_screen")
    assert "friTap.tui.capture_controller" in loaded


def test_import_ui_loads_neither_textual_nor_frida():
    loaded = _loaded_modules("friTap.ui")
    assert "textual" not in loaded
    assert "frida" not in loaded
    assert _leaks(loaded) == []


TUI_ATTRS = ("TapViewerScreen", "TapViewerApp", "open_tap", "install_theme")
NON_TUI_ATTRS = (
    "register_detail_tab", "load_extensions", "register_analyzer",
    "register_app_cipher_decoder", "ReplayController",
)


def test_ui_tui_attribute_loads_textual_but_no_capture():
    before, after = _probe("friTap.ui", TUI_ATTRS)
    assert "textual" not in before
    assert "textual" in after
    assert _leaks(after) == []


def test_ui_non_tui_attributes_do_not_load_textual():
    _, after = _probe("friTap.ui", NON_TUI_ATTRS)
    assert "textual" not in after
    assert _leaks(after) == []


def test_core_extension_registry_loads_no_ui_package():
    loaded = _loaded_modules("friTap.extensions")
    assert not [m for m in loaded
                if m in ("friTap.ui", "friTap.tui")
                or m.startswith(("friTap.ui.", "friTap.tui."))]
