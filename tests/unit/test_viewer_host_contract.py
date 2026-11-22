"""Host contract of the TUI viewer mixins (task 2.2 / 4.1).

The mixins in ``friTap/tui/screens/viewer_mixins/`` are plain Python: every
``self.<name>`` they read or call that no mixin defines (incl. the replay-only
defaults of ``ViewerHostDefaults``) and that is not part of Textual's
``Screen`` API must be provided by the HOST screen. Both hosts, ``MainScreen``
and the replay-only ``TapViewerScreen`` (task 4.1), must provide ALL of these:

* ``HOST_CONTRACT_METHODS`` — host hooks / helpers (override points), and
* ``HOST_CONTRACT_STATE`` — instance attributes the host initialises in
  ``__init__`` (``MainScreen.__init__`` today).

The set is pinned explicitly, so growing the contract is a conscious decision:
when a mixin starts using a new host name, add it here AND make sure the
replay-only viewer provides it. Names read via ``getattr(self, "x", default)``
are mixin-owned lazy state and are deliberately not part of the contract.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.screen import Screen  # noqa: E402

from friTap.tui.screens.main_screen import MainScreen  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
MIXIN_DIR = REPO_ROOT / "friTap" / "tui" / "screens" / "viewer_mixins"
MAIN_SCREEN = REPO_ROOT / "friTap" / "tui" / "screens" / "main_screen.py"

HOST_CONTRACT_METHODS = {
    "_flow_title_hints",
    "_get_activity_log",
    "_request_close",
    "_update_capture_indicator",
    "reload_replay",
}

# Host hooks with a replay-only default in ViewerHostDefaults. MainScreen
# overrides all but ``_alert`` with its capture-aware variant.
DEFAULTED_HOST_METHODS = {
    "_alert",
    "_analyzer_flow_ids_and_getter",
    "_divert_analyzer_key",
    "_escape_running_capture",
    "_has_flows",
    "_hide_host_panels",
    "_is_capturing",
    "_live_flow_collector",
    "_no_flows_to_save_message",
    "_start_live_tap_recording",
}
MAIN_SCREEN_OVERRIDES = DEFAULTED_HOST_METHODS - {"_alert"}

HOST_CONTRACT_STATE = {
    "_analyzer_run_id",
    "_detail_origin",
    "_findings_cache",
    "_replay_ctrl",
    "_replay_file",
}

HOST_CONTRACT = HOST_CONTRACT_METHODS | HOST_CONTRACT_STATE


def _mixin_trees() -> list[ast.AST]:
    return [ast.parse(p.read_text(encoding="utf-8")) for p in sorted(MIXIN_DIR.glob("*.py"))]


def _names_defined_in_mixin_classes(trees) -> set[str]:
    """Methods, properties and class attributes defined on any mixin class."""
    defined: set[str] = set()
    for tree in trees:
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            for node in cls.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defined.add(node.name)
                elif isinstance(node, ast.Assign):
                    defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    defined.add(node.target.id)
    return defined


def _self_attributes_read(trees) -> set[str]:
    """Every ``self.<name>`` that is read or called (``Load`` context)."""
    return {
        node.attr
        for tree in trees
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and isinstance(node.ctx, ast.Load)
    }


def computed_host_contract() -> set[str]:
    trees = _mixin_trees()
    candidates = _self_attributes_read(trees) - _names_defined_in_mixin_classes(trees)
    return {name for name in candidates if not hasattr(Screen, name)}


def _main_screen_init_state() -> set[str]:
    """``self.<name>`` attributes assigned in ``MainScreen.__init__``."""
    tree = ast.parse(MAIN_SCREEN.read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "MainScreen")
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    return {
        node.attr
        for node in ast.walk(init)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and isinstance(node.ctx, ast.Store)
    }


def test_host_contract_is_pinned():
    computed = computed_host_contract()
    assert computed == HOST_CONTRACT, (
        f"new host names (add to HOST_CONTRACT_* and to the replay-only viewer): "
        f"{sorted(computed - HOST_CONTRACT)}; no longer used: {sorted(HOST_CONTRACT - computed)}"
    )


def test_methods_and_state_are_disjoint():
    assert not HOST_CONTRACT_METHODS & HOST_CONTRACT_STATE


@pytest.mark.parametrize("name", sorted(HOST_CONTRACT_METHODS))
def test_main_screen_provides_host_method(name):
    assert callable(getattr(MainScreen, name, None)), f"MainScreen lacks host method {name}"


@pytest.mark.parametrize("name", sorted(HOST_CONTRACT_STATE))
def test_main_screen_initialises_host_state(name):
    assert name in _main_screen_init_state(), f"MainScreen.__init__ does not set {name}"
    assert not hasattr(MainScreen, name), f"{name} should be instance state, not a class attribute"


# ---------------------------------------------------------------------------
# Replay-only viewer (task 4.1): TapViewerScreen must satisfy the same contract.
# ---------------------------------------------------------------------------

TAP_VIEWER = REPO_ROOT / "friTap" / "tui" / "screens" / "tap_viewer.py"


def _class_init_state(path: Path, class_name: str) -> set[str]:
    """``self.<name>`` attributes assigned in ``<class_name>.__init__``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == class_name)
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    return {
        node.attr
        for node in ast.walk(init)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and isinstance(node.ctx, ast.Store)
    }


def test_class_init_state_helper_matches_main_screen():
    assert _class_init_state(MAIN_SCREEN, "MainScreen") == _main_screen_init_state()


@pytest.mark.parametrize("name", sorted(HOST_CONTRACT_METHODS))
def test_tap_viewer_provides_host_method(name):
    from friTap.tui.screens.tap_viewer import TapViewerScreen

    assert callable(getattr(TapViewerScreen, name, None)), f"TapViewerScreen lacks host method {name}"


@pytest.mark.parametrize("name", sorted(HOST_CONTRACT_STATE))
def test_tap_viewer_initialises_host_state(name):
    from friTap.tui.screens.tap_viewer import TapViewerScreen

    assert name in _class_init_state(TAP_VIEWER, "TapViewerScreen"), (
        f"TapViewerScreen.__init__ does not set {name}"
    )
    assert not hasattr(TapViewerScreen, name), f"{name} should be instance state"


@pytest.mark.parametrize("name", sorted(HOST_CONTRACT_METHODS))
def test_tap_viewer_overrides_every_host_method(name):
    """Every non-defaulted host hook is the viewer's own variant, not inherited."""
    from friTap.tui.screens.tap_viewer import TapViewerScreen

    assert name in vars(TapViewerScreen), f"TapViewerScreen inherits {name} instead of defining it"


# ---------------------------------------------------------------------------
# ViewerHostDefaults: replay-only defaults, overridden by the capture host.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(DEFAULTED_HOST_METHODS))
def test_defaulted_hook_is_defined_on_viewer_host_defaults(name):
    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults

    assert callable(vars(ViewerHostDefaults).get(name)), f"ViewerHostDefaults lacks {name}"
    assert name not in HOST_CONTRACT_METHODS


@pytest.mark.parametrize("name", sorted(DEFAULTED_HOST_METHODS))
def test_tap_viewer_uses_the_default(name):
    from friTap.tui.screens.tap_viewer import TapViewerScreen
    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults

    assert getattr(TapViewerScreen, name) is getattr(ViewerHostDefaults, name)


@pytest.mark.parametrize("name", sorted(MAIN_SCREEN_OVERRIDES))
def test_main_screen_overrides_capture_aware_hook(name):
    assert name in vars(MainScreen), f"MainScreen falls back to the replay-only default {name}"


@pytest.mark.parametrize("class_path", ["main_screen.MainScreen", "tap_viewer.TapViewerScreen"])
def test_viewer_host_defaults_is_last_mixin_before_screen(class_path):
    import importlib

    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults

    module_name, class_name = class_path.split(".")
    cls = getattr(importlib.import_module(f"friTap.tui.screens.{module_name}"), class_name)
    assert cls.__bases__[-2:] == (ViewerHostDefaults, Screen)
