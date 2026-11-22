"""AST guard: the TUI viewer mixins stay free of live-capture code.

The mixins in ``friTap/tui/screens/viewer_mixins/`` are shared by the
live-capture ``MainScreen`` and the replay-only viewer screen, so they must
not touch capture state (``_capture``, ``_wizard``, ``_get_state``,
``app_state``) nor import capture code (frida, the capture controller, the
wizard) or ``main_screen`` itself.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MIXIN_DIR = REPO_ROOT / "friTap" / "tui" / "screens" / "viewer_mixins"
MIXIN_PACKAGE = "friTap.tui.screens.viewer_mixins"

FORBIDDEN_NAMES = {"_capture", "_wizard", "_get_state", "app_state"}
FORBIDDEN_MODULES = (
    "frida",
    "friTap.tui.capture_controller",
    "friTap.tui.wizard",
    "friTap.tui.screens.main_screen",
)


def _mixin_modules() -> list[Path]:
    return sorted(MIXIN_DIR.glob("*.py"))


def _module_name(path: Path) -> str:
    if path.name == "__init__.py":
        return MIXIN_PACKAGE
    return f"{MIXIN_PACKAGE}.{path.stem}"


def resolve_import(node: ast.ImportFrom, module_name: str, is_package: bool) -> str:
    """Absolute module named by a (possibly relative) ``from ... import``."""
    if node.level == 0:
        return node.module or ""
    package_parts = module_name.split(".")
    if not is_package:
        package_parts = package_parts[:-1]
    base = package_parts[: len(package_parts) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


def imported_modules(tree: ast.AST, module_name: str, is_package: bool) -> list[str]:
    """Every module an AST imports, relative imports resolved (incl. ``from X import y`` as ``X.y``)."""
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = resolve_import(node, module_name, is_package)
            modules.append(base)
            modules.extend(f"{base}.{alias.name}" for alias in node.names)
    return modules


def forbidden_identifiers(tree: ast.AST) -> list[tuple[int, str]]:
    """``(line, name)`` for every forbidden attribute access / name / def."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.arg)):
            name = getattr(node, "name", None) or getattr(node, "arg", None)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value  # getattr(self, "_capture") style access
        if name in FORBIDDEN_NAMES:
            hits.append((getattr(node, "lineno", 0), name))
    return hits


def _is_forbidden_module(module: str) -> bool:
    return any(module == bad or module.startswith(bad + ".") for bad in FORBIDDEN_MODULES)


def test_mixin_package_has_modules():
    assert (MIXIN_DIR / "__init__.py").is_file()
    assert len(_mixin_modules()) >= 2


@pytest.mark.parametrize("path", _mixin_modules(), ids=lambda p: p.name)
def test_mixin_touches_no_capture_state(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert forbidden_identifiers(tree) == []


@pytest.mark.parametrize("path", _mixin_modules(), ids=lambda p: p.name)
def test_mixin_imports_no_capture_code(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = imported_modules(tree, _module_name(path), path.name == "__init__.py")
    assert [m for m in modules if _is_forbidden_module(m)] == []


@pytest.mark.parametrize("path", _mixin_modules(), ids=lambda p: p.name)
def test_mixin_defines_no_textual_screen_config(path: Path):
    """Plain mixins: no BINDINGS / CSS / compose (those belong to the screen)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        members = {
            target.id
            for stmt in cls.body if isinstance(stmt, ast.Assign)
            for target in stmt.targets if isinstance(target, ast.Name)
        } | {stmt.name for stmt in cls.body if isinstance(stmt, ast.FunctionDef)}
        assert not members & {"BINDINGS", "CSS", "DEFAULT_CSS", "compose"}, cls.name


def test_guard_detects_relative_capture_import():
    """The resolver itself: a relative wizard/main_screen import is caught."""
    tree = ast.parse(
        "from ...wizard import CaptureWizard\n"
        "from ..main_screen import MainScreen\n"
        "from ... import capture_controller\n"
    )
    modules = imported_modules(tree, f"{MIXIN_PACKAGE}.decrypt", False)
    assert "friTap.tui.wizard" in modules
    assert "friTap.tui.screens.main_screen" in modules
    assert "friTap.tui.capture_controller" in modules
    assert forbidden_identifiers(ast.parse("self._capture.stop()")) == [(1, "_capture")]


def test_importing_mixins_does_not_load_frida():
    code = (
        "import sys\n"
        f"import {MIXIN_PACKAGE}\n"
        "print('frida' in sys.modules)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().splitlines()[-1] == "False"


def test_main_screen_inherits_decrypt_mixin():
    pytest.importorskip("textual")
    from friTap.tui.screens.main_screen import MainScreen
    from friTap.tui.screens.viewer_mixins import DecryptMixin

    assert issubclass(MainScreen, DecryptMixin)
    assert MainScreen.__mro__.index(DecryptMixin) < [
        c.__name__ for c in MainScreen.__mro__
    ].index("Screen")
    assert MainScreen.action_open_pcap is DecryptMixin.action_open_pcap
