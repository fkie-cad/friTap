"""§F leak guard (scripts/check_public_denylist.sh): STRUCTURAL 3 import rule.

The guard derives module names from private.txt and flags a public file that
imports a stripped private path. These tests pin both entry kinds:
  - a FILE entry (friTap/x/y.py) flags any import of friTap.x.y;
  - a DIRECTORY entry (friTap/x/pkg/) flags only a module-level (unindented)
    import of friTap.x.pkg or a submodule — function-level / guarded imports
    are the sanctioned graceful-degradation pattern and must keep passing.
They also pin the denylist NOTE wording for a caller-supplied (scrubbed) tree.

Runs the real script against a synthetic, name-free repo (copied scripts + a
fake private.txt), so it never depends on the real private.txt contents.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCRIPTS = os.path.join(_REPO_ROOT, "scripts")
_GUARD_FILES = ("check_public_denylist.sh", "lib.sh", "denylist_tokens.py", "denylist.hashes")

pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win") or shutil.which("bash") is None,
    reason="leak guard is a bash script",
)

_PRIVATE_TXT = """\
# comment line
friTap/secretpkg/              # a stripped private package (directory entry)
friTap/hidden_mod.py           # a stripped private module (file entry)
tests/unit/test_hidden_*.py
"""


def _write(path, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _run_guard(tmp_path, public_files: dict, token_scan_rc: int | None = None) -> str:
    """Build a fake repo root + public tree, run the guard on the tree, return stdout.

    token_scan_rc replaces the denylist scanner with a stub exiting that code
    (2 = residuals found), so the NOTE branch is reachable without real tokens.
    """
    fake_repo = tmp_path / "repo"
    for name in _GUARD_FILES:
        dst = fake_repo / "scripts" / name
        os.makedirs(dst.parent, exist_ok=True)
        shutil.copy(os.path.join(_SCRIPTS, name), dst)
    if token_scan_rc is not None:
        _write(fake_repo / "scripts" / "denylist_tokens.py", f"import sys\nsys.exit({token_scan_rc})\n")
    _write(fake_repo / "private.txt", _PRIVATE_TXT)
    tree = tmp_path / "tree"
    for rel, text in public_files.items():
        _write(tree / rel, text)
    proc = subprocess.run(
        ["bash", str(fake_repo / "scripts" / "check_public_denylist.sh"), str(tree)],
        capture_output=True, text=True, timeout=120,
    )
    return proc.stdout


def _structural3_failed(out: str) -> bool:
    return "FAIL  structural: a public module imports a stripped private path" in out


def test_module_level_import_of_private_package_is_flagged(tmp_path):
    out = _run_guard(tmp_path, {"friTap/public.py": "import friTap.secretpkg.core as c\n"})
    assert _structural3_failed(out)
    assert "stripped private package: friTap.secretpkg" in out


def test_module_level_from_import_of_private_subpackage_is_flagged(tmp_path):
    out = _run_guard(tmp_path, {"tests/unit/test_x.py": "from friTap.secretpkg.records import R\n"})
    assert _structural3_failed(out)


def test_guarded_function_level_import_of_private_package_passes(tmp_path):
    src = (
        "def f():\n"
        "    try:\n"
        "        from friTap.secretpkg import thing\n"
        "    except ImportError:\n"
        "        return None\n"
    )
    out = _run_guard(tmp_path, {"friTap/public.py": src})
    assert "PASS  structural: no public import of a stripped private module" in out


def test_similarly_named_public_package_is_not_flagged(tmp_path):
    out = _run_guard(tmp_path, {"friTap/public.py": "import friTap.secretpkg_public\n"})
    assert not _structural3_failed(out)


def test_file_entry_import_still_flagged_at_any_indent(tmp_path):
    out = _run_guard(tmp_path, {"friTap/public.py": "def f():\n    from friTap.hidden_mod import X\n"})
    assert _structural3_failed(out)
    assert "stripped private module: friTap.hidden_mod" in out


def test_supplied_tree_note_says_residuals_will_be_published(tmp_path):
    out = _run_guard(tmp_path, {"friTap/public.py": "x = 1\n"}, token_scan_rc=2)
    assert "accepted reveal-token residuals present in the scrubbed tree (these WILL be published)" in out
    assert "cleared by the §E scrubber" not in out.split("NOTE  denylist", 1)[1].splitlines()[0]
