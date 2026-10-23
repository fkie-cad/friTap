"""Publish scrubber: package.json ``scripts`` path-token pass.

scrub_public_tree.py operates on a THROWAWAY public tree from which private
paths were already stripped. scrub_package_json drops ``agent/**.ts|js`` tokens
from ``scripts`` values whose files no longer exist, so ``npm run`` / CI does not
fail on a dangling path. These tests pin: missing ref dropped, existing ref kept,
unrelated scripts untouched, idempotency, and skip when package.json is absent.
"""
from __future__ import annotations

import importlib.util
import json
import os

# Load the standalone script as a module (it lives under scripts/, not a pkg).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCRIPT_PATH = os.path.join(_REPO_ROOT, "scripts", "scrub_public_tree.py")


def _load_scrub_module():
    spec = importlib.util.spec_from_file_location("scrub_public_tree", _SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


scrub = _load_scrub_module()

KEPT = "agent/public/a.test.ts"
MISSING = "agent/private/x.test.ts"


def _make_tree(tmp_path, scripts: dict) -> str:
    (tmp_path / "agent" / "public").mkdir(parents=True)
    (tmp_path / KEPT).write_text("// test\n", encoding="utf-8")
    pkg = {"name": "demo", "version": "1.0.0", "scripts": scripts, "devDependencies": {"tsx": "^4"}}
    (tmp_path / "package.json").write_text(
        json.dumps(pkg, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    return str(tmp_path)


def _scripts(tmp_path) -> dict:
    return json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))["scripts"]


def test_missing_ref_dropped_existing_kept(tmp_path):
    tree = _make_tree(tmp_path, {"test:agent": f"node --test {KEPT} {MISSING}"})
    report = scrub.scrub_package_json(tree)
    assert "dropped 1" in report
    assert _scripts(tmp_path)["test:agent"] == f"node --test {KEPT}"


def test_unrelated_scripts_and_keys_untouched(tmp_path):
    scripts = {
        "build": "frida-compile agent/main.ts -o out.js",  # exists -> kept
        "lint": "eslint  --ext .ts .",
        "test:agent": f"node --test {MISSING}",
    }
    tree = _make_tree(tmp_path, scripts)
    (tmp_path / "agent" / "main.ts").write_text("", encoding="utf-8")
    scrub.scrub_package_json(tree)
    data = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    assert list(data) == ["name", "version", "scripts", "devDependencies"]
    assert list(data["scripts"]) == ["build", "lint", "test:agent"]
    assert data["scripts"]["build"] == scripts["build"]
    assert data["scripts"]["lint"] == scripts["lint"]  # untouched, whitespace kept
    assert data["scripts"]["test:agent"] == "node --test"


def test_preserves_indent_and_trailing_newline(tmp_path):
    tree = _make_tree(tmp_path, {"t": f"node {MISSING}"})
    scrub.scrub_package_json(tree)
    text = (tmp_path / "package.json").read_text(encoding="utf-8")
    assert text.endswith("}\n")
    assert '\n    "name": "demo",' in text


def test_idempotent(tmp_path):
    tree = _make_tree(tmp_path, {"t": f"node {KEPT} {MISSING}"})
    scrub.scrub_package_json(tree)
    first = (tmp_path / "package.json").read_bytes()
    report = scrub.scrub_package_json(tree)
    assert "already clean" in report
    assert (tmp_path / "package.json").read_bytes() == first


def test_clean_file_not_rewritten(tmp_path):
    tree = _make_tree(tmp_path, {"t": f"node {KEPT}"})
    before = (tmp_path / "package.json").read_bytes()
    assert "already clean" in scrub.scrub_package_json(tree)
    assert (tmp_path / "package.json").read_bytes() == before


def test_absent_file_skips(tmp_path):
    assert scrub.scrub_package_json(str(tmp_path)) == "package.json: absent (skip)"
