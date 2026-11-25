"""scripts/sync_plugin_version.py: keep plugin.json's version equal to about.py's.

publish_public.sh runs it after ``--no-release`` freezes about.py, so a published
snapshot never ships a red test_claude_plugin.py. These tests pin: mismatch
rewritten (formatting otherwise untouched), already-in-sync no-op, missing
plugin.json skipped, unparsable about.py / missing version rejected, CLI exit codes.
"""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCRIPT_PATH = os.path.join(_REPO_ROOT, "scripts", "sync_plugin_version.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("sync_plugin_version", _SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sync = _load_module()

PLUGIN_TEXT = (
    '{\n  "name": "fritap",\n  "version": "1.0.0",\n'
    '  "keywords": ["frida", "tls"],\n  "mcpServers": {"x": {"version": "1.0.0"}}\n}\n'
)


def _make_tree(tmp_path, about_version: str = "2.0.0", plugin_text: str | None = PLUGIN_TEXT) -> str:
    (tmp_path / "friTap").mkdir()
    (tmp_path / "friTap" / "about.py").write_text(
        f'__author__ = "x"\n__version__ = "{about_version}"\ndebug = False\n', encoding="utf-8")
    if plugin_text is not None:
        (tmp_path / ".claude-plugin").mkdir()
        (tmp_path / ".claude-plugin" / "plugin.json").write_text(plugin_text, encoding="utf-8")
    return str(tmp_path)


def _plugin_text(tree: str) -> str:
    with open(os.path.join(tree, ".claude-plugin", "plugin.json"), encoding="utf-8") as fh:
        return fh.read()


def test_reads_version_without_importing(tmp_path):
    assert sync.read_package_version(_make_tree(tmp_path, "3.1.4")) == "3.1.4"


def test_mismatch_rewrites_only_the_top_level_version(tmp_path):
    tree = _make_tree(tmp_path, "2.0.0")
    status = sync.sync_plugin_version(tree)
    assert "1.0.0 -> 2.0.0" in status
    text = _plugin_text(tree)
    assert text == PLUGIN_TEXT.replace('"version": "1.0.0",', '"version": "2.0.0",', 1)
    assert json.loads(text)["mcpServers"]["x"]["version"] == "1.0.0"


def test_already_in_sync_is_a_noop(tmp_path):
    tree = _make_tree(tmp_path, "1.0.0")
    assert "already at 1.0.0" in sync.sync_plugin_version(tree)
    assert _plugin_text(tree) == PLUGIN_TEXT


def test_missing_plugin_json_is_skipped(tmp_path):
    tree = _make_tree(tmp_path, plugin_text=None)
    assert "skipped" in sync.sync_plugin_version(tree)


def test_about_py_without_version_is_rejected(tmp_path):
    tree = _make_tree(tmp_path)
    (tmp_path / "friTap" / "about.py").write_text("debug = False\n", encoding="utf-8")
    with pytest.raises(sync.VersionSyncError):
        sync.sync_plugin_version(tree)


def test_plugin_json_without_version_is_rejected(tmp_path):
    tree = _make_tree(tmp_path, plugin_text='{"name": "fritap"}\n')
    with pytest.raises(sync.VersionSyncError):
        sync.sync_plugin_version(tree)


def test_failed_rewrite_leaves_plugin_json_untouched(tmp_path):
    """A nested "version" with the same value ahead of the top-level one cannot be
    rewritten safely: the error must leave the file exactly as it was."""
    nested_first = '{\n  "meta": {"version": "1.0.0"},\n  "version": "1.0.0"\n}\n'
    tree = _make_tree(tmp_path, "2.0.0", plugin_text=nested_first)
    with pytest.raises(sync.VersionSyncError):
        sync.sync_plugin_version(tree)
    assert _plugin_text(tree) == nested_first


def test_cli_exit_codes(tmp_path, capsys):
    tree = _make_tree(tmp_path, "2.0.0")
    assert sync.main(["sync_plugin_version.py", tree]) == 0
    assert json.loads(_plugin_text(tree))["version"] == "2.0.0"
    (tmp_path / "friTap" / "about.py").write_text("", encoding="utf-8")
    assert sync.main(["sync_plugin_version.py", tree]) == 1
    assert "ERROR" in capsys.readouterr().err


def test_repo_plugin_json_is_in_sync():
    """The real repo: the same invariant test_claude_plugin.py checks, via this helper."""
    plugin_path = os.path.join(_REPO_ROOT, ".claude-plugin", "plugin.json")
    with open(plugin_path, encoding="utf-8") as fh:
        assert json.load(fh)["version"] == sync.read_package_version(_REPO_ROOT)
