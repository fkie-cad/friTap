"""The Claude Code plugin + marketplace manifests at the repo root stay valid and in sync."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from friTap.about import __version__

REPO = Path(__file__).resolve().parents[2]
PLUGIN_DIR = REPO / ".claude-plugin"


def _load(name: str) -> dict:
    return json.loads((PLUGIN_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def plugin() -> dict:
    return _load("plugin.json")


@pytest.fixture(scope="module")
def marketplace() -> dict:
    return _load("marketplace.json")


def test_plugin_version_matches_package(plugin):
    assert plugin["version"] == __version__


def test_skills_path_points_at_packaged_skills(plugin):
    skills = plugin["skills"]
    assert skills.startswith("./")
    skills_dir = (REPO / skills).resolve()
    assert skills_dir == (REPO / "friTap" / "skills").resolve()
    assert any(skills_dir.glob("*/SKILL.md"))


def test_mcp_server_runs_fritap_mcp_without_capture(plugin):
    server = plugin["mcpServers"]["fritap"]
    assert server["command"] == "fritap" and server["args"][0] == "mcp"
    assert not any(arg.startswith("--allow-") for arg in server["args"])


def test_marketplace_lists_the_plugin_at_repo_root(marketplace, plugin):
    assert marketplace["name"] == "fritap"
    assert marketplace["owner"]["name"]
    entry = next(p for p in marketplace["plugins"] if p["name"] == plugin["name"])
    assert entry["source"] == "./"
    assert "version" not in entry  # plugin.json's version is the single source of truth
