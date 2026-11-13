"""The eval-suite fixture generator (``evals/fixtures/make_fixtures.py``).

Regenerates the fixture into ``tmp_path`` and checks the agent read tools
report the ground truth documented in ``evals/fixtures/FACTS.md``.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from friTap.agent_api import tools_read
from friTap.agent_api.context import ToolContext
from friTap.agent_api.registry import Registry

SCRIPT = Path(__file__).resolve().parents[2] / "evals" / "fixtures" / "make_fixtures.py"
TRACKER = "track.adnet-metrics.test"


def _load_generator():
    spec = importlib.util.spec_from_file_location("eval_make_fixtures", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def generator():
    return _load_generator()


@pytest.fixture
def fixture_dir(generator, tmp_path):
    generator.generate(tmp_path)
    return tmp_path


@pytest.fixture
def call(fixture_dir):
    registry = Registry()
    tools_read.register_all(registry)
    ctx = ToolContext(root=fixture_dir)
    return lambda tool, params: registry.call(tool, {"tap": "audit.tap", **params}, context=ctx)


def _digest_hosts(digest: dict) -> set[str]:
    return {row["untrusted"]["host"]
            for group in digest["protocols"].values() for row in group["hosts"]}


def _diff_hosts(groups: list[dict]) -> set[str]:
    return {group["untrusted"]["host"] for group in groups}


def test_generator_is_deterministic(generator, tmp_path):
    first = generator.generate(tmp_path / "a").read_bytes()
    second = generator.generate(tmp_path / "b").read_bytes()
    assert first == second


def test_phases_sidecar_has_marker_shape(fixture_dir):
    lines = (fixture_dir / "phases.jsonl").read_text(encoding="utf-8").splitlines()
    markers = [json.loads(line) for line in lines]
    assert [m["label"] for m in markers] == ["before-login", "after-login"]
    assert all({"t", "t_rel", "label", "at"} <= set(m) for m in markers)


def test_digest_lists_tracker_host_and_email_finding(call):
    digest = call("get_digest", {})
    assert TRACKER in _digest_hosts(digest)
    titles = {row["untrusted"]["title"] for row in digest["findings"]["top"]}
    assert "PII: email" in titles


def test_grouped_email_pii_row_lists_every_flow(call):
    out = call("list_findings", {"category": "pii"})
    [row] = out["rows"]
    assert (row["ref"], row["count"], row["refs"]) == ("f2", 2, ["f2", "f3"])
    assert "refs_more" not in row


def test_digest_email_pii_row_lists_tracker_flow(call):
    top = call("get_digest", {})["findings"]["top"]
    [row] = [r for r in top if r["untrusted"]["title"] == "PII: email"]
    assert row["refs"] == ["f2", "f3"]


def test_email_pii_finding_covers_tracker_flow(call):
    out = call("list_findings", {"category": "pii", "filter": f'http.host == "{TRACKER}"'})
    assert [row["untrusted"]["title"] for row in out["rows"]] == ["PII: email"]


def test_find_values_hits_login_and_tracker(call):
    out = call("find_values", {"values": [{"value": "canary.user@example.test",
                                           "kind": "email", "label": "email"}]})
    assert {(row["ref"], row["untrusted"]["host"]) for row in out["rows"]} == {
        ("f2", "api.example-shop.test"), ("f3", TRACKER)}


def test_diff_shows_tracker_only_after_login(call):
    out = call("diff", {"phase_a": "before-login", "phase_b": "after-login"})
    assert TRACKER in _diff_hosts(out["added"])
    assert TRACKER not in _diff_hosts(out["removed"])
    assert out["summary"] == {"endpoints_a": 1, "endpoints_b": 4,
                              "added": 4, "removed": 1, "changed": 0}
