#!/usr/bin/env python3

"""Tests for the semantic capture / phase diff (:mod:`friTap.analysis.diff`).

Covers added/removed/changed set-diff, ID path templating reuse (``/users/123``
and ``/users/456`` collapse to one endpoint), phase-window partitioning by
``started`` timestamp, token-budget truncation, and injected ``classify``
attribution. Fixtures are real synthetic ``.tap`` files built with the shared
:mod:`tests.unit._digest_helpers` (``TapWriter``) builders, so the reader sees
exactly what a capture would contain. Everything is offline.
"""

from __future__ import annotations

import json

import pytest

from friTap.analysis.diff import (
    SCHEMA,
    diff_phases,
    diff_taps,
    load_phases,
    load_sidecar_phases,
    phase_label_for,
    phase_labels,
    phases_sidecar_for,
)
from friTap.analysis.digest import estimate_tokens
from tests.unit import _digest_helpers as helpers


def _write_tap(path, flows, *, keylog=False):
    return str(helpers.write_tap(path, flows, keylog=keylog))


def _total_endpoints(diff: dict) -> int:
    return sum(len(group["endpoints"])
               for section in ("added", "removed", "changed")
               for group in diff[section])


# ---------------------------------------------------------------------------
# added / removed / changed
# ---------------------------------------------------------------------------

@pytest.fixture
def before_after(tmp_path):
    """A pair of taps that exercise added, removed and (status) changed rows."""
    tap_a = _write_tap(tmp_path / "a.tap", [
        helpers.http_flow("a-user", method="GET", url="/v1/users/42", status=200),
        helpers.http_flow("a-login", method="POST", url="/v1/login", status=200),
    ])
    tap_b = _write_tap(tmp_path / "b.tap", [
        # Same templated signature as a-user, but a different status -> changed.
        helpers.http_flow("b-user", method="GET", url="/v1/users/99", status=500),
        # New endpoint -> added. /v1/login is gone -> removed.
        helpers.http_flow("b-items", method="GET", url="/v1/items/7", status=200),
    ])
    return tap_a, tap_b


def test_added_removed_changed_counts(before_after):
    tap_a, tap_b = before_after
    diff = diff_taps(tap_a, tap_b).to_dict()

    assert diff["schema"] == SCHEMA
    assert diff["summary"] == {
        "endpoints_a": 2, "endpoints_b": 2,
        "added": 1, "removed": 1, "changed": 1,
    }

    added_paths = {row["untrusted"]["path"]
                   for group in diff["added"] for row in group["endpoints"]}
    removed_paths = {row["untrusted"]["path"]
                     for group in diff["removed"] for row in group["endpoints"]}
    assert added_paths == {"/v1/items/{id}"}
    assert removed_paths == {"/v1/login"}


def test_changed_reports_status_code_set(before_after):
    tap_a, tap_b = before_after
    diff = diff_taps(tap_a, tap_b).to_dict()

    changed_rows = [row for group in diff["changed"] for row in group["endpoints"]]
    assert len(changed_rows) == 1
    row = changed_rows[0]
    assert row["untrusted"]["path"] == "/v1/users/{id}"
    status_change = next(c for c in row["changes"] if c["field"] == "status_codes")
    assert status_change["before"] == [200]
    assert status_change["after"] == [500]


# ---------------------------------------------------------------------------
# path templating reuse
# ---------------------------------------------------------------------------

def test_numeric_ids_collapse_to_one_endpoint(tmp_path):
    """/users/123 and /users/456 are one templated endpoint, not two."""
    tap_a = _write_tap(tmp_path / "ids.tap", [
        helpers.http_flow("f1", method="GET", url="/users/123", status=200),
        helpers.http_flow("f2", method="GET", url="/users/456", status=200),
    ])
    tap_empty = _write_tap(tmp_path / "empty.tap", [])

    diff = diff_taps(tap_empty, tap_a).to_dict()
    added_rows = [row for group in diff["added"] for row in group["endpoints"]]
    assert len(added_rows) == 1
    assert added_rows[0]["untrusted"]["path"] == "/users/{id}"
    assert added_rows[0]["count"] == 2  # both flows aggregated into the one endpoint


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

def test_phase_label_for_windows():
    phases = [{"t": 1000.0, "label": "warmup"}, {"t": 2000.0, "label": "active"}]
    assert phase_label_for(500.0, phases) is None       # before first window
    assert phase_label_for(1000.0, phases) == "warmup"  # inclusive lower bound
    assert phase_label_for(1999.0, phases) == "warmup"  # [t0, t1)
    assert phase_label_for(2000.0, phases) == "active"  # next window
    assert phase_label_for(9999.0, phases) == "active"  # last runs to +inf


def test_load_phases_sorted_and_skips_bad_lines(tmp_path):
    path = tmp_path / "phases.jsonl"
    path.write_text(
        json.dumps({"t": 2000.0, "t_rel": 10.0, "label": "active"}) + "\n"
        + "not json\n"
        + "\n"
        + json.dumps({"t": 1000.0, "t_rel": 0.0, "label": "warmup"}) + "\n"
        + json.dumps({"label": "no-timestamp"}) + "\n",
        encoding="utf-8",
    )
    phases = load_phases(str(path))
    assert [p["label"] for p in phases] == ["warmup", "active"]
    assert [p["t"] for p in phases] == [1000.0, 2000.0]


def test_diff_phases_partitions_by_started(tmp_path):
    phases = [{"t": 1000.0, "label": "warmup"}, {"t": 2000.0, "label": "active"}]
    tap = _write_tap(tmp_path / "phased.tap", [
        helpers.http_flow("warm", method="GET", url="/ping", status=200, started=1500.0),
        helpers.http_flow("act", method="GET", url="/track/55", status=200, started=2500.0),
    ])

    diff = diff_phases(tap, phases, "warmup", "active").to_dict()
    assert diff["mode"] == "phases"
    assert (diff["a"], diff["b"]) == ("warmup", "active")

    added_paths = {row["untrusted"]["path"]
                   for group in diff["added"] for row in group["endpoints"]}
    removed_paths = {row["untrusted"]["path"]
                     for group in diff["removed"] for row in group["endpoints"]}
    # /track/{id} is only in the 'active' phase; /ping only in 'warmup'.
    assert added_paths == {"/track/{id}"}
    assert removed_paths == {"/ping"}


def test_diff_phases_rejects_equal_labels(tmp_path):
    # Equal labels would funnel every flow into the first bucket, so the diff
    # would falsely report "everything removed"; reject it instead.
    phases = [{"t": 1000.0, "label": "warmup"}, {"t": 2000.0, "label": "active"}]
    tap = _write_tap(tmp_path / "phased.tap", [
        helpers.http_flow("warm", method="GET", url="/ping", status=200, started=1500.0),
    ])
    with pytest.raises(ValueError):
        diff_phases(tap, phases, "active", "active")


def test_diff_taps_labels_default_to_basenames(before_after):
    diff = diff_taps(*before_after).to_dict()
    assert (diff["a"], diff["b"]) == ("a.tap", "b.tap")


def test_diff_taps_label_override(before_after):
    diff = diff_taps(*before_after, a_label="sess-1", b_label="sess-2").to_dict()
    assert (diff["a"], diff["b"]) == ("sess-1", "sess-2")
    one_sided = diff_taps(*before_after, b_label="sess-2").to_dict()
    assert (one_sided["a"], one_sided["b"]) == ("a.tap", "sess-2")


def test_phase_labels_distinct_in_marker_order():
    phases = [{"t": 1.0, "label": "warmup"}, {"t": 2.0, "label": "active"},
              {"t": 3.0, "label": "warmup"}]
    assert phase_labels(phases) == ["warmup", "active"]


def test_sidecar_phases_present_and_absent(tmp_path):
    tap = tmp_path / "capture.tap"
    assert phases_sidecar_for(str(tap)) == tmp_path / "phases.jsonl"
    assert load_sidecar_phases(str(tap)) is None
    (tmp_path / "phases.jsonl").write_text(
        json.dumps({"t": 1000.0, "label": "warmup"}) + "\n", encoding="utf-8")
    assert load_sidecar_phases(str(tap)) == [{"t": 1000.0, "label": "warmup"}]


# ---------------------------------------------------------------------------
# budget
# ---------------------------------------------------------------------------

def test_budget_drops_rows_and_sets_truncated_marker(tmp_path):
    flows = [helpers.http_flow(f"f{i}", host=f"h{i}.example.com", method="GET",
                               url="/a", status=200) for i in range(8)]
    tap_a = _write_tap(tmp_path / "many.tap", flows)
    tap_empty = _write_tap(tmp_path / "none.tap", [])

    result = diff_taps(tap_a, tap_empty)
    full = result.to_dict()
    assert _total_endpoints(full) == 8
    assert "truncated" not in full

    budget = estimate_tokens(full) - 10
    trimmed = result.to_dict(budget=budget)
    assert "truncated" in trimmed
    assert trimmed["truncated"]["reason"] == "budget"
    assert _total_endpoints(trimmed) < 8
    assert sum(trimmed["truncated"]["dropped"].values()) == 8 - _total_endpoints(trimmed)


# ---------------------------------------------------------------------------
# classify attribution
# ---------------------------------------------------------------------------

def test_classify_annotates_host_groups(tmp_path):
    tap_a = _write_tap(tmp_path / "a.tap", [
        helpers.http_flow("f1", host="tracker.example.com", method="GET",
                          url="/beacon", status=200),
    ])
    tap_empty = _write_tap(tmp_path / "empty.tap", [])

    def classify(host):
        return {"owner": "Acme", "category": "analytics", "party": "third", "extra": "ignored"}

    diff = diff_taps(tap_empty, tap_a, classify=classify).to_dict()
    group = diff["added"][0]
    assert group["attribution"] == {"owner": "Acme", "category": "analytics", "party": "third"}


def test_no_classify_means_no_attribution(tmp_path):
    tap_a = _write_tap(tmp_path / "a.tap", [
        helpers.http_flow("f1", host="tracker.example.com", method="GET",
                          url="/beacon", status=200),
    ])
    tap_empty = _write_tap(tmp_path / "empty.tap", [])
    diff = diff_taps(tap_empty, tap_a).to_dict()
    assert "attribution" not in diff["added"][0]


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------

def test_markdown_is_ref_based_and_grouped(before_after):
    tap_a, tap_b = before_after
    md = diff_taps(tap_a, tap_b).to_markdown()
    assert "# Capture Diff Report" in md
    assert "## Added Endpoints" in md
    assert "/v1/items/{id}" in md
    assert "f" in md  # flow refs like f1 present
