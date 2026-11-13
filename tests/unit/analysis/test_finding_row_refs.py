"""``refs`` / ``refs_more`` on grouped finding rows (``finding_rows``).

A row clusters identical findings; ``ref`` names only the first flow, so
``refs`` must list every distinct flow the cluster covers.
"""

from __future__ import annotations

from friTap.analysis import Finding, Severity
from friTap.analysis.digest import MAX_FINDING_REFS, finding_rows
from friTap.analysis.digest_render import _finding_line


def _finding(flow_id: str, title: str = "PII: email") -> Finding:
    return Finding(severity=Severity.LOW, title=title, description="d",
                   source="privacy", flow_id=flow_id, metadata={"category": "pii"})


def _rows(flow_ids: list[str], ordinals: dict[str, int]) -> list[dict]:
    return finding_rows([_finding(fid) for fid in flow_ids], show_values=True, ordinals=ordinals)


def test_refs_list_distinct_flows_in_first_seen_order():
    [row] = _rows(["b", "a", "b", "c"], {"a": 1, "b": 2, "c": 3})
    assert row["ref"] == "f2"
    assert row["refs"] == ["f2", "f1", "f3"]
    assert row["count"] == 4
    assert "refs_more" not in row


def test_single_flow_row_still_carries_refs():
    [row] = _rows(["a"], {"a": 1})
    assert row["refs"] == ["f1"]


def test_cross_flow_findings_have_empty_refs():
    [row] = _rows(["", "unselected"], {"a": 1})
    assert row["ref"] == "" and row["refs"] == []


def test_refs_are_capped_with_refs_more():
    ids = [f"flow-{i}" for i in range(MAX_FINDING_REFS + 3)]
    [row] = _rows(ids, {fid: i + 1 for i, fid in enumerate(ids)})
    assert row["refs"] == [f"f{i}" for i in range(1, MAX_FINDING_REFS + 1)]
    assert row["refs_more"] == 3


def test_markdown_line_lists_all_refs():
    row = {"severity": "low", "category": "pii", "count": 2, "ref": "f2",
           "refs": ["f2", "f3"], "untrusted": {"title": "t", "description": "d"}}
    assert "(f2, f3)" in _finding_line(row)
    row["refs_more"] = 4
    assert "(f2, f3 +4 more)" in _finding_line(row)


def test_markdown_line_falls_back_to_ref_and_cross_flow():
    row = {"severity": "low", "category": "pii", "count": 1, "ref": "f2",
           "untrusted": {"title": "t", "description": "d"}}
    assert "(f2)" in _finding_line(row)
    row.update(ref="", refs=[])
    assert "(cross-flow)" in _finding_line(row)
