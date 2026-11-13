#!/usr/bin/env python3

"""The capture digest and semantic diff surface a flow's resolved SDK.

When ``--attribute-sdk`` attributed a flow to a known SDK, its
``{sdk,vendor,category}`` dict rides the ``.tap`` and is lifted onto the digest
host/endpoint rows (and the diff endpoint rows) as a TRUSTED top-level ``sdks``
list — it comes from the bundled signature table, not captured traffic, so it is
NOT placed under ``untrusted``. A capture with no attributed flow is unchanged
(no ``sdks`` key anywhere), so existing digests stay byte-identical.
"""

from __future__ import annotations

from friTap.analysis.diff import _collect_endpoints, diff_taps
from friTap.analysis.digest import build_digest, scan_flows
from tests.unit import _digest_helpers as helpers

FB_SDK = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}


def _write(path, flows):
    return str(helpers.write_tap(path, flows))


def _all_rows(digest):
    """Every host + endpoint row across all protocol groups."""
    rows = []
    for group in digest["protocols"].values():
        rows.extend(group["hosts"])
        rows.extend(group["endpoints"])
    return rows


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------

def test_digest_surfaces_sdk_on_host_and_endpoint_rows(tmp_path):
    flow = helpers.http_flow("f-1", host="graph.facebook.com", url="/v1/events")
    flow.sdk = dict(FB_SDK)
    tap = _write(tmp_path / "sdk.tap", [flow])

    digest = build_digest(tap)
    rows_with_sdk = [row for row in _all_rows(digest) if "sdks" in row]
    # Both the host row and the endpoint row of the single flow carry it.
    assert len(rows_with_sdk) == 2
    for row in rows_with_sdk:
        assert row["sdks"] == [FB_SDK]
        # Trusted: lifted to the row top level, never under untrusted.
        assert "sdks" not in row["untrusted"]


def test_digest_dedupes_and_sorts_multiple_sdks(tmp_path):
    flutter = {"sdk": "Flutter", "vendor": "Google", "category": "framework"}
    f1 = helpers.http_flow("f-1", host="api.example.com", url="/a")
    f1.sdk = dict(FB_SDK)
    f2 = helpers.http_flow("f-2", host="api.example.com", url="/b")
    f2.sdk = dict(flutter)
    f3 = helpers.http_flow("f-3", host="api.example.com", url="/c")
    f3.sdk = dict(FB_SDK)  # duplicate SDK on the same host
    tap = _write(tmp_path / "multi.tap", [f1, f2, f3])

    digest = build_digest(tap)
    host_rows = [row for group in digest["protocols"].values()
                 for row in group["hosts"] if "sdks" in row]
    assert len(host_rows) == 1
    # Distinct, ordered by SDK name (Facebook SDK < Flutter).
    assert host_rows[0]["sdks"] == [FB_SDK, flutter]


def test_digest_unchanged_without_sdk(tmp_path):
    flow = helpers.http_flow("f-1", host="graph.facebook.com", url="/v1/events")
    # flow.sdk left at None.
    tap = _write(tmp_path / "plain.tap", [flow])
    digest = build_digest(tap)
    assert all("sdks" not in row for row in _all_rows(digest))


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def test_diff_surfaces_sdk_on_added_endpoint(tmp_path):
    before = _write(tmp_path / "a.tap", [
        helpers.http_flow("old-1", host="api.example.com", url="/legacy"),
    ])
    added = helpers.http_flow("new-1", host="graph.facebook.com", url="/v1/events")
    added.sdk = dict(FB_SDK)
    after = _write(tmp_path / "b.tap", [added])

    result = diff_taps(before, after).to_dict()
    added_rows = [row for group in result["added"] for row in group["endpoints"]]
    assert len(added_rows) == 1
    assert added_rows[0]["sdks"] == [FB_SDK]
    assert "sdks" not in added_rows[0]["untrusted"]


# ---------------------------------------------------------------------------
# Two-tier attribution (flow.attribution): originator + transport
# ---------------------------------------------------------------------------
#
# ``Flow`` has no ``attribution`` field yet, so it cannot round-trip a ``.tap``;
# these tests set it on in-memory flows and digest them via ``scan_flows``.

OKHTTP = {"sdk": "OkHttp", "vendor": "Square", "category": "network"}


def _attribution(originator=None, kind="cronet"):
    return {"transport": {"module": f"lib{kind}.so", "kind": kind},
            "originator": originator, "confidence": "high",
            "source": "backtrace", "bucket": "sdk", "mixed": False}


def _digest_flows(flows):
    return build_digest("(in memory)", scan=scan_flows(flows))


def _host_rows(digest):
    return [row for group in digest["protocols"].values() for row in group["hosts"]]


def test_digest_prefers_attribution_originator_over_flow_sdk():
    flow = helpers.http_flow("f-1", host="graph.facebook.com", url="/v1/events")
    flow.sdk = dict(OKHTTP)
    flow.attribution = _attribution(dict(FB_SDK))
    rows = [row for row in _all_rows(_digest_flows([flow])) if "sdks" in row]
    assert len(rows) == 2  # host + endpoint
    assert all(row["sdks"] == [FB_SDK] for row in rows)


def test_digest_falls_back_to_flow_sdk_without_originator():
    flow = helpers.http_flow("f-1", host="graph.facebook.com", url="/v1/events")
    flow.sdk = dict(FB_SDK)
    flow.attribution = _attribution(None)  # transport known, originator not
    rows = [row for row in _all_rows(_digest_flows([flow])) if "sdks" in row]
    assert len(rows) == 2
    assert all(row["sdks"] == [FB_SDK] for row in rows)


def test_digest_host_rows_list_sorted_deduped_transports():
    flows = []
    for i, kind in enumerate(["cronet", "boringssl", "cronet"]):
        flow = helpers.http_flow(f"f-{i}", host="api.example.com", url=f"/p{i}")
        flow.attribution = _attribution(None, kind=kind)
        flows.append(flow)
    digest = _digest_flows(flows)
    (host,) = _host_rows(digest)
    assert host["transports"] == ["boringssl", "cronet"]
    # Endpoint rows never carry transports.
    endpoints = [row for g in digest["protocols"].values() for row in g["endpoints"]]
    assert endpoints and all("transports" not in row for row in endpoints)


def test_digest_has_no_transports_without_attribution():
    flow = helpers.http_flow("f-1", host="api.example.com", url="/a")
    flow.sdk = dict(FB_SDK)
    assert all("transports" not in row for row in _all_rows(_digest_flows([flow])))


def test_diff_prefers_attribution_originator_over_flow_sdk():
    flow = helpers.http_flow("f-1", host="graph.facebook.com", url="/v1/events")
    flow.sdk = dict(OKHTTP)
    flow.attribution = _attribution(dict(FB_SDK))
    (endpoint,) = _collect_endpoints([(1, None, flow)]).values()
    assert list(endpoint.sdks.values()) == [FB_SDK]


def test_digest_transport_kind_is_capped_at_max_key_chars():
    from friTap.analysis._digest_shapes import MAX_KEY_CHARS

    flow = helpers.http_flow("f-1", host="api.example.com", url="/a")
    flow.attribution = _attribution(None, kind="k" * (MAX_KEY_CHARS + 20))
    (host,) = _host_rows(_digest_flows([flow]))
    assert host["transports"] == ["k" * (MAX_KEY_CHARS - 1) + "…"]
