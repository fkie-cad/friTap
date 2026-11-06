"""Tool-level tests for the ``find_values`` (canary) and ``diff`` read tools.

Both tools are exercised through :meth:`Registry.call` on a fresh registry with
synthetic ``.tap`` fixtures (:mod:`tests.unit._digest_helpers`), mirroring the
style of :mod:`test_read_tools`. Everything is offline — no device/Frida.

Also covers the opt-in attribution enrichment of ``get_digest`` (host rows gain
trusted ``owner``/``category``/``party`` only when requested).
"""

from __future__ import annotations

import json
import re

import pytest

from friTap.agent_api import tools_read
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry
from tests.unit._digest_helpers import EMAIL
from tests.unit._digest_helpers import http_flow as _http_flow
from tests.unit._digest_helpers import json_body as _json_body
from tests.unit._digest_helpers import write_tap as _write_tap


@pytest.fixture
def registry():
    reg = Registry()
    tools_read.register_all(reg)
    return reg


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(root=tmp_path)


def _text(doc) -> str:
    return json.dumps(doc, ensure_ascii=False)


def _error(registry, name, params, ctx) -> ToolError:
    with pytest.raises(ToolError) as info:
        registry.call(name, params, context=ctx)
    return info.value


# ---------------------------------------------------------------------------
# find_values
# ---------------------------------------------------------------------------

def test_find_values_finds_planted_canary(registry, ctx, tmp_path):
    _write_tap(tmp_path / "leak.tap",
               [_http_flow("u", url=f"/signup?email={EMAIL}", body=_json_body())])
    out = registry.call("find_values", {
        "tap": "leak.tap",
        "values": [{"value": EMAIL, "kind": "email", "label": "signup-email"}],
    }, context=ctx)

    assert out["schema"] == "fritap.find_values/1" and out["notice"]
    assert out["summary"]["hits"] >= 1
    assert out["summary"]["by_label"]["signup-email"] >= 1
    assert all(row["label"] == "signup-email" for row in out["rows"])
    # Redacted by default: no raw span, and the email itself never echoed.
    assert EMAIL not in _text(out)
    assert all("raw_span" not in row["untrusted"] for row in out["rows"])


def test_find_values_show_values_refused_without_allow_values(registry, tmp_path):
    _write_tap(tmp_path / "leak.tap", [_http_flow("u", url=f"/x?email={EMAIL}")])
    no_values = ToolContext(root=tmp_path, allow_values=False)
    err = _error(registry, "find_values", {
        "tap": "leak.tap", "show_values": True,
        "values": [{"value": EMAIL, "kind": "email", "label": "e"}],
    }, no_values)
    assert err.error_type == "forbidden"


def test_find_values_show_values_reveals_span_when_allowed(registry, tmp_path):
    _write_tap(tmp_path / "leak.tap", [_http_flow("u", url=f"/x?email={EMAIL}")])
    allowed = ToolContext(root=tmp_path, allow_values=True)
    out = registry.call("find_values", {
        "tap": "leak.tap", "show_values": True,
        "values": [{"value": EMAIL, "kind": "email", "label": "e"}],
    }, context=allowed)
    assert EMAIL in _text(out)
    assert any("raw_span" in row["untrusted"] for row in out["rows"])


def test_find_values_surfaces_short_canary_warning(registry, ctx, tmp_path):
    _write_tap(tmp_path / "leak.tap", [_http_flow("u", url="/x?q=hi")])
    out = registry.call("find_values", {
        "tap": "leak.tap",
        "values": [{"value": "hi", "kind": "free", "label": "tiny"}],
    }, context=ctx)
    assert out["warnings"] and out["warnings"][0]["label"] == "tiny"
    assert out["warnings"][0]["warning"]


def test_find_values_accepts_advertising_id_alias(registry, ctx, tmp_path):
    # "advertising_id" is a privacy.py-vocabulary alias for the "aaid" kind: it
    # must be accepted by the enum and behave exactly like "aaid".
    aaid = "38400000-8cf0-11bd-b23e-10b96e40000d"
    _write_tap(tmp_path / "leak.tap", [_http_flow("u", url=f"/t?gaid={aaid}")], keylog=False)
    alias = registry.call("find_values", {
        "tap": "leak.tap",
        "values": [{"value": aaid, "kind": "advertising_id", "label": "ad"}],
    }, context=ctx)
    canon = registry.call("find_values", {
        "tap": "leak.tap",
        "values": [{"value": aaid, "kind": "aaid", "label": "ad"}],
    }, context=ctx)
    assert alias["summary"]["hits"] == canon["summary"]["hits"] >= 1
    # The row's kind is normalized to the canonical form.
    assert alias["rows"] and all(row["kind"] == "aaid" for row in alias["rows"])


def test_find_values_rows_use_canonical_ref(registry, ctx, tmp_path):
    # Hits must carry the shared f<N> ref (like every other read tool), not the
    # raw internal flow id, so an agent can pass row["ref"] straight to get_flow.
    _write_tap(tmp_path / "leak.tap",
               [_http_flow("u", url=f"/signup?email={EMAIL}")])
    out = registry.call("find_values", {
        "tap": "leak.tap",
        "values": [{"value": EMAIL, "kind": "email", "label": "e"}],
    }, context=ctx)
    assert out["rows"]
    for row in out["rows"]:
        assert "flow_id" not in row
        assert re.fullmatch(r"f\d+", row["ref"])


# ---------------------------------------------------------------------------
# diff: tap mode
# ---------------------------------------------------------------------------

@pytest.fixture
def before_after(tmp_path):
    _write_tap(tmp_path / "a.tap", [
        _http_flow("a-user", method="GET", url="/v1/users/42", status=200),
        _http_flow("a-login", method="POST", url="/v1/login", status=200),
    ], keylog=False)
    _write_tap(tmp_path / "b.tap", [
        _http_flow("b-user", method="GET", url="/v1/users/99", status=500),
        _http_flow("b-items", method="GET", url="/v1/items/7", status=200),
    ], keylog=False)


def test_diff_taps_added_removed_changed(registry, ctx, before_after):
    out = registry.call("diff", {"tap_a": "a.tap", "tap_b": "b.tap"}, context=ctx)
    assert out["schema"] == "fritap.diff/1" and out["mode"] == "taps" and out["notice"]
    assert out["summary"] == {"endpoints_a": 2, "endpoints_b": 2,
                              "added": 1, "removed": 1, "changed": 1}
    added = {row["untrusted"]["path"] for g in out["added"] for row in g["endpoints"]}
    removed = {row["untrusted"]["path"] for g in out["removed"] for row in g["endpoints"]}
    assert added == {"/v1/items/{id}"} and removed == {"/v1/login"}


def test_diff_taps_markdown(registry, ctx, before_after):
    out = registry.call("diff", {"tap_a": "a.tap", "tap_b": "b.tap", "format": "md"}, context=ctx)
    assert out["schema"] == "fritap.diff_md/1" and out["notice"]
    assert out["markdown"].startswith("# Capture Diff Report")


def test_diff_taps_labels_are_basenames_not_paths(registry, ctx, before_after):
    # The a/b labels must not leak the server's absolute filesystem layout.
    out = registry.call("diff", {"tap_a": "a.tap", "tap_b": "b.tap"}, context=ctx)
    assert (out["a"], out["b"]) == ("a.tap", "b.tap")
    assert "/" not in out["a"] and "/" not in out["b"]


# ---------------------------------------------------------------------------
# diff: phase mode
# ---------------------------------------------------------------------------

def test_diff_phases_partitions_by_sidecar(registry, ctx, tmp_path):
    _write_tap(tmp_path / "phased.tap", [
        _http_flow("warm", method="GET", url="/ping", status=200, started=1500.0),
        _http_flow("act", method="GET", url="/track/55", status=200, started=2500.0),
    ], keylog=False)
    (tmp_path / "phases.jsonl").write_text(
        json.dumps({"t": 1000.0, "label": "warmup"}) + "\n"
        + json.dumps({"t": 2000.0, "label": "active"}) + "\n", encoding="utf-8")

    out = registry.call("diff", {"tap": "phased.tap", "phase_a": "warmup", "phase_b": "active"},
                        context=ctx)
    assert out["mode"] == "phases" and (out["a"], out["b"]) == ("warmup", "active")
    added = {row["untrusted"]["path"] for g in out["added"] for row in g["endpoints"]}
    removed = {row["untrusted"]["path"] for g in out["removed"] for row in g["endpoints"]}
    assert added == {"/track/{id}"} and removed == {"/ping"}


def test_diff_phases_missing_sidecar_is_clean_error(registry, ctx, tmp_path):
    _write_tap(tmp_path / "phased.tap", [_http_flow("a", url="/x")], keylog=False)
    err = _error(registry, "diff",
                 {"tap": "phased.tap", "phase_a": "warmup", "phase_b": "active"}, ctx)
    assert err.error_type == "not_found" and "mark_phase" in err.hint


# ---------------------------------------------------------------------------
# diff: mode validation + attribution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("params", [
    {},
    {"tap_a": "a.tap"},
    {"tap": "a.tap", "phase_a": "x"},
    {"tap_a": "a.tap", "tap_b": "b.tap", "tap": "a.tap", "phase_a": "x", "phase_b": "y"},
    {"tap": "a.tap", "phase_a": "x", "phase_b": "x"},  # equal labels -> all-removed trap
])
def test_diff_rejects_incomplete_or_mixed_modes(registry, ctx, before_after, params):
    assert _error(registry, "diff", params, ctx).error_type == "bad_param"


def test_diff_annotates_host_with_attribution(registry, ctx, tmp_path):
    _write_tap(tmp_path / "empty.tap", [], keylog=False)
    _write_tap(tmp_path / "ga.tap",
               [_http_flow("f1", host="google-analytics.com", method="GET", url="/collect")],
               keylog=False)

    out = registry.call("diff", {"tap_a": "empty.tap", "tap_b": "ga.tap",
                                 "first_party": ["myapp.example.com"]}, context=ctx)
    group = out["added"][0]
    att = group["attribution"]
    assert att["owner"] == "Google" and att["category"] == "analytics"
    assert att["party"] == "third"


def test_diff_first_party_marks_party_first(registry, ctx, tmp_path):
    _write_tap(tmp_path / "empty.tap", [], keylog=False)
    _write_tap(tmp_path / "ga.tap",
               [_http_flow("f1", host="google-analytics.com", method="GET", url="/collect")],
               keylog=False)
    out = registry.call("diff", {"tap_a": "empty.tap", "tap_b": "ga.tap",
                                 "first_party": ["google-analytics.com"]}, context=ctx)
    assert out["added"][0]["attribution"]["party"] == "first"


def test_diff_first_party_auto_infers_from_both_sides(registry, ctx, tmp_path):
    # "auto" infers first-party from the UNION of both sides' hosts (api.myapp.com
    # appears on both, the tracker only on B), so the app backend is party=first
    # and the tracker stays third.
    _write_tap(tmp_path / "a.tap",
               [_http_flow("a1", host="api.myapp.com", method="GET", url="/old")], keylog=False)
    _write_tap(tmp_path / "b.tap", [
        _http_flow("b1", host="api.myapp.com", method="GET", url="/new"),
        _http_flow("b2", host="google-analytics.com", method="GET", url="/collect"),
    ], keylog=False)
    out = registry.call("diff", {"tap_a": "a.tap", "tap_b": "b.tap", "first_party": "auto"},
                        context=ctx)
    parties = {g["untrusted"]["host"]: g["attribution"]["party"] for g in out["added"]}
    assert parties["api.myapp.com"] == "first"
    assert parties["google-analytics.com"] == "third"


# ---------------------------------------------------------------------------
# get_digest attribution enrichment (opt-in, additive)
# ---------------------------------------------------------------------------

def test_get_digest_attribute_annotates_hosts(registry, ctx, tmp_path):
    _write_tap(tmp_path / "ga.tap",
               [_http_flow("f1", host="google-analytics.com", method="GET", url="/collect")],
               keylog=False)
    out = registry.call("get_digest", {"tap": "ga.tap", "attribute": True}, context=ctx)
    assert out["params"]["attribute"] is True
    host_rows = [row for proto in out["protocols"].values() for row in proto["hosts"]]
    ga = next(r for r in host_rows if r["untrusted"]["host"] == "google-analytics.com")
    assert ga["owner"] == "Google" and ga["category"] == "analytics" and ga["party"] == "third"


def test_get_digest_first_party_auto_marks_app_domain_first(registry, ctx, tmp_path):
    # "auto" infers the app's own backend (api.myapp.com, 2 flows) while the
    # most-noisy analytics tracker is excluded, so the backend is party=first
    # and the tracker is third.
    _write_tap(tmp_path / "mix.tap", [
        _http_flow("f1", host="api.myapp.com", method="GET", url="/a"),
        _http_flow("f2", host="api.myapp.com", method="GET", url="/b"),
        _http_flow("f3", host="google-analytics.com", method="GET", url="/collect"),
    ], keylog=False)
    out = registry.call("get_digest", {"tap": "mix.tap", "first_party": "auto"}, context=ctx)
    assert out["params"]["attribute"] is True
    assert out["params"]["first_party"] == ["myapp.com"]
    rows = {r["untrusted"]["host"]: r for proto in out["protocols"].values()
            for r in proto["hosts"]}
    assert rows["api.myapp.com"]["party"] == "first"
    assert rows["google-analytics.com"]["party"] == "third"


def test_get_digest_explicit_first_party_list_overrides_auto_exclusion(registry, ctx, tmp_path):
    # An explicit list wins: even a known tracker is first-party when named
    # (auto would never pick it), proving the explicit path is unchanged.
    _write_tap(tmp_path / "ga.tap",
               [_http_flow("f1", host="google-analytics.com", method="GET", url="/collect")],
               keylog=False)
    out = registry.call("get_digest", {"tap": "ga.tap",
                                       "first_party": ["google-analytics.com"]}, context=ctx)
    assert out["params"]["first_party"] == ["google-analytics.com"]
    rows = {r["untrusted"]["host"]: r for proto in out["protocols"].values()
            for r in proto["hosts"]}
    assert rows["google-analytics.com"]["party"] == "first"


def test_get_digest_without_attribute_has_no_attribution_keys(registry, ctx, tmp_path):
    from friTap.analysis.digest import build_digest

    _write_tap(tmp_path / "ga.tap",
               [_http_flow("f1", host="google-analytics.com", method="GET", url="/collect")],
               keylog=False)
    out = registry.call("get_digest", {"tap": "ga.tap"}, context=ctx)
    # Byte-identical to a plain build_digest (no attribute/first_party in params).
    assert out == build_digest(str(tmp_path / "ga.tap"))
    assert "attribute" not in out["params"] and "first_party" not in out["params"]
    host_rows = [row for proto in out["protocols"].values() for row in proto["hosts"]]
    assert all({"owner", "category", "party"}.isdisjoint(r) for r in host_rows)
