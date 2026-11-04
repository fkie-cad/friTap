"""Tests for the read / discover / export agent tools (``friTap.agent_api.tools_read``).

Fixtures are synthetic ``.tap`` files written with :class:`TapWriter`; every
tool is exercised through :meth:`Registry.call` on a fresh registry.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from friTap.agent_api import protocol_catalog, tools_read
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry
from friTap.agent_api.services import reading
from friTap.agent_api.services.sources import resolve_tap_source
from friTap.analysis.digest import build_digest
from friTap.analysis.export_har import flow_to_har_entry, tap_to_har
from friTap.flow.tap_reader import TapReader
from tests.unit._digest_helpers import EMAIL, KEYLOG_LINE, MASTER_SECRET
from tests.unit._digest_helpers import http_flow as _http_flow
from tests.unit._digest_helpers import json_body as _json_body
from tests.unit._digest_helpers import signal_flow as _signal_flow
from tests.unit._digest_helpers import write_tap as _write_tap

FRITAP_PY = Path(__file__).resolve().parents[3] / "friTap" / "friTap.py"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def root(tmp_path):
    flows = [
        _http_flow(f"user-{i}", url=f"/v1/users/{1000 + i}/profile?lang=en",
                   body=_json_body(uid=i), headers={"authorization": "Bearer tok.en.x"},
                   started=1_700_000_000.0 + i)
        for i in range(3)
    ]
    flows.append(_http_flow("grpc-1", host="grpc.example.com", url="/pkg.Svc/Call",
                            body=b"\x00\x00\x00\x00\x02\x08\x01",
                            content_type="application/grpc", protocol="HTTP/2",
                            started=1_700_000_050.0))
    flows.append(_http_flow("rare-1", host="rare.example.net", method="GET",
                            url="/static/app.js", content_type="", status=404,
                            started=1_700_000_060.0))
    flows.append(_signal_flow("sig-1"))
    _write_tap(tmp_path / "mixed.tap", flows)
    return tmp_path


@pytest.fixture
def registry():
    reg = Registry()
    tools_read.register_all(reg)
    return reg


@pytest.fixture
def ctx(root):
    return ToolContext(root=root)


def _error(registry, name, params, ctx) -> ToolError:
    with pytest.raises(ToolError) as info:
        registry.call(name, params, context=ctx)
    return info.value


def _text(doc) -> str:
    return json.dumps(doc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_registers_all_read_tools(registry):
    assert set(registry.names()) == {
        "list_supported_protocols", "list_protocols", "get_digest", "list_endpoints",
        "get_flow", "list_findings", "export",
    }
    for spec in registry.specs():
        assert spec.result_schema and len(spec.summary) <= 100
    assert registry.get("export").mutating and registry.get("export").kind == "export"
    assert registry.get("list_supported_protocols").kind == "discover"


def test_default_registry_loads_read_tools():
    from friTap.agent_api.registry import registry as default

    assert "get_digest" in default.names()


# ---------------------------------------------------------------------------
# Sources / sandbox
# ---------------------------------------------------------------------------

def test_tap_and_session_id_are_mutually_exclusive(registry, ctx):
    assert _error(registry, "list_protocols", {}, ctx).error_type == "bad_param"
    err = _error(registry, "list_protocols", {"tap": "mixed.tap", "session_id": "s1"}, ctx)
    assert err.error_type == "bad_param"


def test_sandbox_escape_is_forbidden(registry, ctx, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    _write_tap(outside / "x.tap", [_http_flow("a")])
    for tap in ("../" + outside.name + "/x.tap", str(outside / "x.tap")):
        assert _error(registry, "get_digest", {"tap": tap}, ctx).error_type == "forbidden"


def test_missing_tap_and_wrong_suffix(registry, ctx, root):
    assert _error(registry, "get_digest", {"tap": "nope.tap"}, ctx).error_type == "not_found"
    (root / "a.txt").write_text("x")
    assert _error(registry, "get_digest", {"tap": "a.txt"}, ctx).error_type == "bad_param"


def test_session_id_uses_capture_manager_hook(monkeypatch, root, ctx):
    import friTap.agent_api.capture.manager as manager

    monkeypatch.setattr(manager, "tap_path_for", lambda sid: root / "mixed.tap")
    assert resolve_tap_source({"session_id": "abc"}, ctx) == root / "mixed.tap"


# ---------------------------------------------------------------------------
# list_supported_protocols / protocol_catalog
# ---------------------------------------------------------------------------

def test_list_supported_protocols(registry, ctx):
    out = registry.call("list_supported_protocols", {}, context=ctx)
    assert out["schema"] == "fritap.capture_protocols/1"
    names = [p["name"] for p in out["protocols"]]
    assert names == protocol_catalog.capture_protocol_names()
    tls = next(p for p in out["protocols"] if p["name"] == "tls")
    assert {"keys", "plaintext", "full"} == set(tls["capture_modes"])
    assert {o["name"] for o in tls["options"]} >= {"offsets", "pairip_safe", "force_scan"}
    assert "android" in tls["platforms"]


def test_capture_protocol_names_follow_registry():
    from friTap.protocols.registry import available_protocol_names, custom_cipher_names

    names = protocol_catalog.capture_protocol_names()
    assert set(available_protocol_names()) <= set(names)
    assert ("custom" in names) == bool(custom_cipher_names())
    assert "auto" not in names and "all" not in names


def test_every_option_flag_exists_in_cli_argparse():
    source = FRITAP_PY.read_text()
    declared = set(re.findall(r'add_argument\(([^)]*)', source, flags=re.S))
    flags = {tok for args in declared for tok in re.findall(r'"(-{1,2}[\w-]+)"', args)}
    for spec in protocol_catalog.OPTIONS:
        assert spec.flag in flags, spec.flag


def test_validate_protocol_options_accepts_valid():
    protocol_catalog.validate_protocol_options(["tls"], {"pairip_safe": True, "force_scan": ["a"]})
    protocol_catalog.validate_protocol_options(None, {"patterns": "p.json"})
    protocol_catalog.validate_protocol_options(["ssh"], {"patterns": "p.json", "quic_only": None})


@pytest.mark.skipif("signal" not in protocol_catalog.capture_protocol_names(),
                    reason="signal protocol not in this build")
def test_validate_protocol_options_accepts_option_of_implied_protocol():
    protocol_catalog.validate_protocol_options(["signal"], {"offsets": "o.json"})  # implies tls


@pytest.mark.parametrize("protocols, options, error_type", [
    (["tlz"], {}, "unknown_protocol"),
    (["ssh"], {"pairip_safe": True}, "unsupported_option"),
    (["tls"], {"libraries": ["libssl.so"]}, "unsupported_option"),
    (["tls"], {"bogus": 1}, "unsupported_option"),
    (["tls"], {"pairip_safe": "yes"}, "bad_param"),
    (["tls"], {"force_scan": "notalist"}, "bad_param"),
])
def test_validate_protocol_options_errors(protocols, options, error_type):
    with pytest.raises(ToolError) as info:
        protocol_catalog.validate_protocol_options(protocols, options)
    assert info.value.error_type == error_type
    if error_type != "bad_param":
        assert info.value.hint


def test_libraries_hint_points_at_alternatives():
    with pytest.raises(ToolError) as info:
        protocol_catalog.validate_protocol_options(["tls"], {"libraries": ["x"]})
    assert "force_scan" in info.value.hint


def test_options_to_cli_flags_order_and_shapes():
    argv = protocol_catalog.options_to_cli_flags(
        {"pairip_safe": True, "quic_only": False, "force_scan": ["a", "b"],
         "offsets": "o.json", "patterns": None})
    assert argv == ["--offsets", "o.json", "--force-scan", "a", "--force-scan", "b",
                    "--pairip-safe"]
    assert protocol_catalog.options_to_cli_flags(None) == []
    with pytest.raises(ToolError):
        protocol_catalog.options_to_cli_flags({"nope": True})


def test_options_schema_covers_catalog():
    schema = protocol_catalog.options_schema()
    assert set(schema["properties"]) == {spec.name for spec in protocol_catalog.OPTIONS}
    assert schema["additionalProperties"] is False


# ---------------------------------------------------------------------------
# list_protocols
# ---------------------------------------------------------------------------

def test_list_protocols_counts(registry, ctx):
    out = registry.call("list_protocols", {"tap": "mixed.tap"}, context=ctx)
    assert out["schema"] == "fritap.protocols/1"
    assert out["source"]["flows_total"] == 6
    assert out["protocols"]["http1"] == 4
    assert out["app_protocols"]["grpc"] == 1 and out["app_protocols"]["signal"] == 1
    assert "http2" in out["known_protocols"]


# ---------------------------------------------------------------------------
# get_digest
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slice_params, kwargs", [
    ({}, {}),
    ({"protocol": "signal"}, {"protocol": "signal"}),
    ({"app_protocol": "grpc"}, {"app_protocol": "grpc"}),
    ({"filter": 'http.host == "rare.example.net"'}, {"filter_expr": 'http.host == "rare.example.net"'}),
])
def test_get_digest_equals_build_digest(registry, ctx, root, slice_params, kwargs):
    out = registry.call("get_digest", {"tap": "mixed.tap", **slice_params}, context=ctx)
    assert out == build_digest(str(root / "mixed.tap"), **kwargs)


def test_get_digest_focus_budget_and_markdown(registry, ctx, root):
    out = registry.call("get_digest", {"tap": "mixed.tap", "focus": "privacy", "budget": 300},
                        context=ctx)
    assert out == build_digest(str(root / "mixed.tap"), focus="privacy", budget_tokens=300)
    md = registry.call("get_digest", {"tap": "mixed.tap", "format": "md"}, context=ctx)
    assert md["schema"] == "fritap.digest_md/1" and md["notice"]
    assert md["markdown"].startswith("# friTap")


def test_get_digest_budget_cap(registry, ctx):
    err = _error(registry, "get_digest", {"tap": "mixed.tap", "budget": 9000}, ctx)
    assert err.error_type == "bad_param"


def test_unknown_protocol_has_hint(registry, ctx):
    err = _error(registry, "get_digest", {"tap": "mixed.tap", "protocol": "htpp2"}, ctx)
    assert err.error_type == "unknown_protocol" and "http2" in err.hint
    err = _error(registry, "list_endpoints", {"tap": "mixed.tap", "app_protocol": "grcp"}, ctx)
    assert err.error_type == "unknown_protocol" and "grpc" in err.hint


def test_bad_filter_has_hint(registry, ctx):
    err = _error(registry, "get_digest", {"tap": "mixed.tap", "filter": "http.hots == 1"}, ctx)
    assert err.error_type == "bad_filter" and err.hint
    err = _error(registry, "list_findings", {"tap": "mixed.tap", "filter": "(("}, ctx)
    assert err.error_type == "bad_filter"
    err = _error(registry, "get_digest",
                 {"tap": "mixed.tap", "filter": 'http.host contians "x"'}, ctx)
    assert err.error_type == "bad_filter" and "contains" in err.hint


# ---------------------------------------------------------------------------
# list_endpoints
# ---------------------------------------------------------------------------

def _digest_endpoint_refs(digest):
    return sorted(row["ref"] for proto in digest["protocols"].values()
                  for row in proto["endpoints"])


def test_list_endpoints_matches_digest_rows(registry, ctx, root):
    out = registry.call("list_endpoints", {"tap": "mixed.tap"}, context=ctx)
    assert out["schema"] == "fritap.endpoints/1" and out["notice"]
    digest = build_digest(str(root / "mixed.tap"), budget_tokens=8000)
    assert sorted(r["ref"] for r in out["rows"]) == _digest_endpoint_refs(digest)
    assert out["rows"][0]["count"] == 3 and out["rows"][0]["protocol"] == "http1"
    assert out["total"] == len(out["rows"]) and out["next_cursor"] is None


def test_list_endpoints_slice(registry, ctx, root):
    out = registry.call("list_endpoints", {"tap": "mixed.tap", "app_protocol": "grpc"},
                        context=ctx)
    assert [r["protocol"] for r in out["rows"]] == ["grpc"]
    assert out["source"]["flows_selected"] == 1


def test_list_endpoints_pagination(registry, ctx):
    full = registry.call("list_endpoints", {"tap": "mixed.tap"}, context=ctx)["rows"]
    first = registry.call("list_endpoints", {"tap": "mixed.tap", "limit": 2}, context=ctx)
    assert first["rows"] == full[:2] and first["next_cursor"] == "2"
    second = registry.call("list_endpoints",
                           {"tap": "mixed.tap", "limit": 2, "cursor": first["next_cursor"]},
                           context=ctx)
    assert second["rows"] == full[2:4]
    err = _error(registry, "list_endpoints", {"tap": "mixed.tap", "cursor": "99"}, ctx)
    assert err.error_type == "bad_param"


def test_list_endpoints_never_contains_values(registry, ctx):
    text = _text(registry.call("list_endpoints", {"tap": "mixed.tap"}, context=ctx))
    assert EMAIL not in text and "tok.en.x" not in text


# ---------------------------------------------------------------------------
# get_flow
# ---------------------------------------------------------------------------

def test_get_flow_default_and_fields(registry, ctx):
    out = registry.call("get_flow", {"tap": "mixed.tap", "ref": "f1"}, context=ctx)
    assert out["schema"] == "fritap.flow/1" and out["params"]["max_bytes"] == 4096
    assert {"flow", "request", "response", "messages"} <= set(out)
    assert EMAIL not in _text(out)
    only = registry.call("get_flow", {"tap": "mixed.tap", "ref": "f1", "fields": ["flow"]},
                         context=ctx)
    assert set(only) == {"schema", "source", "params", "notice", "flow"}


def test_get_flow_show_values_and_messages(registry, ctx):
    shown = registry.call("get_flow", {"tap": "mixed.tap", "ref": "f1", "show_values": True},
                          context=ctx)
    assert EMAIL in _text(shown)
    msgs = registry.call("get_flow", {"tap": "mixed.tap", "ref": "f6#m0", "fields": ["messages"]},
                         context=ctx)
    assert msgs["messages_total"] == 1 and msgs["messages"][0]["ref"] == "f6#m0"


def test_get_flow_bad_ref_and_cap(registry, ctx):
    err = _error(registry, "get_flow", {"tap": "mixed.tap", "ref": "f99"}, ctx)
    assert err.error_type == "bad_ref" and err.hint
    err = _error(registry, "get_flow", {"tap": "mixed.tap", "ref": "f1", "max_bytes": 20000}, ctx)
    assert err.error_type == "bad_param"
    err = _error(registry, "get_flow", {"tap": "mixed.tap", "ref": "f1", "fields": ["x"]}, ctx)
    assert err.error_type == "bad_param"


def test_project_flow_fields_keeps_envelope():
    detail = {"schema": "s", "source": {}, "params": {}, "notice": "n", "flow": 1,
              "request": 2, "response": 3, "messages": [], "messages_total": 0}
    assert reading.project_flow_fields(detail, None) is detail
    assert reading.project_flow_fields(detail, ["messages"]) == {
        "schema": "s", "source": {}, "params": {}, "notice": "n", "messages": [],
        "messages_total": 0}


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_redacted_by_default(registry, ctx, root):
    out = registry.call("list_findings", {"tap": "mixed.tap"}, context=ctx)
    assert out["schema"] == "fritap.findings/1" and out["notice"]
    assert out["summary"]["total"] >= 1 and out["rows"]
    _write_tap(root / "pii.tap", [_http_flow("p", url=f"/signup?email={EMAIL}",
                                             body=_json_body())])
    redacted = registry.call("list_findings", {"tap": "pii.tap", "limit": 200}, context=ctx)
    assert redacted["rows"] and EMAIL not in _text(redacted)
    shown = registry.call("list_findings", {"tap": "pii.tap", "limit": 200, "show_values": True},
                          context=ctx)
    assert EMAIL in _text(shown)


def test_list_findings_filters(registry, ctx):
    pii = registry.call("list_findings", {"tap": "mixed.tap", "category": "pii"}, context=ctx)
    assert pii["rows"] and {r["category"] for r in pii["rows"]} == {"pii"}
    severe = registry.call("list_findings", {"tap": "mixed.tap", "min_severity": "critical"},
                           context=ctx)
    assert all(r["severity"] == "critical" for r in severe["rows"])
    err = _error(registry, "list_findings", {"tap": "mixed.tap", "min_severity": "huge"}, ctx)
    assert err.error_type == "bad_param"


def test_list_findings_pagination(registry, ctx):
    full = registry.call("list_findings", {"tap": "mixed.tap"}, context=ctx)
    page = registry.call("list_findings", {"tap": "mixed.tap", "limit": 1}, context=ctx)
    assert page["rows"] == full["rows"][:1] and page["total"] == full["total"]
    assert (page["next_cursor"] is None) == (full["total"] <= 1)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def test_export_har(registry, ctx, root):
    out = registry.call("export", {"tap": "mixed.tap", "format": "har", "out": "out/x.har"},
                        context=ctx)
    path = root / "out" / "x.har"
    data = path.read_bytes()
    assert out == {"schema": "fritap.export/1", "path": str(path.resolve()), "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "format": "har"}
    har = json.loads(data)
    assert har["log"]["version"] == "1.2" and len(har["log"]["entries"]) == 5
    first = har["log"]["entries"][0]
    assert first["request"]["url"].startswith("https://api.example.com/v1/users/")
    assert {"name": "lang", "value": "en"} in first["request"]["queryString"]
    assert "postData" not in first["request"]
    assert (path.stat().st_mode & 0o777) == 0o600


def test_export_har_slice_and_bodies(registry, ctx, root):
    registry.call("export", {"tap": "mixed.tap", "format": "har", "out": "g.har",
                             "app_protocol": "grpc", "include_bodies": True}, context=ctx)
    entries = json.loads((root / "g.har").read_text())["log"]["entries"]
    assert len(entries) == 1 and entries[0]["request"]["postData"]["encoding"] == "base64"


def test_export_har_module_matches_flow_entries(root):
    har = tap_to_har(str(root / "mixed.tap"))
    with TapReader(str(root / "mixed.tap")) as reader:
        flows = [reader.read_flow(s.flow_id) for s in reader.read_flow_summaries()]
    expected = [e for e in (flow_to_har_entry(f) for f in flows) if e is not None]
    assert [e["request"]["url"] for e in har["log"]["entries"]] == \
        [e["request"]["url"] for e in expected]


def test_export_markdown(registry, ctx, root):
    out = registry.call("export", {"tap": "mixed.tap", "format": "markdown", "out": "r.md"},
                        context=ctx)
    text = (root / "r.md").read_text()
    assert out["format"] == "markdown" and text.startswith("# friTap")
    assert "# friTap flow f1" in text and EMAIL not in text and MASTER_SECRET not in text


def test_export_refuses_overwrite(registry, ctx, root):
    (root / "x.har").write_text("keep")
    err = _error(registry, "export", {"tap": "mixed.tap", "format": "har", "out": "x.har"}, ctx)
    assert err.error_type == "already_exists" and "overwrite" in err.hint
    assert (root / "x.har").read_text() == "keep"
    registry.call("export", {"tap": "mixed.tap", "format": "har", "out": "x.har",
                             "overwrite": True}, context=ctx)
    assert (root / "x.har").read_text() != "keep"


def test_export_refuses_source_and_escape(registry, ctx):
    err = _error(registry, "export", {"tap": "mixed.tap", "format": "har", "out": "mixed.tap",
                                      "overwrite": True}, ctx)
    assert err.error_type == "bad_param"
    err = _error(registry, "export", {"tap": "mixed.tap", "format": "har", "out": "../e.har"}, ctx)
    assert err.error_type == "forbidden"


def test_export_keylog_requires_both_opt_ins(registry, ctx, root):
    params = {"tap": "mixed.tap", "format": "keylog", "out": "k.log"}
    assert _error(registry, "export", params, ctx).error_type == "forbidden"
    err = _error(registry, "export", {**params, "confirm_secrets": True}, ctx)
    assert err.error_type == "forbidden" and "--allow-secrets" in err.hint
    secret_ctx = ToolContext(root=root, allow_secrets=True)
    assert _error(registry, "export", params, secret_ctx).error_type == "forbidden"
    assert not (root / "k.log").exists()
    out = registry.call("export", {**params, "confirm_secrets": True}, context=secret_ctx)
    assert (root / "k.log").read_text() == KEYLOG_LINE + "\n"
    assert MASTER_SECRET not in _text(out)


def test_export_keylog_rejects_slice(registry, root):
    secret_ctx = ToolContext(root=root, allow_secrets=True)
    err = _error(registry, "export", {"tap": "mixed.tap", "format": "keylog", "out": "k.log",
                                      "confirm_secrets": True, "protocol": "tls"}, secret_ctx)
    assert err.error_type == "bad_param"


def test_export_keylog_of_session_reads_split_keylog_files(registry, root):
    # A live capture's tap holds no key records; capture="keys" writes keys.<proto>.log.
    session_dir = root / ".fritap-sessions" / "s1"
    session_dir.mkdir(parents=True)
    _write_tap(session_dir / "capture.tap", [_http_flow("a")], keylog=False)
    (session_dir / "keys.tls.log").write_text(KEYLOG_LINE + "\n\n")
    secret_ctx = ToolContext(root=root, allow_secrets=True)
    out = registry.call("export", {"tap": ".fritap-sessions/s1/capture.tap", "format": "keylog",
                                   "out": "k.log", "confirm_secrets": True}, context=secret_ctx)
    assert (root / "k.log").read_text() == KEYLOG_LINE + "\n"
    assert out["bytes"] == len(KEYLOG_LINE) + 1


def test_export_keylog_ignores_keylog_files_next_to_plain_tap(registry, root, tmp_path):
    _write_tap(root / "plain.tap", [_http_flow("a")], keylog=False)
    (root / "keys.tls.log").write_text(KEYLOG_LINE + "\n")
    secret_ctx = ToolContext(root=root, allow_secrets=True)
    out = registry.call("export", {"tap": "plain.tap", "format": "keylog", "out": "k.log",
                                   "confirm_secrets": True}, context=secret_ctx)
    assert out["bytes"] == 0


# ---------------------------------------------------------------------------
# TapReader.iter_keylogs
# ---------------------------------------------------------------------------

def test_iter_keylogs(root, tmp_path):
    with TapReader(str(root / "mixed.tap")) as reader:
        assert [k for k, _ts in reader.iter_keylogs()] == [KEYLOG_LINE]
    _write_tap(tmp_path / "nokeys.tap", [_http_flow("a")], keylog=False)
    with TapReader(str(tmp_path / "nokeys.tap")) as reader:
        assert list(reader.iter_keylogs()) == []
