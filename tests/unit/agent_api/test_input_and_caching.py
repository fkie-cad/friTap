"""Untrusted JSON input, single-encode wire format, read-tool caches and stream decoding."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from friTap.agent_api.adapters import cli
from friTap.agent_api.adapters.mcp_server import call_tool_result
from friTap.agent_api.capture.session import _decode
from friTap.agent_api.capture.status import StatusTracker
from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import capped_json, dumps_compact
from friTap.agent_api.errors import ToolError
from friTap.agent_api.json_input import load_json, load_json_object
from friTap.agent_api.registry import Registry, ToolSpec
from friTap.agent_api.schema import object_schema
from friTap.agent_api.services import discovery, reading
from friTap.agent_api.services.protocols import protocols_in_tap
from friTap.output.stdout_stream import envelope
from tests.unit._digest_helpers import http_flow, write_tap

DEEP = "[" * 5000 + "]" * 5000          # RecursionError on CPython < 3.14
NESTED = "[" * 100 + "]" * 100            # parses everywhere; > MAX_JSON_DEPTH (64)
DEEP_OBJECT = '{"a": ' + NESTED + "}"


# --- untrusted JSON ---------------------------------------------------------

@pytest.mark.parametrize("text", [DEEP, NESTED, "{not json", '"x' + "y" * 10])
def test_load_json_rejects_deep_or_invalid(text):
    with pytest.raises(ToolError) as info:
        load_json(text, "src")
    assert info.value.error_type == "bad_param" and info.value.error.startswith("src:")


def test_load_json_object_size_cap_and_type():
    with pytest.raises(ToolError):
        load_json_object("{}" + " " * 20, "src", max_bytes=10)
    with pytest.raises(ToolError) as info:
        load_json_object("[1]", "src", error_type="bad_request")
    assert info.value.error_type == "bad_request"
    assert load_json_object('{"a": [1]}', "src") == {"a": [1]}


def _echo_registry():
    reg = Registry()
    schema = object_schema({"tap": {"type": "string"}, "opts": {"type": "object"}})
    reg.register(ToolSpec("echo", "Echo.", schema, lambda p, c: {"params": p}, "read"))
    return reg


@pytest.mark.parametrize("tokens", [
    ["echo", "--json", DEEP_OBJECT],
    ["echo", "--opts", DEEP_OBJECT],
])
def test_cli_rejects_deep_json(tokens):
    out = io.StringIO()
    code = cli.QueryCli(_echo_registry(), out, io.StringIO()).run(tokens)
    doc = json.loads(out.getvalue())
    assert code != 0 and doc["error_type"] == "bad_param"
    assert "nested deeper" in doc["error"]


def test_cli_params_file_is_depth_checked(tmp_path):
    params = tmp_path / "p.json"
    params.write_text(DEEP_OBJECT)
    out = io.StringIO()
    cli.QueryCli(_echo_registry(), out, io.StringIO()).run(["echo", "--params-file", str(params)])
    assert json.loads(out.getvalue())["error_type"] == "bad_param"


def test_rest_body_is_depth_checked():
    from friTap.agent_api.adapters.rest_server import _parse_params

    with pytest.raises(ToolError) as info:
        _parse_params(DEEP_OBJECT.encode())
    assert info.value.error_type == "bad_request"


# --- one serializer on the wire ----------------------------------------------

def _path_registry():
    reg = Registry()
    reg.register(ToolSpec("where", "Path result.", object_schema({}),
                          lambda p, c: {"path": Path("/x/y"), "n": [1, 2]}, "read"))
    return reg


def test_capped_json_text_is_the_wire_text():
    doc, text = capped_json({"a": [1] * 50, "p": Path("/x")}, 10_000)
    assert text == dumps_compact(doc) and json.loads(text)["p"] == "/x"
    trimmed, text = capped_json({"a": list(range(500))}, 200)
    assert trimmed["truncated"] and json.loads(text) == trimmed


def test_registry_call_json_matches_call():
    result, text = _path_registry().call_json("where", {})
    assert json.loads(text) == {"path": "/x/y", "n": [1, 2]}
    assert result["path"] == Path("/x/y")


def test_mcp_result_with_non_json_type_serializes():
    pytest.importorskip("mcp")
    result = call_tool_result(_path_registry(), ToolContext(), "where", {})
    assert not result.isError
    assert json.loads(result.content[0].text) == {"path": "/x/y", "n": [1, 2]}


# --- read-tool caches ---------------------------------------------------------

@pytest.fixture
def tap(tmp_path):
    reading.scan_cache.clear()
    yield Path(write_tap(tmp_path / "c.tap", [http_flow("f1"), http_flow("f2", host="b.example")]))
    reading.scan_cache.clear()


def _count_scans(monkeypatch):
    from friTap.analysis import digest

    calls = []
    real = digest.scan_tap

    def spy(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(digest, "scan_tap", spy)
    return calls


def test_scan_cache_reuses_scan_across_pages(tap, monkeypatch):
    calls = _count_scans(monkeypatch)
    first = reading.endpoints(tap, {})
    assert reading.endpoints(tap, {}) == first
    assert len(calls) == 1
    reading.endpoints(tap, {"protocol": "tls"})  # another slice -> another scan
    assert len(calls) == 2


def test_scan_cache_misses_after_rewrite(tap, monkeypatch):
    calls = _count_scans(monkeypatch)
    reading.endpoints(tap, {})
    stat = tap.stat()
    os.utime(tap, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    reading.endpoints(tap, {})
    assert len(calls) == 2


def test_scan_cache_is_bounded():
    cache = reading.TapResultCache(maxsize=2)
    here = Path(__file__)
    for index in range(5):
        cache.get_or_compute(here, (index,), lambda: index)
    assert len(cache._entries) == 2


def test_findings_category_runs_only_matching_analyzers(tap, monkeypatch):
    from friTap.analysis import digest

    seen = []
    real = digest.builtin_analyzers

    def spy(show_values, focus="all", categories=None):
        seen.append(categories)
        return real(show_values, focus, categories)

    monkeypatch.setattr(digest, "builtin_analyzers", spy)
    reading.findings(tap, {"category": "network"})
    assert seen == [frozenset({"network"})]
    assert digest._analyzer_names_for("all", ["credentials", "ioc", "privacy"],
                                      frozenset({"network"})) == ["ioc"]


def test_protocols_in_tap_is_memoized(tap, monkeypatch):
    first = protocols_in_tap(tap)
    from friTap.flow import tap_reader

    monkeypatch.setattr(tap_reader.TapReader, "iter_flows",
                        lambda self: (_ for _ in ()).throw(AssertionError("re-read")))
    assert protocols_in_tap(tap) == first


def test_app_snapshot_reused_for_later_pages():
    clock = [0.0]
    snaps = discovery.AppSnapshots(ttl=30, clock=lambda: clock[0])
    calls = []

    def enumerate_apps():
        calls.append(1)
        return {"id": "d"}, [len(calls)]

    assert snaps.get(("d",), True, enumerate_apps)[1] == [1]
    assert snaps.get(("d",), False, enumerate_apps)[1] == [1]   # cursor page: snapshot
    clock[0] = 31
    assert snaps.get(("d",), False, enumerate_apps)[1] == [2]   # expired
    assert snaps.get(("d",), True, enumerate_apps)[1] == [3]    # first page: fresh


# --- capture stream decoding --------------------------------------------------

def _line(kind, **fields):
    return (json.dumps(envelope(kind, fields)) + "\n").encode()


def test_decode_keeps_only_plaintext_length():
    record = _decode(_line("data", protocol="tls", data="00" * 4096, function="SSL_read"))
    assert record["data_len"] == 4096 and "data" not in record
    assert record["function"] == "SSL_read"
    assert _decode(b"[" * 100000 + b"]" * 100000) is None
    assert _decode(b"not json") is None


def test_status_counts_data_len_and_hex():
    tracker = StatusTracker()
    tracker.feed(_decode(_line("data", protocol="tls", data="ab" * 10)))
    tracker.feed({"type": "data", "protocol": "tls", "data": "abcd"})
    assert tracker.protocols["tls"].data_bytes == 12


@pytest.mark.parametrize("reported,exit_code,expected", [
    ("duration", 0, "duration"),
    ("target_exited", 0, "target_exited"),
    ("stopped", 0, "stopped"),
    (None, 3, "target_exited"),     # older child: inferred
    (None, 0, "duration"),
    ("bogus", 0, "duration"),       # unknown value ignored
])
def test_ended_by_prefers_child_report(reported, exit_code, expected):
    tracker = StatusTracker()
    end = {"type": "stream_end", "exit_code": exit_code}
    if reported:
        end["ended_by"] = reported
    tracker.feed(end)
    assert tracker.ended_by() == expected
    assert tracker.ended_by(stop_requested=True) == "stopped"


def test_markdown_export_scans_the_capture_once(tap, monkeypatch):
    from friTap.agent_api.services import export

    calls = _count_scans(monkeypatch)
    text = export.markdown_text(tap, {})
    assert len(calls) == 1, "digest and flow selection must share one scan"
    assert "# Flows" in text and "b.example" in text
    export.markdown_text(tap, {})
    assert len(calls) == 1, "a second export of the unchanged tap hits the cache"


def test_digest_cached_scan_matches_uncached_and_survives_budgets(tap):
    from friTap.analysis.digest import build_digest

    tight = reading.digest(tap, {"budget": 60})
    roomy = reading.digest(tap, {"budget": 4000})
    assert tight["truncated"], "the tight budget must actually drop rows"
    assert roomy == build_digest(str(tap), budget_tokens=4000), \
        "a budget pass on a digest must not mutate the cached scan"


def test_digest_rejects_bad_focus_before_scanning(tap, monkeypatch):
    calls = _count_scans(monkeypatch)
    with pytest.raises(ValueError):
        reading.digest(tap, {"budget": 100, "focus": "nope"})
    assert calls == []


def test_build_digest_uses_a_precomputed_scan(tap, monkeypatch):
    from friTap.analysis import digest

    scan = digest.scan_tap(str(tap), None, digest.builtin_analyzers(False))
    calls = _count_scans(monkeypatch)
    doc = digest.build_digest(str(tap), scan=scan)
    assert calls == []
    assert doc["source"]["flows_selected"] == scan.selected
