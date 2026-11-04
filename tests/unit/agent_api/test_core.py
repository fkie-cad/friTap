"""Unit tests for the agent API core: registry, schema, errors, paths, envelope."""

from __future__ import annotations

import json
import os

import pytest

from friTap.agent_api import ToolContext, ToolError, ToolSpec, list_tools, registry
from friTap.agent_api.envelope import cap_response, json_size, ok, paginate
from friTap.agent_api.errors import wrap
from friTap.agent_api.paths import resolve_under_root
from friTap.agent_api.registry import Registry
from friTap.agent_api.schema import (
    SHOW_VALUES,
    SLICE_PARAMS,
    TAP_SOURCE_KEYS,
    TAP_SOURCE_PARAMS,
    object_schema,
    page_params,
    validate,
)
from friTap.exit_codes import EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR

READ_SCHEMA = object_schema(
    {**TAP_SOURCE_PARAMS, **SLICE_PARAMS, **SHOW_VALUES, **page_params(),
     "fmt": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
     "tags": {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}}},
    one_of_required=TAP_SOURCE_KEYS,
)


def _echo(params, ctx):
    return {"schema": "test/1", "params": params, "root": str(ctx.root)}


def _spec(name="echo", handler=_echo, **kw):
    return ToolSpec(name=name, summary="Echo params.", params_schema=READ_SCHEMA,
                    handler=handler, kind="read", **kw)


def _bad_param(fn, *args):
    with pytest.raises(ToolError) as info:
        fn(*args)
    assert info.value.error_type == "bad_param"
    return info.value


# --------------------------------------------------------------------- registry

class TestRegistry:
    def test_register_and_call_applies_defaults(self, tmp_path):
        reg = Registry()
        reg.register(_spec())
        out = reg.call("echo", {"tap": "x.tap"}, context=ToolContext(root=tmp_path))
        assert out["params"] == {"tap": "x.tap", "show_values": False, "limit": 50, "fmt": "json"}
        assert out["root"] == str(tmp_path)

    def test_show_values_forbidden_without_allow_values(self, tmp_path):
        reg = Registry()
        reg.register(_spec())
        ctx = ToolContext(root=tmp_path, allow_values=False)
        with pytest.raises(ToolError) as info:
            reg.call("echo", {"tap": "x.tap", "show_values": True}, context=ctx)
        assert info.value.error_type == "forbidden"
        assert "--allow-values" in info.value.hint
        assert reg.call("echo", {"tap": "x.tap"}, context=ctx)["params"]["show_values"] is False

    def test_show_values_allowed_by_default_context(self, tmp_path):
        reg = Registry()
        reg.register(_spec())
        assert ToolContext().allow_values is True
        out = reg.call("echo", {"tap": "x.tap", "show_values": True},
                       context=ToolContext(root=tmp_path))
        assert out["params"]["show_values"] is True

    def test_duplicate_name_rejected(self):
        reg = Registry()
        reg.register(_spec())
        with pytest.raises(ValueError):
            reg.register(_spec())

    def test_unknown_tool_hint(self):
        reg = Registry()
        reg.register(_spec("get_digest"))
        with pytest.raises(ToolError) as info:
            reg.get("get_digets")
        assert info.value.error_type == "unknown_tool"
        assert "get_digest" in info.value.hint

    def test_invalid_kind_and_long_summary(self):
        with pytest.raises(ValueError):
            ToolSpec("x", "s", {}, _echo, kind="write")
        with pytest.raises(ValueError):
            ToolSpec("x", "s" * 101, {}, _echo, kind="read")

    def test_handler_exception_is_wrapped(self):
        def boom(params, ctx):
            raise RuntimeError("kaputt")

        reg = Registry()
        reg.register(_spec(handler=boom))
        with pytest.raises(ToolError) as info:
            reg.call("echo", {"tap": "x.tap"})
        assert info.value.error_type == "runtime_error"
        assert info.value.exit_code == EXIT_RUNTIME_ERROR
        assert info.value.error == "RuntimeError: kaputt"

    def test_non_dict_result_is_runtime_error(self):
        reg = Registry()
        reg.register(_spec(handler=lambda p, c: [1]))
        with pytest.raises(ToolError) as info:
            reg.call("echo", {"tap": "x.tap"})
        assert info.value.error_type == "runtime_error"

    def test_call_caps_response(self):
        reg = Registry()
        reg.register(_spec(handler=lambda p, c: {"rows": ["x" * 100] * 100}))
        out = reg.call("echo", {"tap": "x.tap"}, context=ToolContext(max_response_bytes=1000))
        assert out["truncated"] is True and json_size(out) <= 1000

    def test_lazy_loader_runs_once(self, tmp_path, monkeypatch):
        (tmp_path / "fake_tools_mod.py").write_text(
            "from friTap.agent_api import ToolSpec\n"
            "CALLS = []\n"
            "def register_all(reg):\n"
            "    CALLS.append(1)\n"
            "    reg.register(ToolSpec('t', 's', {}, lambda p, c: {}, kind='discover'))\n"
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        reg = Registry(loader="fake_tools_mod")
        assert reg.names() == ["t"] and reg.names() == ["t"]
        import fake_tools_mod
        assert fake_tools_mod.CALLS == [1]

    def test_default_registry_loads(self):
        assert isinstance(registry.names(), list)
        assert isinstance(list_tools(), list)


# ----------------------------------------------------------------------- schema

class TestSchema:
    def test_object_schema_shape(self):
        assert READ_SCHEMA["additionalProperties"] is False
        assert READ_SCHEMA["oneOf"] == [{"required": ["tap"]}, {"required": ["session_id"]}]
        json.dumps(READ_SCHEMA)

    def test_enum(self):
        assert validate(READ_SCHEMA, {"tap": "a", "fmt": "markdown"})["fmt"] == "markdown"
        err = _bad_param(validate, READ_SCHEMA, {"tap": "a", "fmt": "markdwn"})
        assert "markdown" in err.hint

    def test_bounds(self):
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "limit": 0})
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "limit": 201})
        assert validate(READ_SCHEMA, {"tap": "a", "limit": 200})["limit"] == 200

    def test_types(self):
        _bad_param(validate, READ_SCHEMA, {"tap": 5})
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "limit": "5"})
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "limit": 5.0})
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "show_values": "yes"})
        _bad_param(validate, READ_SCHEMA, {"tap": ""})
        _bad_param(validate, READ_SCHEMA, ["tap"])

    def test_bool_is_not_int(self):
        err = _bad_param(validate, READ_SCHEMA, {"tap": "a", "limit": True})
        assert err.extra["param"] == "limit"

    def test_array_items(self):
        assert validate(READ_SCHEMA, {"tap": "a", "tags": ["a", "b"]})["tags"] == ["a", "b"]
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "tags": ["c"]})
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "tags": "a"})

    def test_cursor_pattern(self):
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "cursor": "abc"})

    def test_unknown_key_hint(self):
        err = _bad_param(validate, READ_SCHEMA, {"tap": "a", "protocl": "tls"})
        assert "protocol" in err.hint

    def test_one_of_required(self):
        err = _bad_param(validate, READ_SCHEMA, {})
        assert "tap" in err.error and "session_id" in err.error
        _bad_param(validate, READ_SCHEMA, {"tap": "a", "session_id": "s1"})
        assert validate(READ_SCHEMA, {"session_id": "s1"})["session_id"] == "s1"

    def test_any_of_and_required(self):
        schema = {"type": "object", "properties": {"a": {}, "b": {}},
                  "required": ["a"], "anyOf": [{"required": ["a"]}, {"required": ["b"]}]}
        assert validate(schema, {"a": 1, "b": 2}) == {"a": 1, "b": 2}
        _bad_param(validate, schema, {"b": 2})

    def test_none_counts_as_absent_and_input_untouched(self):
        params = {"tap": "a", "limit": None}
        assert validate(READ_SCHEMA, params)["limit"] == 50
        assert params == {"tap": "a", "limit": None}


# ----------------------------------------------------------------------- errors

class TestErrors:
    def test_to_dict(self):
        err = ToolError("boom", "bad_param", hint="h", param="x")
        assert err.to_dict() == {"error": "boom", "error_type": "bad_param", "hint": "h",
                                 "exit_code": EXIT_USAGE_ERROR, "param": "x"}
        assert "hint" not in ToolError("boom", "bad_param").to_dict()

    def test_passthrough(self):
        err = ToolError("x", "forbidden")
        assert wrap(err) is err

    def test_filter_syntax_error(self):
        from friTap.filter.errors import FilterSyntaxError

        err = wrap(FilterSyntaxError("unexpected token", 4))
        assert err.error_type == "bad_filter" and err.extra["position"] == 4

    def test_unknown_field_error_from_real_parser(self):
        from friTap.filter import FilterEngine
        from friTap.filter.errors import UnknownFieldError

        with pytest.raises(UnknownFieldError) as info:
            FilterEngine("http.hots == 1")
        err = wrap(info.value)
        assert err.error_type == "bad_filter"
        assert err.hint and "http.host" in err.hint

    @pytest.mark.parametrize("expression,suggested", [
        ('http.host contians "x"', "contains"),
        ('http.host matchs "x"', "matches"),
        ('http.host contains "x" adn tls', "and"),
        ('http.host = "x"', "=="),
    ])
    def test_operator_typo_gets_did_you_mean(self, expression, suggested):
        from friTap.filter import FilterEngine
        from friTap.filter.errors import FilterSyntaxError

        with pytest.raises(FilterSyntaxError) as info:
            FilterEngine(expression)
        err = wrap(info.value)
        assert err.error_type == "bad_filter"
        assert err.hint.startswith("did you mean: " + suggested)

    def test_unrelated_unexpected_token_has_no_hint(self):
        from friTap.filter import FilterEngine
        from friTap.filter.errors import FilterSyntaxError

        with pytest.raises(FilterSyntaxError) as info:
            FilterEngine('http.host xyzzy "x"')
        assert wrap(info.value).hint is None

    def test_flow_ref_error(self):
        from friTap.analysis.digest_flow import FlowRefError

        assert wrap(FlowRefError("no flow f9")).error_type == "bad_ref"

    def test_os_errors(self):
        assert wrap(FileNotFoundError("gone")).error_type == "not_found"
        assert wrap(PermissionError("no")).error_type == "forbidden"

    def test_other_is_runtime(self):
        err = wrap(KeyError("k"))
        assert err.error_type == "runtime_error" and err.exit_code == EXIT_RUNTIME_ERROR
        assert err.error.startswith("KeyError: ")


# ------------------------------------------------------------------------ paths

class TestPaths:
    @pytest.fixture
    def root(self, tmp_path):
        root = tmp_path / "root"
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "a.tap").write_bytes(b"x")
        (tmp_path / "secret.tap").write_bytes(b"x")
        return root

    def _error_type(self, *args, **kw):
        with pytest.raises(ToolError) as info:
            resolve_under_root(*args, **kw)
        return info.value.error_type

    def test_inside_ok(self, root):
        got = resolve_under_root("sub/a.tap", root, suffix=".tap")
        assert got == (root / "sub" / "a.tap").resolve()
        assert resolve_under_root(str(root / "sub" / "a.tap"), root) == got

    def test_dotdot_escape(self, root):
        assert self._error_type("../secret.tap", root) == "forbidden"
        assert self._error_type("sub/../../secret.tap", root) == "forbidden"

    def test_symlink_escape(self, root):
        os.symlink(root.parent / "secret.tap", root / "link.tap")
        assert self._error_type("link.tap", root) == "forbidden"

    def test_suffix(self, root):
        assert self._error_type("sub/a.tap", root, suffix=".pcap") == "bad_param"

    def test_missing(self, root):
        assert self._error_type("nope.tap", root) == "not_found"
        assert resolve_under_root("new.tap", root, must_exist=False).name == "new.tap"

    def test_empty(self, root):
        assert self._error_type("", root) == "bad_param"


# --------------------------------------------------------------------- envelope

class TestEnvelope:
    def test_ok(self):
        from friTap.analysis.digest import UNTRUSTED_NOTICE

        assert ok("fritap.x/1", {"a": 1}) == {"schema": "fritap.x/1", "a": 1}
        assert ok("fritap.x/1", {}, notice=True)["notice"] == UNTRUSTED_NOTICE

    def test_paginate_round_trip(self):
        rows = list(range(7))
        seen, cursor = [], None
        while True:
            page, cursor = paginate(rows, 3, cursor)
            seen.extend(page)
            if cursor is None:
                break
        assert seen == rows

    def test_paginate_edges(self):
        assert paginate([], 5, None) == ([], None)
        assert paginate([1, 2], 2, "2") == ([], None)

    @pytest.mark.parametrize("cursor", ["abc", "-1", "1.5", "99", "٣"])
    def test_bad_cursor(self, cursor):
        _bad_param(paginate, [1, 2, 3], 2, cursor)

    def test_cap_response_fits_unchanged(self):
        doc = {"a": [1, 2]}
        assert cap_response(doc, 1000) is doc

    def test_cap_response_trims_largest_list(self):
        doc = {"schema": "s", "small": [1, 2], "inner": {"big": ["y" * 50] * 200}}
        out = cap_response(doc, 2000)
        assert json_size(out) <= 2000
        assert out["truncated"] is True and out["truncated_fields"] == ["inner.big"]
        assert out["small"] == [1, 2] and len(doc["inner"]["big"]) == 200

    def test_cap_response_deterministic(self):
        doc = {"a": ["x" * 30] * 100, "b": ["z" * 30] * 90}
        assert cap_response(doc, 1500) == cap_response(doc, 1500)


# ---------------------------------------------------------------------------
# page_params / compact listing defaults
# ---------------------------------------------------------------------------

def test_page_params_default_and_bounds():
    from friTap.agent_api.schema import MAX_PAGE_LIMIT, page_params
    assert page_params(20)["limit"]["default"] == 20
    assert page_params(20)["limit"]["maximum"] == MAX_PAGE_LIMIT
    assert page_params()["limit"]["default"] == 50
    for bad in (0, MAX_PAGE_LIMIT + 1):
        with pytest.raises(AssertionError):
            page_params(bad)


def test_endpoints_and_findings_default_to_compact_page():
    from friTap.agent_api.registry import registry
    from friTap.agent_api.schema import COMPACT_PAGE_LIMIT, MAX_PAGE_LIMIT
    for tool in ("list_endpoints", "list_findings"):
        limit = registry.get(tool).params_schema["properties"]["limit"]
        assert (limit["default"], limit["maximum"]) == (COMPACT_PAGE_LIMIT, MAX_PAGE_LIMIT) == (20, 200)
