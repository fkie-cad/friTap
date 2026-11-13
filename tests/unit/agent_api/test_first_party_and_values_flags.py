"""``first_party`` string normalization and the ``find_values --values`` CLI shorthand.

Regression tests for two agent-API bugs:

* a non-``"auto"`` ``first_party`` string (``--first-party myapp.com``) was
  iterated character by character into a set of one-letter "domains";
* ``fritap q find_values --values ...`` always failed with ``bad_param``
  because the generated flag produced strings where the schema wanted objects.

Offline: synthetic ``.tap`` fixtures from :mod:`tests.unit._digest_helpers`.
"""

from __future__ import annotations

import io
import json

import pytest

from friTap.agent_api import tools_read
from friTap.agent_api.adapters import cli
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry
from friTap.agent_api.schema import check_value
from friTap.analysis.attribution import normalize_first_party
from friTap.analysis.canary import canary_spec_from_text, parse_canaries
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
def leak_tap(tmp_path):
    _write_tap(tmp_path / "leak.tap",
               [_http_flow("u", url=f"/signup?email={EMAIL}", body=_json_body())])
    return tmp_path / "leak.tap"


def _run_q(registry, root, tokens):
    out = io.StringIO()
    code = cli.QueryCli(registry, out, io.StringIO()).run(["--root", str(root), *tokens])
    return code, json.loads(out.getvalue())


# ---------------------------------------------------------------------------
# normalize_first_party
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("given, expected", [
    ("myapp.com", ["myapp.com"]),
    ("a.com,b.com", ["a.com", "b.com"]),
    (" a.com , ,b.com, ", ["a.com", "b.com"]),
    ("auto", "auto"),
    (["a.com", "b.com"], ["a.com", "b.com"]),
    (("a.com",), ["a.com"]),
    ([" a.com ", ""], ["a.com"]),
    (None, None),
])
def test_normalize_first_party(given, expected):
    assert normalize_first_party(given) == expected


def test_normalize_first_party_never_splits_into_characters():
    assert normalize_first_party("myapp.com") != list("myapp.com")


# ---------------------------------------------------------------------------
# Validation of the first_party property (property-level anyOf)
# ---------------------------------------------------------------------------

def test_first_party_schema_accepts_list_and_string():
    prop = tools_read.first_party_param("Domains", "to infer them")
    for value in (["a.com"], "a.com,b.com", "auto"):
        check_value("first_party", value, prop)
    assert "comma-separated" in prop["description"]


@pytest.mark.parametrize("bad", [5, {"a": 1}, "", [1]])
def test_first_party_schema_rejects_other_shapes(bad):
    prop = tools_read.first_party_param("Domains", "to infer them")
    with pytest.raises(ToolError) as info:
        check_value("first_party", bad, prop)
    assert info.value.error_type == "bad_param"


# ---------------------------------------------------------------------------
# get_digest / diff through the registry (MCP/REST-style string params)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("first_party, expected", [
    ("example.com", ["example.com"]),
    ("example.com, other.org", ["example.com", "other.org"]),
    (["example.com"], ["example.com"]),
])
def test_get_digest_first_party_string_is_domain_list(registry, leak_tap, first_party,
                                                      expected):
    ctx = ToolContext(root=leak_tap.parent)
    doc = registry.call("get_digest", {"tap": "leak.tap", "first_party": first_party},
                        context=ctx)
    assert doc["params"]["first_party"] == expected


def test_get_digest_first_party_auto_still_infers(registry, tmp_path):
    _write_tap(tmp_path / "app.tap", [_http_flow("u", host="api.myapp.io")])
    doc = registry.call("get_digest", {"tap": "app.tap", "first_party": "auto"},
                        context=ToolContext(root=tmp_path))
    assert doc["params"]["first_party"] == ["myapp.io"]


def test_get_digest_first_party_string_marks_host_first_party(registry, leak_tap):
    ctx = ToolContext(root=leak_tap.parent)
    doc = registry.call("get_digest", {"tap": "leak.tap", "first_party": "example.com"},
                        context=ctx)
    hosts = [host for section in doc["protocols"].values() for host in section["hosts"]]
    assert hosts and all(host["party"] == "first" for host in hosts)


def test_diff_classifier_accepts_comma_string():
    classify = tools_read._diff_classifier("example.com,other.org", lambda: {})
    assert classify("api.example.com")["party"] == "first"
    assert classify("cdn.other.org")["party"] == "first"


# ---------------------------------------------------------------------------
# fritap q --first-party (end to end through the CLI adapter)
# ---------------------------------------------------------------------------

def test_cli_get_digest_first_party_comma_list(registry, leak_tap):
    code, doc = _run_q(registry, leak_tap.parent,
                       ["get_digest", "--tap", "leak.tap", "--first-party", "example.com,b.org"])
    assert code == 0
    assert doc["params"]["first_party"] == ["example.com", "b.org"]


def test_cli_get_digest_first_party_single_domain(registry, leak_tap):
    code, doc = _run_q(registry, leak_tap.parent,
                       ["get_digest", "--tap", "leak.tap", "--first-party", "example.com"])
    assert code == 0
    assert doc["params"]["first_party"] == ["example.com"]


# ---------------------------------------------------------------------------
# find_values shorthand
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("alice@example.com", {"value": "alice@example.com", "kind": "free", "label": "free-1"}),
    ("email=alice@example.com", {"value": "alice@example.com", "kind": "email",
                                 "label": "email-1"}),
    ("EMAIL=a@b.c", {"value": "a@b.c", "kind": "email", "label": "email-1"}),
    ("geo=48.137,11.575", {"value": "48.137,11.575", "kind": "gps", "label": "gps-1"}),
    ("ip=fe80::1", {"value": "fe80::1", "kind": "ip", "label": "ip-1"}),
    ("fe80::1", {"value": "fe80::1", "kind": "free", "label": "free-1"}),
    ("https://x.io/?a=b", {"value": "https://x.io/?a=b", "kind": "free", "label": "free-1"}),
    ("token=abc", {"value": "token=abc", "kind": "free", "label": "free-1"}),
    ("email=", {"value": "email=", "kind": "free", "label": "free-1"}),
])
def test_canary_spec_from_text(text, expected):
    assert canary_spec_from_text(text, 1) == expected


def test_parse_canaries_accepts_strings_and_objects():
    canaries = parse_canaries(["email=a@b.example", "plain-value-123",
                               {"value": "x", "kind": "free", "label": "mine"}])
    assert [(c.kind, c.label) for c in canaries] == [
        ("email", "email-1"), ("free", "free-2"), ("free", "mine")]


def test_find_values_string_items_via_registry(registry, leak_tap):
    ctx = ToolContext(root=leak_tap.parent)
    doc = registry.call("find_values", {"tap": "leak.tap", "values": [f"email={EMAIL}"]},
                        context=ctx)
    assert doc["summary"]["by_label"]["email-1"] >= 1


def test_find_values_rejects_non_string_non_object_items(registry, leak_tap):
    ctx = ToolContext(root=leak_tap.parent)
    with pytest.raises(ToolError) as info:
        registry.call("find_values", {"tap": "leak.tap", "values": [5]}, context=ctx)
    assert info.value.error_type == "bad_param"


# ---------------------------------------------------------------------------
# fritap q find_values --values (end to end through the CLI adapter)
# ---------------------------------------------------------------------------

def test_cli_find_values_kind_shorthand(registry, leak_tap):
    code, doc = _run_q(registry, leak_tap.parent,
                       ["find_values", "--tap", "leak.tap", "--values", f"email={EMAIL}"])
    assert code == 0
    assert doc["summary"]["by_label"]["email-1"] >= 1
    assert EMAIL not in json.dumps(doc)


def test_cli_find_values_bare_value_and_repeat(registry, leak_tap):
    code, doc = _run_q(registry, leak_tap.parent,
                       ["find_values", "--tap", "leak.tap", "--values", EMAIL,
                        "--values", "gps=48.137,11.575"])
    assert code == 0
    assert doc["summary"]["canaries"] == 2  # the GPS comma is not a list separator
    assert doc["summary"]["by_label"]["free-1"] >= 1


def test_cli_find_values_json_object_item(registry, leak_tap):
    item = json.dumps({"value": EMAIL, "kind": "email", "label": "signup"})
    code, doc = _run_q(registry, leak_tap.parent,
                       ["find_values", "--tap", "leak.tap", "--values", item])
    assert code == 0
    assert doc["summary"]["by_label"]["signup"] >= 1


def test_cli_find_values_bad_json_item_is_bad_param(registry, leak_tap):
    code, doc = _run_q(registry, leak_tap.parent,
                       ["find_values", "--tap", "leak.tap", "--values", "{not json"])
    assert code != 0 and doc["error_type"] == "bad_param"


def test_cli_find_values_json_flag_still_works(registry, leak_tap):
    params = {"values": [{"value": EMAIL, "kind": "email", "label": "signup"}]}
    code, doc = _run_q(registry, leak_tap.parent,
                       ["find_values", "--tap", "leak.tap", "--json", json.dumps(params)])
    assert code == 0
    assert doc["summary"]["by_label"]["signup"] >= 1


# ---------------------------------------------------------------------------
# Generic CLI behaviour for arrays
# ---------------------------------------------------------------------------

def test_items_allow_objects():
    assert cli.items_allow_objects({"type": "object"})
    assert cli.items_allow_objects({"anyOf": [{"type": "object"}, {"type": "string"}]})
    assert not cli.items_allow_objects({"type": "string"})


def test_scalar_arrays_still_split_on_commas():
    assert cli._split_array("fields", ["a,b", "c"], {"type": "string"}) == ["a", "b", "c"]


def test_object_arrays_take_one_item_per_flag():
    items = {"anyOf": [{"type": "object"}, {"type": "string"}]}
    assert cli._split_array("values", ["a,b", '{"k": 1}'], items) == ["a,b", {"k": 1}]
