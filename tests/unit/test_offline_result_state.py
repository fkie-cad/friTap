"""Protocol-neutral ``ConvertResult`` / ``WriterState`` (WS2).

Pins the frozen v1 JSON shape of :meth:`ConvertResult.to_dict` (key order and
values), the read-only flat-counter properties, the generic
``record_protocol(prefix, **counters)`` merge, the registered per-protocol
writer-state namespaces (with legacy attribute routing and stand-in fallback),
the TUI's flat-counter fallback, and that ``pipeline_api`` names no protocol.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import pathlib
from types import SimpleNamespace

import pytest

from friTap.flow.tap_writer import TapWriter
from friTap.offline import (
    pcap_to_tap,  # noqa: F401 - registers the protocol packages
    pipeline_api,
)
from friTap.offline.mtproto.state import TELEGRAM_STATE, TelegramPipelineState
from friTap.offline.pipeline_api import (
    ConvertResult,
    WriterState,
    protocol_state_of,
    register_protocol_state,
)
from friTap.offline.rc4.state import RC4_STATE, Rc4PipelineState
from friTap.offline.result_schema import V1_BUCKET_DEFAULTS, V1_FLAT_COUNTERS

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

V1_KEY_ORDER = [
    "tap_path", "flow_count", "decrypted_packet_count", "stream_count",
    "dropped_packet_count", "dropped_stream_count", "findings_count",
    "encrypted_streams_skipped",
    "mtproto_messages", "mtproto_streams", "mtproto_records_undecryptable",
    "mtproto_streams_degraded",
    "per_protocol",
]

V1_BUCKET_KEY_ORDER = [
    "messages", "streams", "undecryptable", "degraded", "degraded_non_mtproto",
    "partial", "recovered_via_obf", "degraded_unrecovered", "short",
    "unsupported_framing", "e2e_only", "unknown_key_ids",
]


def _writer_state() -> WriterState:
    return WriterState(TapWriter(), "x.tap", "t", None)


# --------------------------------------------------------------------------- #
# ConvertResult: v1 JSON shape
# --------------------------------------------------------------------------- #

def test_to_dict_key_order_is_the_frozen_v1_layout():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("mtproto", messages=2, streams=1, undecryptable=3, degraded=4)
    data = result.to_dict()
    assert list(data) == V1_KEY_ORDER
    assert [data[name] for name, _p, _k in V1_FLAT_COUNTERS] == [2, 1, 3, 4]
    # Exact serialized bytes (unsorted, as a web/API caller would dump them).
    assert json.dumps(data) == (
        '{"tap_path": "out.tap", "flow_count": 0, "decrypted_packet_count": 0, '
        '"stream_count": 0, "dropped_packet_count": 0, "dropped_stream_count": 0, '
        '"findings_count": 0, "encrypted_streams_skipped": 0, "mtproto_messages": 2, '
        '"mtproto_streams": 1, "mtproto_records_undecryptable": 3, '
        '"mtproto_streams_degraded": 4, "per_protocol": {"mtproto": {"messages": 2, '
        '"streams": 1, "undecryptable": 3, "degraded": 4, "degraded_non_mtproto": 0, '
        '"partial": 0, "recovered_via_obf": 0, "degraded_unrecovered": 0, "short": 0, '
        '"unsupported_framing": 0, "e2e_only": false, "unknown_key_ids": {}}}}'
    )


def test_to_dict_is_a_deep_copy():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("rc4", unknown_key_ids={"aa": 1})
    data = result.to_dict()
    data["per_protocol"]["rc4"]["unknown_key_ids"]["aa"] = 99
    assert result.per_protocol["rc4"]["unknown_key_ids"] == {"aa": 1}


def test_schema_tables_are_the_v1_layout():
    assert list(V1_BUCKET_DEFAULTS) == V1_BUCKET_KEY_ORDER
    assert V1_BUCKET_DEFAULTS["e2e_only"] is False
    assert V1_BUCKET_DEFAULTS["unknown_key_ids"] == {}
    assert [name for name, _p, _k in V1_FLAT_COUNTERS] == V1_KEY_ORDER[8:12]


# The import-free-leaf check for result_schema lives in
# test_architecture_layering.py (rule R7, IMPORT_FREE_MODULES).


# --------------------------------------------------------------------------- #
# ConvertResult: flat-counter properties
# --------------------------------------------------------------------------- #

def test_flat_counters_are_views_of_the_bucket():
    result = ConvertResult(tap_path="out.tap")
    assert (result.mtproto_messages, result.mtproto_streams,
            result.mtproto_records_undecryptable, result.mtproto_streams_degraded) == (0, 0, 0, 0)
    for _ in range(2):
        result.record_protocol("mtproto", messages=3, streams=1, undecryptable=2, degraded=4)
    assert (result.mtproto_messages, result.mtproto_streams,
            result.mtproto_records_undecryptable, result.mtproto_streams_degraded) == (6, 2, 4, 8)
    # Other prefixes never leak into the flat counters.
    result.record_protocol("telegram", messages=100)
    assert result.mtproto_messages == 6


def test_flat_counters_are_read_only_and_not_fields():
    result = ConvertResult(tap_path="out.tap")
    with pytest.raises(AttributeError):
        result.mtproto_messages = 5
    field_names = {f.name for f in dataclasses.fields(ConvertResult)}
    assert not field_names & {name for name, _p, _k in V1_FLAT_COUNTERS}
    with pytest.raises(TypeError):
        ConvertResult(tap_path="out.tap", mtproto_messages=1)


# --------------------------------------------------------------------------- #
# ConvertResult: generic record_protocol merge
# --------------------------------------------------------------------------- #

def test_rc4_bucket_carries_all_twelve_v1_keys():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("rc4", messages=2, streams=1, undecryptable=0, degraded=0)
    bucket = result.per_protocol["rc4"]
    assert list(bucket) == V1_BUCKET_KEY_ORDER
    assert bucket == {**V1_BUCKET_DEFAULTS, "messages": 2, "streams": 1}


def test_new_buckets_never_share_the_mutable_defaults():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("a", unknown_key_ids={"k": 1})
    result.record_protocol("b")
    assert result.per_protocol["b"]["unknown_key_ids"] == {}
    assert V1_BUCKET_DEFAULTS["unknown_key_ids"] == {}


def test_generic_merge_semantics():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("p", messages=1, e2e_only=True, unknown_key_ids={"aa": 1})
    result.record_protocol("p", messages=2, e2e_only=False,
                           unknown_key_ids={"aa": 2, "bb": 1}, short=None)
    bucket = result.per_protocol["p"]
    assert bucket["messages"] == 3
    assert bucket["e2e_only"] is True  # latched (OR), stays a bool
    assert bucket["unknown_key_ids"] == {"aa": 3, "bb": 1}
    assert list(bucket["unknown_key_ids"]) == ["aa", "bb"]
    assert bucket["short"] == 0  # None is skipped
    # A counter outside the v1 defaults becomes a new key; floats add.
    result.record_protocol("p", latency=1.5)
    result.record_protocol("p", latency=2.0)
    assert bucket["latency"] == 3.5
    assert list(bucket)[-1] == "latency"


def test_bool_checked_before_int_keeps_v1_types():
    result = ConvertResult(tap_path="out.tap")
    result.record_protocol("p", e2e_only=0)
    assert result.per_protocol["p"]["e2e_only"] is False  # not turned into 0
    result.record_protocol("p", e2e_only=1)
    assert result.per_protocol["p"]["e2e_only"] is True


def test_unsupported_counter_types_raise():
    result = ConvertResult(tap_path="out.tap")
    with pytest.raises(TypeError):
        result.record_protocol("p", messages="3")
    with pytest.raises(TypeError):
        result.record_protocol("p", unknown_key_ids=5)
    with pytest.raises(TypeError):
        result.record_protocol("p", messages={"a": 1})
    with pytest.raises(TypeError):
        result.record_protocol("p", brand_new=["x"])


# --------------------------------------------------------------------------- #
# WriterState protocol namespaces
# --------------------------------------------------------------------------- #

def test_registered_namespaces_have_the_historical_defaults():
    state = _writer_state()
    telegram = state.protocol_state(TELEGRAM_STATE)
    assert isinstance(telegram, TelegramPipelineState)
    assert (telegram.mtproto_meta, telegram.telegram_e2e_meta, telegram.telegram_emitted,
            telegram.telegram_ledger, telegram.telegram_refs,
            telegram.telegram_record_seq) == ({}, {}, set(), None, None, 0)
    rc4 = state.protocol_state(RC4_STATE)
    assert isinstance(rc4, Rc4PipelineState) and rc4.rc4_provenance == {}
    # Generic side channels stay on the writer state itself.
    assert state.inner_meta == {} and state.tls_spans == {}


def test_legacy_attributes_alias_the_namespace():
    state = _writer_state()
    telegram = protocol_state_of(state, TELEGRAM_STATE)
    assert telegram is state.protocol_state(TELEGRAM_STATE)  # same object every time
    assert state.mtproto_meta is telegram.mtproto_meta
    state.telegram_record_seq = 5
    assert telegram.telegram_record_seq == 5
    assert "telegram_record_seq" not in vars(state)
    state.rc4_provenance["k"] = [1]
    assert protocol_state_of(state, RC4_STATE).rc4_provenance == {"k": [1]}
    # Namespaces are per writer state (per conversion).
    assert _writer_state().protocol_state(TELEGRAM_STATE) is not telegram


def test_unknown_and_private_attributes_are_not_routed():
    state = _writer_state()
    with pytest.raises(AttributeError):
        state.no_such_attribute
    with pytest.raises(AttributeError):
        state._no_such_private
    assert getattr(state, "no_such_attribute", None) is None
    state.ad_hoc = 1  # unclaimed names still land on the writer state
    assert vars(state)["ad_hoc"] == 1
    with pytest.raises(KeyError):
        state.protocol_state("never_registered")


def test_stand_ins_resolve_to_themselves():
    stand_in = SimpleNamespace(mtproto_meta={})
    assert protocol_state_of(stand_in, TELEGRAM_STATE) is stand_in
    # Even a stand-in carrying a ``protocol_state`` instance attribute: only the
    # TYPE decides.
    odd = SimpleNamespace(protocol_state=lambda name: "nope")
    assert protocol_state_of(odd, RC4_STATE) is odd


def test_register_protocol_state_guards(monkeypatch):
    monkeypatch.setattr(pipeline_api, "_PROTOCOL_STATE_FACTORIES",
                        dict(pipeline_api._PROTOCOL_STATE_FACTORIES))
    monkeypatch.setattr(pipeline_api, "_LEGACY_ATTR_OWNERS",
                        dict(pipeline_api._LEGACY_ATTR_OWNERS))
    with pytest.raises(ValueError):
        register_protocol_state("other", dict, ("mtproto_meta",))
    with pytest.raises(ValueError):
        register_protocol_state("other", dict, ("_private",))
    register_protocol_state("demo", lambda: SimpleNamespace(demo_value=7), ("demo_value",))
    register_protocol_state("demo", lambda: SimpleNamespace(demo_value=8), ("demo_value",))
    assert _writer_state().demo_value == 8  # re-registration replaces the factory


@pytest.mark.parametrize("attr", ["opened", "inner_meta", "tls_spans",
                                  "protocol_state", "ensure_open"])
def test_register_protocol_state_rejects_writer_state_names(monkeypatch, attr):
    monkeypatch.setattr(pipeline_api, "_PROTOCOL_STATE_FACTORIES",
                        dict(pipeline_api._PROTOCOL_STATE_FACTORIES))
    monkeypatch.setattr(pipeline_api, "_LEGACY_ATTR_OWNERS",
                        dict(pipeline_api._LEGACY_ATTR_OWNERS))
    with pytest.raises(ValueError, match="WriterState attribute"):
        register_protocol_state("hijack", SimpleNamespace, (attr,))
    assert "hijack" not in pipeline_api._PROTOCOL_STATE_FACTORIES
    assert attr not in pipeline_api._LEGACY_ATTR_OWNERS


def test_writer_state_own_attrs_cover_every_public_instance_attribute():
    """The guard's instance-attribute list must track WriterState.__init__."""
    public = {name for name in vars(_writer_state()) if not name.startswith("_")}
    assert public <= pipeline_api._WRITER_STATE_OWN_ATTRS


# --------------------------------------------------------------------------- #
# TUI flat-counter fallback
# --------------------------------------------------------------------------- #

def test_tui_counts_mtproto_once_and_falls_back_for_stand_ins():
    from friTap.tui.screens.main_screen import MainScreen

    result = ConvertResult(tap_path="x.tap")
    result.record_protocol("mtproto", degraded=2, undecryptable=3)
    assert MainScreen._degraded_stream_count(result) == 2
    assert MainScreen._undecryptable_record_count(result) == 3
    stand_in = SimpleNamespace(mtproto_streams_degraded=3, mtproto_records_undecryptable=4)
    assert MainScreen._degraded_stream_count(stand_in) == 3
    assert MainScreen._undecryptable_record_count(stand_in) == 4
    assert MainScreen._short_stream_count(stand_in) == 0


def test_tui_drops_the_nonexistent_legacy_names():
    source = (REPO_ROOT / "friTap/tui/screens/main_screen.py").read_text()
    for bogus in ("mtproto_streams_recovered_via_obf",
                  "mtproto_streams_degraded_unrecovered",
                  "mtproto_streams_short"):
        assert bogus not in source


# --------------------------------------------------------------------------- #
# Layering: pipeline_api names no protocol
# --------------------------------------------------------------------------- #

def _identifiers(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.arg):
            yield node.arg
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.keyword) and node.arg:
            yield node.arg
        elif isinstance(node, ast.alias):
            yield node.name
            if node.asname:
                yield node.asname
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def test_pipeline_api_names_no_protocol():
    tree = ast.parse((REPO_ROOT / "friTap/offline/pipeline_api.py").read_text())
    offenders = sorted({
        ident for ident in _identifiers(tree)
        if any(word in ident.lower() for word in ("mtproto", "telegram", "rc4"))
    })
    assert offenders == []
