"""Hardening of the runtime layer-field registry (review fix F2).

* malformed specs are rejected before they touch any index;
* ``_rebuild_indexes`` is transactional and a failed change rolls back;
* protocol-predicate names and ``protocol.<x>`` names cannot be registered;
* the filter-help grid survives a non-str description;
* ``friTap.filter.fields`` treats a cache entry from an older layer-field
  generation as a miss.
"""

from __future__ import annotations

import pytest

from friTap.filter import fields
from friTap.filter import layer_fields as lf
from friTap.filter.layer_fields import (
    LayerFieldSpec,
    clear_registered_layer_fields,
    layer_field_spec,
    layer_fields_generation,
    register_layer_field,
)
from friTap.filter.protocols import known_protocol_names

_GOOD = LayerFieldSpec("acme.token", ("acme",), "auth.token", "str", "Acme token")


def _state():
    return (lf.all_layer_field_specs(), dict(lf._SPECS_BY_NAME), lf._EXTRACTED_SPECS,
            dict(lf._SCALAR_ROOTS_BY_LAYER), dict(lf._REGISTERED_SPECS),
            layer_fields_generation())


_BAD_SPECS = [
    (LayerFieldSpec("acme.empty", ("acme",), "", "str"), ValueError),
    (LayerFieldSpec("acme.bare", "acme", "token", "str"), TypeError),  # type: ignore[arg-type]
    (LayerFieldSpec("acme.mixed", ("acme", 3), "token", "str"), TypeError),  # type: ignore[arg-type]
    (LayerFieldSpec("acme.blob", ("acme",), "token", "bytes"), ValueError),
    (LayerFieldSpec("acme.desc", ("acme",), "token", "str", 42), TypeError),  # type: ignore[arg-type]
]


# -- 1a: validation -----------------------------------------------------------

@pytest.mark.parametrize("spec,error", _BAD_SPECS)
def test_bad_spec_rejected_and_state_unchanged(spec, error):
    before = _state()
    with pytest.raises(error):
        register_layer_field(spec)
    assert _state() == before
    assert layer_field_spec(spec.field) is None


def test_str_layers_message_is_clear():
    with pytest.raises(TypeError, match="tuple or list"):
        register_layer_field(LayerFieldSpec("acme.x", "tls", "sni", "str"))  # type: ignore[arg-type]


def test_list_layers_accepted_and_lowercased():
    stored = register_layer_field(LayerFieldSpec("acme.x", ["ACME"], "x", "int"))  # type: ignore[arg-type]
    assert stored.layers == ("acme",)


def test_union_spec_without_path_still_allowed():
    register_layer_field(_GOOD)
    union = register_layer_field(
        LayerFieldSpec("acme.any", (), "", "str", union_of=("acme.token",)))
    assert layer_field_spec("acme.any") is union


@pytest.mark.parametrize("spec,error", _BAD_SPECS)
def test_valid_registration_after_rejected_one_works(spec, error):
    with pytest.raises(error):
        register_layer_field(spec)
    stored = register_layer_field(_GOOD)
    assert layer_field_spec("acme.token") is stored
    assert lf._SCALAR_ROOTS_BY_LAYER["acme"] == ("auth",)
    assert fields.get_field("acme.token").value_type == "str"


# -- 1b: transactional rebuild ------------------------------------------------

def test_failure_inside_rebuild_rolls_back(monkeypatch):
    register_layer_field(_GOOD)
    before = _state()

    def boom(extracted=None):
        raise RuntimeError("forced")

    monkeypatch.setattr(lf, "_scalar_roots_by_layer", boom)
    with pytest.raises(RuntimeError, match="forced"):
        register_layer_field(LayerFieldSpec("acme.other", ("acme",), "o", "str"))
    assert _state() == before
    monkeypatch.undo()
    assert register_layer_field(LayerFieldSpec("acme.other", ("acme",), "o", "str"))
    assert layer_field_spec("acme.other") is not None


def test_failure_during_clear_rolls_back(monkeypatch):
    register_layer_field(_GOOD)
    before = _state()
    monkeypatch.setattr(lf, "_scalar_roots_by_layer",
                        lambda extracted=None: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        clear_registered_layer_fields()
    assert _state() == before
    monkeypatch.undo()  # before the autouse fixture's teardown clear


def test_generation_bumps_only_on_successful_rebuild():
    start = layer_fields_generation()
    register_layer_field(_GOOD)
    assert layer_fields_generation() == start + 1
    with pytest.raises(ValueError):
        register_layer_field(LayerFieldSpec("acme.empty", ("acme",), "", "str"))
    assert layer_fields_generation() == start + 1


# -- 3: protocol predicate names ---------------------------------------------

@pytest.mark.parametrize("name", ["telegram", "signal", "quic", "mtproto", "bhttp"])
def test_protocol_predicate_names_rejected(name):
    assert name in known_protocol_names()
    before = _state()
    with pytest.raises(ValueError, match="protocol predicate"):
        register_layer_field(LayerFieldSpec(name, (name,), "x", "str"))
    assert _state() == before
    assert fields.get_field(name).value_type == "bool"


def test_protocol_predicate_names_rejected_case_insensitively():
    with pytest.raises(ValueError, match="protocol predicate"):
        register_layer_field(LayerFieldSpec("  BHTTP ", ("bhttp",), "x", "str"))


@pytest.mark.parametrize("name", ["protocol.acme", "protocol.signal", "PROTOCOL.x"])
def test_protocol_prefix_rejected(name):
    with pytest.raises(ValueError, match="reserved"):
        register_layer_field(LayerFieldSpec(name, ("acme",), "x", "str"))


def test_builtin_layer_field_replacement_still_allowed():
    stored = register_layer_field(LayerFieldSpec("tls.sni", ("tls",), "server_name", "str", "SNI"))
    assert layer_field_spec("tls.sni") is stored


# -- 4: dynamic-cache generation ----------------------------------------------

def test_stale_generation_cache_entry_is_a_miss():
    register_layer_field(_GOOD)
    current = fields.get_field("acme.token")
    stale = fields.FieldDef(name="acme.token", value_type="int", accessor=lambda o: ())
    # A racing get_field that resolved before the last rebuild stored this.
    fields._DYNAMIC_CACHE["acme.token"] = (layer_fields_generation() - 1, stale)
    resolved = fields.get_field("acme.token")
    assert resolved is not stale
    assert resolved.value_type == current.value_type == "str"


def test_same_generation_cache_entry_is_reused():
    first = fields.get_field("telegram")
    assert first is not None
    assert fields.get_field("telegram") is first


def test_rebuild_invalidates_cached_layer_field():
    register_layer_field(_GOOD)
    assert fields.get_field("acme.token").value_type == "str"
    register_layer_field(LayerFieldSpec("acme.token", ("acme",), "auth.token", "int"))
    assert fields.get_field("acme.token").value_type == "int"


# -- 2: filter help with a weird description ----------------------------------

def test_filter_help_survives_non_str_description(monkeypatch):
    from friTap.tui.modals import filter_help_modal as fhm

    weird = LayerFieldSpec("acme.weird", ("acme",), "w", "str", 12345)  # type: ignore[arg-type]
    monkeypatch.setattr(fhm, "all_layer_field_specs",
                        lambda: lf.all_layer_field_specs() + (weird,))
    text = fhm._build_filter_help_text(width=120)
    assert "acme.weird" in text and "12345" in text


# -- union_of validation (review fix R2) ---------------------------------------

def _union(union_of):
    return LayerFieldSpec("demo.any", ("tls",), "", "str", union_of=union_of)


@pytest.mark.parametrize("union_of,error", [
    ("demo.a", TypeError),
    (("demo.a", 3), TypeError),
    (("demo.a", "  "), ValueError),
])
def test_bad_union_of_rejected_and_state_unchanged(union_of, error):
    before = _state()
    with pytest.raises(error):
        register_layer_field(_union(union_of))
    assert _state() == before
    assert layer_field_spec("demo.any") is None


def test_mixed_case_union_members_lowercased_and_match():
    from friTap.filter import FilterEngine
    from tests.unit._display_filter_helpers import summary_row
    register_layer_field(LayerFieldSpec("demo.a", ("demo",), "a", "str"))
    register_layer_field(LayerFieldSpec("demo.b", ("demo",), "b", "str"))
    stored = register_layer_field(_union([" Demo.A", "DEMO.B"]))
    assert stored.union_of == ("demo.a", "demo.b")
    attrs = lf.extract_filter_attrs([{"name": "demo", "a": "x", "b": "y"}])
    assert FilterEngine('demo.any == "y"').matches(summary_row(attrs=attrs))
