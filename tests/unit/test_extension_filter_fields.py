"""Extension display-filter fields: registration, evaluation, help, reset.

``friTap.extensions.register_filter_field`` hands a :class:`LayerFieldSpec` to
``friTap.filter.layer_fields.register_layer_field``, which rebuilds the filter
indexes. Pure Python except the last test, which drives ``fritap -r`` (the real
``FriTapApp(replay_file=...)``) with ``asyncio.run``.
"""

from __future__ import annotations

import asyncio

import pytest

from friTap import extensions as ext
from friTap.filter import FilterEngine, UnknownFieldError, all_field_names, get_field
from friTap.filter import layer_fields as lf
from friTap.filter.layer_fields import (
    LAYER_FIELD_SPECS,
    LayerFieldSpec,
    all_layer_field_specs,
    clear_registered_layer_fields,
    extract_filter_attrs,
    layer_field_names,
    layer_field_spec,
    register_layer_field,
)
from tests.unit._display_filter_helpers import summary_row
from tests.unit._ext_helpers import FakeEntryPoint

_EXT_SPEC = LayerFieldSpec("acme.token", ("acme",), "auth.token", "str", "Acme token [x]")
_ACME_LAYER = {"name": "acme", "auth": {"token": "t-123"}, "msgs": [{"n": 1}, {"n": 2}]}


@pytest.fixture(autouse=True)
def _discovery_enabled(monkeypatch):
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)


def _builtin_snapshot():
    return (all_layer_field_specs(), dict(lf._SPECS_BY_NAME), lf._EXTRACTED_SPECS,
            dict(lf._SCALAR_ROOTS_BY_LAYER), layer_field_names())


def _matches(expr, attrs) -> bool:
    return FilterEngine(expr).matches(summary_row(attrs=attrs))


# -- layer_fields registry ----------------------------------------------------

def test_no_registration_keeps_builtins_identical():
    assert all_layer_field_specs() == LAYER_FIELD_SPECS
    assert layer_field_names() == [s.field for s in LAYER_FIELD_SPECS]


def test_register_adds_spec_and_rebuilds_every_index():
    stored = register_layer_field(_EXT_SPEC)
    assert stored == _EXT_SPEC
    assert all_layer_field_specs()[-1] is stored
    assert all_layer_field_specs()[:-1] == LAYER_FIELD_SPECS
    assert layer_field_spec("ACME.Token") is stored
    assert "acme.token" in layer_field_names()
    assert stored in lf._EXTRACTED_SPECS
    assert lf._SCALAR_ROOTS_BY_LAYER["acme"] == ("auth",)
    assert extract_filter_attrs([_ACME_LAYER]) == {"acme.token": ("t-123",)}


def test_register_normalizes_case_and_replaces_by_name():
    register_layer_field(LayerFieldSpec("Acme.Token", ("ACME",), "auth.token", "str"))
    register_layer_field(LayerFieldSpec("acme.token", ("acme",), "msgs[].n", "int"))
    registered = [s for s in all_layer_field_specs() if s.field == "acme.token"]
    assert len(registered) == 1
    assert registered[0].layers == ("acme",)
    assert extract_filter_attrs([_ACME_LAYER]) == {"acme.token": (1, 2)}


def test_registered_union_spec_resolves_its_members():
    register_layer_field(_EXT_SPEC)
    register_layer_field(LayerFieldSpec("acme.any", (), "", "str", union_of=("acme.token", "tls.sni")))
    attrs = extract_filter_attrs([_ACME_LAYER, {"name": "tls", "sni": "a.example"}])
    assert lf.lookup_attr(attrs, "acme.any") == ("t-123", "a.example")


def test_replacing_a_builtin_is_undone_by_clear():
    builtin = layer_field_spec("tls.sni")
    register_layer_field(LayerFieldSpec("tls.sni", ("tls",), "alpn", "str"))
    assert layer_field_spec("tls.sni").path == "alpn"
    assert len(all_layer_field_specs()) == len(LAYER_FIELD_SPECS)
    clear_registered_layer_fields()
    assert layer_field_spec("tls.sni") is builtin


@pytest.mark.parametrize("bad, exc", [("acme.token", TypeError),
                                      (LayerFieldSpec(" ", ("a",), "x", "str"), ValueError)])
def test_register_rejects_invalid_specs(bad, exc):
    before = _builtin_snapshot()
    with pytest.raises(exc):
        register_layer_field(bad)
    assert _builtin_snapshot() == before


# -- filter engine (parse + evaluate) -------------------------------------------

def test_registered_field_parses_and_evaluates():
    with pytest.raises(UnknownFieldError):
        FilterEngine('acme.token == "t-123"')
    ext.register_filter_field(_EXT_SPEC)
    attrs = extract_filter_attrs([_ACME_LAYER])
    assert _matches('acme.token == "t-123"', attrs)
    assert _matches('ACME.TOKEN contains "123"', attrs)
    assert _matches("acme.token", attrs)
    assert not _matches('acme.token == "nope"', attrs)
    assert not _matches("acme.token", {})
    assert "acme.token" in all_field_names()


def test_replaced_spec_is_not_served_from_the_field_cache():
    ext.register_filter_field(_EXT_SPEC)
    assert get_field("acme.token").value_type == "str"
    ext.register_filter_field(LayerFieldSpec("acme.token", ("acme",), "msgs[].n", "int"))
    assert get_field("acme.token").value_type == "int"
    assert _matches("acme.token >= 2", extract_filter_attrs([_ACME_LAYER]))


def test_reset_extensions_removes_filter_fields_and_keeps_builtins():
    before = _builtin_snapshot()
    ext.register_filter_field(_EXT_SPEC)
    FilterEngine("acme.token")  # memoizes the dynamic FieldDef
    ext.reset_extensions()
    assert ext.get_filter_fields() == []
    assert _builtin_snapshot() == before
    assert get_field("acme.token") is None
    with pytest.raises(UnknownFieldError):
        FilterEngine("acme.token")
    assert get_field("tls.sni") is not None


def test_extension_registry_stores_the_normalized_spec():
    ext.register_filter_field(LayerFieldSpec("Acme.Token", ("acme",), "auth.token", "str"))
    ext.register_filter_field(LayerFieldSpec("acme.token", ("acme",), "auth.token", "str"))
    assert [s.field for s in ext.get_filter_fields()] == ["acme.token"]


# -- filter help modal ----------------------------------------------------------

def test_help_lists_registered_field_with_literal_brackets():
    pytest.importorskip("textual")
    from friTap.tui.modals.filter_help_modal import (
        _build_filter_help_text,
        _static_field_groups,
    )

    ext.register_filter_field(_EXT_SPEC)
    ext.register_filter_field(LayerFieldSpec("[weird].f", ("weird",), "f", "str", "odd"))
    text = _build_filter_help_text()
    collapsed = " ".join(text.split())
    assert "acme.token str Acme token [x]" in collapsed
    assert "[weird].f" in text
    assert "[weird]" in [line.strip() for line in text.splitlines()]  # group title kept literal
    grouped = [row[0] for _, rows in _static_field_groups() for row in rows]
    assert "acme.token" not in grouped
    ext.reset_extensions()
    assert "acme.token" not in _build_filter_help_text()


# -- fritap -r: fields are registered before the .tap is read -------------------

def _register_acme_lib() -> None:
    ext.register_filter_field(
        LayerFieldSpec("acme.lib", ("tls",), "library", "str", "TLS lib via ext"))


def test_replay_loads_extensions_before_reading_the_tap(tmp_path, monkeypatch):
    pytest.importorskip("textual")
    from friTap.flow.layers import TlsLayer
    from friTap.tui.app import FriTapApp
    from tests.unit._tui_flow_helpers import make_flow, write_tap

    flow = make_flow("flow-aaaa")
    flow.layers.append(TlsLayer(library="BoringSSL"))
    tap_path = tmp_path / "replay.tap"
    write_tap(tap_path, [flow])
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [FakeEntryPoint("acme", _register_acme_lib)])
    seen = {}

    async def _go() -> None:
        app = FriTapApp(replay_file=str(tap_path))
        async with app.run_test() as pilot:
            await pilot.pause()
            seen["summaries"] = app.screen._replay_ctrl.get_summaries()

    asyncio.run(_go())
    (summary,) = seen["summaries"]
    assert summary.filter_attrs.get("acme.lib") == ("BoringSSL",)
    assert FilterEngine('acme.lib == "BoringSSL"').matches(summary)
