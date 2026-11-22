"""Tests for the core viewer extension registry (``friTap.extensions``)."""

import pytest

from friTap.filter.layer_fields import LayerFieldSpec
from friTap import extensions as ext
from tests.unit._ext_helpers import FakeEntryPoint as _EP


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", "1")  # load_extensions() also runs offline discovery; keep it hermetic
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)
    ext.reset_extensions()
    yield
    ext.reset_extensions()


def test_detail_tab_register_get_and_replace():
    ext.register_detail_tab(ext.DetailTabSpec("a", "A", lambda f: None))
    ext.register_detail_tab(ext.DetailTabSpec("a", "A2", lambda f: "x"))
    tabs = ext.get_detail_tabs()
    assert [t.label for t in tabs] == ["A2"]
    assert tabs[0].render(None) == "x"


def test_flow_column_register_get():
    ext.register_flow_column(ext.FlowColumnSpec("k", "K", 6, lambda r: "v"))
    (c,) = ext.get_flow_columns()
    assert (c.key, c.width, c.value(None)) == ("k", 6, "v")


def test_body_decoder_register_get():
    ext.register_body_decoder(ext.BodyDecoderSpec("d", "D", lambda b, h: [b.decode()]))
    (d,) = ext.get_body_decoders()
    assert d.decode(b"hi", {}) == ["hi"]


def test_filter_field_register_get():
    spec = LayerFieldSpec("my.f", ("my",), "f", "str")
    ext.register_filter_field(spec)
    assert ext.get_filter_fields() == [spec]


def test_load_extensions_runs_callable_and_is_idempotent(monkeypatch):
    calls = []

    def target():
        calls.append(1)
        ext.register_flow_column(ext.FlowColumnSpec("k", "K", 3, lambda r: ""))

    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [_EP("x", target)])
    ext.load_extensions()
    ext.load_extensions()
    assert calls == [1]
    assert len(ext.get_flow_columns()) == 1
    ext.load_extensions(force=True)
    assert calls == [1, 1]
    assert len(ext.get_flow_columns()) == 1


def test_failing_entry_point_skipped(monkeypatch):
    def boom():
        raise RuntimeError("x")

    def good():
        ext.register_body_decoder(ext.BodyDecoderSpec("g", "G", lambda b, h: []))

    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [
        _EP("bad-load", exc=ImportError("no")), _EP("bad-call", boom), _EP("ok", good)])
    ext.load_extensions()
    assert [d.name for d in ext.get_body_decoders()] == ["g"]


def test_enumeration_failure_is_swallowed(monkeypatch):
    def fail(*a, **kw):
        raise OSError("nope")
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions()


def test_disabled_via_env(monkeypatch):
    monkeypatch.setenv(ext.DISABLE_ENV_VAR, "1")
    monkeypatch.setattr(ext.discovery_base, "get_entry_points",
                        lambda *a, **kw: pytest.fail("must not enumerate"))
    ext.load_extensions()


def test_reset_clears_everything():
    ext.register_flow_column(ext.FlowColumnSpec("k", "K", 1, lambda r: ""))
    ext.reset_extensions()
    assert ext.get_flow_columns() == []


PUBLIC_NAMES = [
    "UI_EXTENSION_ENTRY_POINT_GROUP", "DISABLE_ENV_VAR", "DetailTabSpec",
    "FlowColumnSpec", "BodyDecoderSpec", "LayerFieldSpec", "register_detail_tab",
    "register_flow_column", "register_body_decoder", "register_filter_field",
    "get_detail_tabs", "get_flow_columns", "get_body_decoders",
    "get_filter_fields", "load_extensions", "reset_extensions",
    "ExtensionLoadError", "extension_load_errors",
]


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_ui_extensions_reexports_the_same_core_objects(name):
    from friTap.ui import extensions as ui_ext
    assert getattr(ui_ext, name) is getattr(ext, name)


def test_ui_extensions_all_matches_core():
    from friTap.ui import extensions as ui_ext
    assert list(ui_ext.__all__) == list(ext.__all__)
    assert set(PUBLIC_NAMES) == set(ext.__all__)


def test_registration_via_ui_path_is_visible_in_core():
    from friTap.ui import extensions as ui_ext
    ui_ext.register_flow_column(ui_ext.FlowColumnSpec("u", "U", 2, lambda r: ""))
    assert [c.key for c in ext.get_flow_columns()] == ["u"]


def test_entry_point_group_string_unchanged():
    assert ext.UI_EXTENSION_ENTRY_POINT_GROUP == "fritap.ui_extensions"
    assert ext.DISABLE_ENV_VAR == "FRITAP_DISABLE_UI_EXTENSIONS"
