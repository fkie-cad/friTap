"""Export guard for the lazy ``friTap.ui`` facade (separate from ``friTap.__all__``)."""

import importlib

import pytest

import friTap.ui as ui

EXPECTED_ALL = [
    "AppCipherDecoder", "BaseAnalyzer", "BodyDecoderSpec", "DecodedView",
    "DetailTabSpec", "ExtensionLoadError", "Finding", "FlowColumnSpec",
    "LayerFieldSpec",
    "ReplayController", "Severity", "TapSource", "TapViewerApp",
    "TapViewerScreen", "UI_EXTENSION_ENTRY_POINT_GROUP", "available_analyzers",
    "extension_load_errors", "get_body_decoders", "get_detail_tabs", "get_filter_fields",
    "get_flow_columns", "install_theme", "iter_replay_rows", "load_extensions",
    "open_tap", "register_analyzer", "register_app_cipher_decoder",
    "register_body_decoder", "register_detail_tab", "register_filter_field",
    "register_flow_column", "theme_variable_defaults",
]

IDENTITIES = {
    "open_tap": ("friTap.tui.viewer_app", "open_tap"),
    "TapViewerApp": ("friTap.tui.viewer_app", "TapViewerApp"),
    "TapViewerScreen": ("friTap.tui.screens.tap_viewer", "TapViewerScreen"),
    "install_theme": ("friTap.tui.theme_install", "install_theme"),
    "theme_variable_defaults": ("friTap.tui.themes", "theme_variable_defaults"),
    "TapSource": ("friTap.flow.replay", "TapSource"),
    "ReplayController": ("friTap.flow.replay", "ReplayController"),
    "iter_replay_rows": ("friTap.flow.replay_rows", "iter_replay_rows"),
    "register_detail_tab": ("friTap.extensions", "register_detail_tab"),
    "DetailTabSpec": ("friTap.extensions", "DetailTabSpec"),
    "load_extensions": ("friTap.extensions", "load_extensions"),
    "ExtensionLoadError": ("friTap.extensions", "ExtensionLoadError"),
    "extension_load_errors": ("friTap.extensions", "extension_load_errors"),
    "FlowColumnSpec": ("friTap.extensions", "FlowColumnSpec"),
    "BodyDecoderSpec": ("friTap.extensions", "BodyDecoderSpec"),
    "LayerFieldSpec": ("friTap.filter.layer_fields", "LayerFieldSpec"),
    "register_flow_column": ("friTap.extensions", "register_flow_column"),
    "register_body_decoder": ("friTap.extensions", "register_body_decoder"),
    "register_filter_field": ("friTap.extensions", "register_filter_field"),
    "get_detail_tabs": ("friTap.extensions", "get_detail_tabs"),
    "get_flow_columns": ("friTap.extensions", "get_flow_columns"),
    "get_body_decoders": ("friTap.extensions", "get_body_decoders"),
    "get_filter_fields": ("friTap.extensions", "get_filter_fields"),
    "UI_EXTENSION_ENTRY_POINT_GROUP": ("friTap.extensions", "UI_EXTENSION_ENTRY_POINT_GROUP"),
    "register_analyzer": ("friTap.analysis.registry", "register_analyzer"),
    "available_analyzers": ("friTap.analysis.registry", "available_analyzers"),
    "BaseAnalyzer": ("friTap.analysis", "BaseAnalyzer"),
    "Finding": ("friTap.analysis", "Finding"),
    "Severity": ("friTap.analysis", "Severity"),
    "AppCipherDecoder": ("friTap.parsers.app_ciphers.registry", "AppCipherDecoder"),
    "DecodedView": ("friTap.parsers.app_ciphers.registry", "DecodedView"),
    "register_app_cipher_decoder": ("friTap.parsers.app_ciphers.registry", "register_app_cipher_decoder"),
}


def test_all_is_pinned():
    assert list(ui.__all__) == EXPECTED_ALL


def test_all_has_no_duplicates():
    assert len(ui.__all__) == len(set(ui.__all__))


@pytest.mark.parametrize("name", EXPECTED_ALL)
def test_every_name_resolves(name):
    assert getattr(ui, name) is not None


def test_dir_lists_every_name():
    assert set(EXPECTED_ALL) <= set(dir(ui))


@pytest.mark.parametrize("name", sorted(IDENTITIES))
def test_identity_with_source_object(name):
    module, attr = IDENTITIES[name]
    assert getattr(ui, name) is getattr(importlib.import_module(module), attr)


def test_closed_message_is_reachable_on_screen():
    assert hasattr(ui.TapViewerScreen, "Closed")


def test_resolved_attribute_is_cached_in_globals():
    ui.register_flow_column
    assert "register_flow_column" in vars(ui)


def test_unknown_attribute_raises():
    with pytest.raises(AttributeError):
        ui.definitely_not_a_thing


def test_register_app_cipher_decoder_adds_to_default_registry():
    from friTap.parsers.app_ciphers.registry import default_registry

    class _Dummy:
        title = "dummy"
        def matches(self, host, path, query, body): return False
        def decode(self, host, path, query, body): return None

    registry = default_registry()
    dummy = _Dummy()
    before = registry.decoders
    ui.register_app_cipher_decoder(dummy)
    try:
        assert registry.decoders[-1] is dummy
    finally:
        registry._decoders.remove(dummy)
    assert registry.decoders == before


# Mirrors RELEASING.md ("Public API surface" -> friTap.ui PROVISIONAL list).
DOCUMENTED_PROVISIONAL = {
    "TapSource", "DetailTabSpec", "FlowColumnSpec", "BodyDecoderSpec",
    "LayerFieldSpec", "register_detail_tab", "register_flow_column",
    "register_body_decoder", "register_filter_field", "get_detail_tabs",
    "get_flow_columns", "get_body_decoders", "get_filter_fields",
    "load_extensions", "UI_EXTENSION_ENTRY_POINT_GROUP", "iter_replay_rows",
    "theme_variable_defaults", "ExtensionLoadError", "extension_load_errors",
}


def test_provisional_set_matches_documented_list():
    assert ui.PROVISIONAL == DOCUMENTED_PROVISIONAL
    assert ui.PROVISIONAL <= set(ui.__all__)
    assert "PROVISIONAL" not in ui.__all__


def test_releasing_md_lists_every_provisional_name():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "RELEASING.md").read_text()
    section = text.split("**PROVISIONAL**", 1)[1].split("  - `AppCipherDecoder`", 1)[0]
    for name in ui.PROVISIONAL:
        assert f"`{name}`" in section, name


@pytest.mark.parametrize("name", ["BaseAnalyzer", "Finding", "Severity", "ReplayController"])
def test_ui_aliases_are_root_package_stable_names(name):
    import friTap
    assert getattr(ui, name) is getattr(friTap, name)
