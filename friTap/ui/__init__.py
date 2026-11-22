"""Stable ``friTap.ui`` facade: the single seam host projects use to embed friTap's viewer.

Separate from ``friTap.__all__``; ``friTap.tui.*`` stays internal. The facade is
lazy (PEP 562): ``import friTap.ui`` loads neither textual nor frida. Textual is
imported only when a TUI name (``open_tap``, ``TapViewerApp``,
``TapViewerScreen``, ``install_theme``, ``theme_variable_defaults``) is accessed.

Embedding modes
    A. Launch:    ``open_tap(path)`` runs a standalone viewer app on a ``.tap``.
    B. Mount:     push ``TapViewerScreen`` into the host's own Textual app
                  (``TapViewerScreen.Closed`` is posted when it closes);
                  ``install_theme`` makes the host app resolve friTap's theme
                  variables.
    C. Extend:    ``register_detail_tab`` / ``register_flow_column`` /
                  ``register_body_decoder`` / ``register_filter_field``, the
                  analyzer registry (``register_analyzer``) and the app-cipher
                  registry (``register_app_cipher_decoder``). Extensions can
                  also be discovered through the entry-point group
                  ``fritap.ui_extensions``; each target is a zero-argument
                  callable that performs its registrations (``load_extensions``).

Stability (see ``RELEASING.md``, "Public API surface"):

    Stable: ``open_tap``, ``TapViewerApp``, ``TapViewerScreen`` (incl.
    ``TapViewerScreen.Closed`` and ``go_back``), ``install_theme``,
    ``register_analyzer``, ``available_analyzers``,
    ``register_app_cipher_decoder``, ``AppCipherDecoder``, ``DecodedView``,
    ``ReplayController``, ``BaseAnalyzer``, ``Finding``, ``Severity``.

    PROVISIONAL (names in :data:`PROVISIONAL`; may change in a MINOR release
    until the viewer widgets consume them): ``TapSource``, the extension specs
    (``DetailTabSpec``, ``FlowColumnSpec``, ``BodyDecoderSpec``,
    ``LayerFieldSpec``), the four ``register_*`` extension functions, the four
    ``get_*`` getters, ``load_extensions``, ``UI_EXTENSION_ENTRY_POINT_GROUP``,
    ``iter_replay_rows`` and ``theme_variable_defaults``.

    ``AppCipherDecoder`` / ``DecodedView`` are a carve-out from internal
    ``friTap.parsers.*``. ``BaseAnalyzer``, ``Finding``, ``Severity`` and
    ``ReplayController`` are the same objects as the root-package names.

The extension registry lives in core (:mod:`friTap.extensions`) so
``friTap.filter`` never imports ``friTap.ui``.
"""

from typing import TYPE_CHECKING

_LAZY_EXPORTS = {
    # Mode A / B: viewer (imports textual on first access)
    "open_tap": "friTap.tui.viewer_app",
    "TapViewerApp": "friTap.tui.viewer_app",
    "TapViewerScreen": "friTap.tui.screens.tap_viewer",
    "install_theme": "friTap.tui.theme_install",
    "theme_variable_defaults": "friTap.tui.themes",
    # Replay (no textual)
    "TapSource": "friTap.flow.replay",
    "ReplayController": "friTap.flow.replay",
    "iter_replay_rows": "friTap.flow.replay_rows",
    # Mode C: extension registry, homed in core friTap.extensions (no textual)
    "UI_EXTENSION_ENTRY_POINT_GROUP": "friTap.extensions",
    "DetailTabSpec": "friTap.extensions",
    "FlowColumnSpec": "friTap.extensions",
    "BodyDecoderSpec": "friTap.extensions",
    "LayerFieldSpec": "friTap.extensions",
    "register_detail_tab": "friTap.extensions",
    "register_flow_column": "friTap.extensions",
    "register_body_decoder": "friTap.extensions",
    "register_filter_field": "friTap.extensions",
    "get_detail_tabs": "friTap.extensions",
    "get_flow_columns": "friTap.extensions",
    "get_body_decoders": "friTap.extensions",
    "get_filter_fields": "friTap.extensions",
    "load_extensions": "friTap.extensions",
    "ExtensionLoadError": "friTap.extensions",
    "extension_load_errors": "friTap.extensions",
    # Analyzer registry
    "register_analyzer": "friTap.analysis.registry",
    "available_analyzers": "friTap.analysis.registry",
    "BaseAnalyzer": "friTap.analysis",
    "Finding": "friTap.analysis",
    "Severity": "friTap.analysis",
    # App-cipher decoder registry
    "AppCipherDecoder": "friTap.parsers.app_ciphers.registry",
    "DecodedView": "friTap.parsers.app_ciphers.registry",
    "register_app_cipher_decoder": "friTap.parsers.app_ciphers.registry",
}

__all__ = sorted(_LAZY_EXPORTS)

# Names that may change in a MINOR release (see RELEASING.md). Not in ``__all__``.
PROVISIONAL = frozenset({
    "TapSource",
    "DetailTabSpec", "FlowColumnSpec", "BodyDecoderSpec", "LayerFieldSpec",
    "register_detail_tab", "register_flow_column", "register_body_decoder",
    "register_filter_field",
    "get_detail_tabs", "get_flow_columns", "get_body_decoders",
    "get_filter_fields",
    "load_extensions", "UI_EXTENSION_ENTRY_POINT_GROUP",
    "ExtensionLoadError", "extension_load_errors",
    "iter_replay_rows", "theme_variable_defaults",
})


def __getattr__(name: str):
    """PEP 562 lazy loader for the facade symbols (see ``_LAZY_EXPORTS``)."""
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module), name)
    globals()[name] = value  # cache: later access skips __getattr__ entirely
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


if TYPE_CHECKING:  # static analysers / IDEs see the real symbols, no runtime cost
    from friTap.analysis import BaseAnalyzer as BaseAnalyzer
    from friTap.analysis import Finding as Finding
    from friTap.analysis import Severity as Severity
    from friTap.analysis.registry import available_analyzers as available_analyzers
    from friTap.analysis.registry import register_analyzer as register_analyzer
    from friTap.extensions import *  # noqa: F401,F403
    from friTap.flow.replay import ReplayController as ReplayController
    from friTap.flow.replay import TapSource as TapSource
    from friTap.flow.replay_rows import iter_replay_rows as iter_replay_rows
    from friTap.parsers.app_ciphers.registry import (
        AppCipherDecoder as AppCipherDecoder,
    )
    from friTap.parsers.app_ciphers.registry import (
        DecodedView as DecodedView,
    )
    from friTap.parsers.app_ciphers.registry import (
        register_app_cipher_decoder as register_app_cipher_decoder,
    )
    from friTap.tui.screens.tap_viewer import TapViewerScreen as TapViewerScreen
    from friTap.tui.theme_install import install_theme as install_theme
    from friTap.tui.themes import theme_variable_defaults as theme_variable_defaults
    from friTap.tui.viewer_app import TapViewerApp as TapViewerApp
    from friTap.tui.viewer_app import open_tap as open_tap
