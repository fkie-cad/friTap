"""Public-API surface guard for the top-level ``friTap`` package.

Asserts that the newly-added public symbols are importable from ``friTap`` and
listed in ``friTap.__all__``, that every name in ``__all__`` resolves via
``getattr``, and that the documented re-export identities hold (the same object
is reachable from the package and from its canonical home module). Pure Python —
no device/Frida/tshark.
"""

import importlib

import friTap


# The new public-API symbols this milestone added to ``friTap``.
NEW_PUBLIC_SYMBOLS = [
    "AnalyzeReport",
    "analyze_tap_report",
    "list_report_formats",
    "list_analyzers",
    "pcap_to_tap",
    "convert_pcap_to_tap",
    "ConvertResult",
    "NoDecryptionKeysError",
    "ReplayController",
    "IFlowSource",
    "FlowSummary",
]


def test_new_symbols_importable_and_in_all():
    for name in NEW_PUBLIC_SYMBOLS:
        assert hasattr(friTap, name), f"friTap.{name} is not importable"
        assert name in friTap.__all__, f"{name} missing from friTap.__all__"


def test_every_all_name_resolves():
    """Every name advertised in ``__all__`` must actually resolve via getattr."""
    for name in friTap.__all__:
        # getattr raises AttributeError if the name is declared but missing;
        # every public symbol here is a class/function/non-empty str, so a
        # truthy result is the meaningful assertion.
        assert getattr(friTap, name) is not None, (
            f"friTap.{name} is declared in __all__ but resolves to None"
        )


def test_all_has_no_duplicates():
    assert len(friTap.__all__) == len(set(friTap.__all__)), "duplicate name in __all__"


def test_analyze_symbols_share_identity_with_commands_analyze():
    analyze = importlib.import_module("friTap.commands.analyze")
    assert friTap.AnalyzeReport is analyze.AnalyzeReport
    assert friTap.analyze_tap_report is analyze.analyze_tap_report
    assert friTap.list_report_formats is analyze.list_report_formats
    assert friTap.list_analyzers is analyze.list_analyzers


def test_offline_symbols_share_identity_with_offline_package():
    import types
    import friTap.offline as offline

    assert friTap.convert_pcap_to_tap is offline.convert_pcap_to_tap
    assert friTap.ConvertResult is offline.ConvertResult
    assert friTap.NoDecryptionKeysError is offline.NoDecryptionKeysError

    # ``pcap_to_tap`` is the wrapper FUNCTION living in the submodule
    # ``friTap.offline.pcap_to_tap`` (it is intentionally NOT bound on the
    # offline package, so it does not shadow the same-named submodule).
    p2t_mod = importlib.import_module("friTap.offline.pcap_to_tap")
    assert isinstance(offline.pcap_to_tap, types.ModuleType)  # package attr = module
    assert friTap.pcap_to_tap is p2t_mod.pcap_to_tap          # top-level = function
    assert callable(friTap.pcap_to_tap)


def test_replay_symbols_reexported_for_back_compat():
    """``friTap.flow`` is the canonical home; ``friTap.tui.replay_controller``
    re-exports the same objects for back-compat."""
    import friTap.flow as flow
    shim = importlib.import_module("friTap.tui.replay_controller")

    assert flow.ReplayController is shim.ReplayController
    assert flow.IFlowSource is shim.IFlowSource
    # And the top-level package exposes the same object too.
    assert friTap.ReplayController is flow.ReplayController
    assert friTap.IFlowSource is flow.IFlowSource
