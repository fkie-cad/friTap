"""Name collisions in the Phase-6 extension wiring (filter field,
body decoder). friTap loggers do not propagate, so warnings are captured with
the shared ``fritap_log_records`` fixture."""

from __future__ import annotations

import logging

import pytest

from friTap import extensions as ext
from friTap.filter import layer_fields as lf
from friTap.filter.fields import FIELD_REGISTRY
from friTap.filter.layer_fields import LayerFieldSpec, register_layer_field


def _snapshot():
    return (lf.all_layer_field_specs(), dict(lf._SPECS_BY_NAME), dict(lf._REGISTERED_SPECS))


def test_static_field_name_is_rejected_and_state_unchanged():
    static = next(n for n in FIELD_REGISTRY if n not in lf._BUILTIN_SPEC_NAMES)
    before = _snapshot()
    with pytest.raises(ValueError, match="built-in static field") as err:
        register_layer_field(LayerFieldSpec(static.upper(), ("x",), "a", "str"))
    assert static in str(err.value)
    assert _snapshot() == before


def test_non_colliding_and_builtin_layer_replacement_still_work():
    register_layer_field(LayerFieldSpec("acme.token", ("acme",), "auth.token", "str"))
    assert lf.layer_field_spec("acme.token") is not None
    register_layer_field(LayerFieldSpec("tls.sni", ("tls",), "alpn", "str"))
    assert lf.layer_field_spec("tls.sni").path == "alpn"


def test_colliding_decoder_is_skipped_with_warning(fritap_log_records):
    pytest.importorskip("textual")
    from friTap.tui.modals import body_processing_modal as bpm

    records = fritap_log_records(bpm.__name__)
    builtin_id = bpm._DECODER_OPTIONS[0][1]
    ext.register_body_decoder(ext.BodyDecoderSpec(builtin_id, "Dup", lambda b, h: ["x"]))
    ext.register_body_decoder(ext.BodyDecoderSpec("fresh", "Fresh", lambda b, h: ["x"]))
    options = bpm._extension_decoder_options()
    assert [o[1] for o in options] == ["fresh"]
    warnings = [r.getMessage() for r in records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and builtin_id in warnings[0]

