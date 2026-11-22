"""Registration validation and load-failure recording in ``friTap.extensions``."""

import pytest

from friTap import extensions as ext
from tests.unit._ext_helpers import FakeEntryPoint as _EP


@pytest.fixture(autouse=True)
def _discovery_enabled(monkeypatch):
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)


def _tab(**kw):
    args = dict(id="t", label="T", render=lambda f: None)
    args.update(kw)
    return ext.DetailTabSpec(**args)


def _col(**kw):
    args = dict(key="k", label="K", width=4, value=lambda r: "")
    args.update(kw)
    return ext.FlowColumnSpec(**args)


def _dec(**kw):
    args = dict(name="d", label="D", decode=lambda b, h: [])
    args.update(kw)
    return ext.BodyDecoderSpec(**args)


def _registry_state():
    return (ext.get_detail_tabs(), ext.get_flow_columns(), ext.get_body_decoders())


@pytest.mark.parametrize("register,spec,exc", [
    (ext.register_detail_tab, "not a spec", TypeError),
    (ext.register_detail_tab, _tab(id=""), ValueError),
    (ext.register_detail_tab, _tab(id="  "), ValueError),
    (ext.register_detail_tab, _tab(id=3), TypeError),
    (ext.register_detail_tab, _tab(label=None), TypeError),
    (ext.register_detail_tab, _tab(render="nope"), TypeError),
    (ext.register_flow_column, _dec(), TypeError),
    (ext.register_flow_column, _col(key=""), ValueError),
    (ext.register_flow_column, _col(label=1), TypeError),
    (ext.register_flow_column, _col(width="12"), TypeError),
    (ext.register_flow_column, _col(width=None), TypeError),
    (ext.register_flow_column, _col(width=True), TypeError),
    (ext.register_flow_column, _col(width=-1), ValueError),
    (ext.register_flow_column, _col(value=None), TypeError),
    (ext.register_body_decoder, _tab(), TypeError),
    (ext.register_body_decoder, _dec(name=" "), ValueError),
    (ext.register_body_decoder, _dec(label=b"x"), TypeError),
    (ext.register_body_decoder, _dec(decode=5), TypeError),
])
def test_invalid_spec_rejected_and_registry_unchanged(register, spec, exc):
    before = _registry_state()
    with pytest.raises(exc):
        register(spec)
    assert _registry_state() == before == ([], [], [])


def test_valid_specs_still_accepted():
    ext.register_flow_column(_col(width=0))
    ext.register_detail_tab(_tab())
    ext.register_body_decoder(_dec())
    assert len(ext.get_flow_columns()) == len(ext.get_detail_tabs()) == 1


def test_rejection_keeps_previous_registration():
    ext.register_flow_column(_col())
    with pytest.raises(ValueError):
        ext.register_flow_column(_col(width=-5))
    assert [c.width for c in ext.get_flow_columns()] == [4]


def test_failing_entry_points_recorded_and_good_one_registers(monkeypatch):
    def boom():
        raise RuntimeError("x")

    def good():
        ext.register_body_decoder(_dec(name="g"))

    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [
        _EP("bad-load", exc=ImportError("no")), _EP("bad-call", boom), _EP("ok", good)])
    ext.load_extensions()
    assert [d.name for d in ext.get_body_decoders()] == ["g"]
    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("bad-load", "ImportError: no"),
        ext.ExtensionLoadError("bad-call", "RuntimeError: x"),
    ]


def test_invalid_spec_from_entry_point_is_recorded(monkeypatch):
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [
        _EP("bad-spec", lambda: ext.register_flow_column(_col(width="12")))])
    ext.load_extensions()
    (err,) = ext.extension_load_errors()
    assert err.source == "bad-spec" and err.error.startswith("TypeError:")
    assert ext.get_flow_columns() == []


def test_enumeration_failure_recorded(monkeypatch):
    def fail(*a, **kw):
        raise OSError("nope")
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions()
    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("entry-points", "OSError: nope")]


def test_offline_discovery_failure_recorded(monkeypatch):
    import friTap.offline.discovery as disc

    def fail(force=False):
        raise ValueError("disc")
    monkeypatch.setattr(disc, "discover_external_offline_decryptors", fail)
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [])
    ext.load_extensions()
    assert ext.extension_load_errors() == [
        ext.ExtensionLoadError("offline-decryptors", "ValueError: disc")]


def test_errors_cleared_by_reset_and_force_reload(monkeypatch):
    def fail(*a, **kw):
        raise OSError("nope")
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions()
    assert len(ext.extension_load_errors()) == 1
    ext.load_extensions()  # idempotent: no re-run, errors kept
    assert len(ext.extension_load_errors()) == 1
    ext.load_extensions(force=True)  # cleared then re-recorded, not accumulated
    assert len(ext.extension_load_errors()) == 1
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", lambda *a, **kw: [])
    ext.load_extensions(force=True)
    assert ext.extension_load_errors() == []
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions(force=True)
    ext.reset_extensions()
    assert ext.extension_load_errors() == []


def test_extension_load_errors_returns_copy(monkeypatch):
    def fail(*a, **kw):
        raise OSError("nope")
    monkeypatch.setattr(ext.discovery_base, "get_entry_points", fail)
    ext.load_extensions()
    ext.extension_load_errors().clear()
    assert len(ext.extension_load_errors()) == 1
