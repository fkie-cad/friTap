"""Re-registration, hostile matches() and built-in name collisions."""
from unittest import mock

from friTap.analysis import registry as analysis_registry
from friTap.parsers.app_ciphers import registry as cipher_registry
from friTap.parsers.app_ciphers.registry import AppCipherRegistry, DecodedView


class _Dec:
    def __init__(self, name, match=True, tag=""):
        self.name, self._match, self.tag = name, match, tag

    def matches(self, host, path, query, body):
        return self._match

    def decode(self, host, path, query, body):
        return DecodedView(title=self.name + self.tag, ok=True, text="x")


class _Raising(_Dec):
    def matches(self, host, path, query, body):
        raise RuntimeError("boom")


def test_reregistration_replaces_in_place():
    reg = AppCipherRegistry()
    first, other = _Dec("a"), _Dec("b")
    reg.register(first)
    reg.register(other)
    replacement = _Dec("a", tag="2")
    reg.register(replacement)
    assert reg.decoders == (replacement, other)
    assert [v.title for v in reg.decode_request("h", "/p", b"")] == ["a2", "b"]


def test_default_registry_builtin_registered_once_and_stable(monkeypatch):
    monkeypatch.setattr(cipher_registry, "_DEFAULT_REGISTRY", None)
    reg = cipher_registry.default_registry()
    before = [type(d) for d in reg.decoders]
    for d in list(reg.decoders):
        cipher_registry.register_app_cipher_decoder(type(d)())
    assert [type(d) for d in reg.decoders] == before
    assert len(before) == 1


def test_raising_matches_is_skipped_and_logged_once():
    reg = AppCipherRegistry()
    reg.register(_Raising("bad"))
    reg.register(_Dec("good"))
    with mock.patch.object(cipher_registry, "logger") as log:
        for _ in range(2):
            views = reg.decode_request("h", "/p", b"")
    assert [v.title for v in views] == ["good"]
    assert log.warning.call_count == 1


def test_analyzer_builtin_collision_warns_and_builtin_wins(monkeypatch):
    monkeypatch.setattr(analysis_registry, "_DISCOVERED", {})
    with mock.patch.object(analysis_registry, "logger") as log:
        analysis_registry.register_analyzer("ioc", lambda **_: object())
    assert log.warning.called and "ioc" in str(log.warning.call_args)
    built = analysis_registry._build("ioc")
    assert type(built).__name__ == "IocAnalyzer"


class _BadReturn(_Dec):
    def decode(self, host, path, query, body):
        return "not a view"


def test_wrong_decode_return_type_is_skipped_and_logged_once():
    reg = AppCipherRegistry()
    reg.register(_BadReturn("bad"))
    reg.register(_Dec("good"))
    with mock.patch.object(cipher_registry, "logger") as log:
        for _ in range(2):
            views = reg.decode_request("h", "/p", b"")
    assert [v.title for v in views] == ["good"]
    assert log.warning.call_count == 1


def test_same_class_without_name_replaces_and_docstring_says_so():
    class _NoName:
        def matches(self, *a):
            return True

        def decode(self, *a):
            return None

    reg = AppCipherRegistry()
    reg.register(_NoName())
    reg.register(_NoName())
    assert len(reg.decoders) == 1
    assert "name" in cipher_registry.register_app_cipher_decoder.__doc__
