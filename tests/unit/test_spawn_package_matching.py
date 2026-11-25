"""Spawn gating on mobile matches whole package names, not plain prefixes."""

import types

import pytest

from friTap.legacy.spawn_matching import spawn_matches_packages
from friTap.legacy.ssl_logger_core import SSL_Logger


@pytest.mark.parametrize("identifier, packages, expected", [
    ("com.foo.bar", ["com.foo.bar"], True),
    ("com.foo.bar:service", ["com.foo.bar"], True),
    ("com.foo.barbaz", ["com.foo.bar"], False),
    ("com.foo.bar.extra", ["com.foo.bar"], False),
    ("com.foo", ["com.foo.bar"], False),
    ("com.other:remote", ["com.foo.bar", "com.other"], True),
    ("com.foo.bar", [], False),
    ("com.foo.bar", None, False),
    ("com.foo.bar", ["", None], False),
    ("", ["com.foo.bar"], False),
    (None, ["com.foo.bar"], False),
])
def test_spawn_matches_packages(identifier, packages, expected):
    assert spawn_matches_packages(identifier, packages) is expected


def test_accepts_any_iterable_of_packages():
    assert spawn_matches_packages("a.b:c", frozenset({"a.b"}))
    assert spawn_matches_packages("a.b", (p for p in ["x", "a.b"]))


def _make_logger(target="com.foo.bar", mobile=True):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._config = types.SimpleNamespace(
        target=target, device=types.SimpleNamespace(mobile=mobile))
    return obj


def test_spawn_packages_default_to_target():
    assert _make_logger().spawn_packages == frozenset({"com.foo.bar"})


def test_add_spawn_packages_extends_the_set_and_ignores_empty():
    obj = _make_logger()
    obj.add_spawn_packages("com.helper", "", "com.other")
    assert obj.spawn_packages == frozenset({"com.foo.bar", "com.helper", "com.other"})


def test_mobile_matches_target_and_its_secondary_processes():
    obj = _make_logger()
    assert obj._should_instrument_spawn("com.foo.bar")
    assert obj._should_instrument_spawn("com.foo.bar:push")


def test_mobile_rejects_prefix_lookalikes_and_empty():
    obj = _make_logger()
    assert not obj._should_instrument_spawn("com.foo.barbaz")
    assert not obj._should_instrument_spawn("com.foo.bar.evil")
    assert not obj._should_instrument_spawn("")
    assert not obj._should_instrument_spawn(None)


def test_mobile_matches_added_packages():
    obj = _make_logger()
    assert not obj._should_instrument_spawn("com.helper:svc")
    obj.add_spawn_packages("com.helper")
    assert obj._should_instrument_spawn("com.helper:svc")
    assert obj._should_instrument_spawn("com.helper")
    assert not obj._should_instrument_spawn("com.helperx")


@pytest.mark.parametrize("target, identifier, expected", [
    ("/usr/bin/curl", "curl", True),
    ("curl https://example.com", "/usr/bin/curl-wrapper", False),
    ("C:\\Tools\\App.exe", "app.exe", True),
    ("firefox", "/opt/Firefox-bin", True),  # desktop keeps case-insensitive substring
    ("firefox", "chrome", False),
])
def test_desktop_behaviour_unchanged(target, identifier, expected):
    assert _make_logger(target=target, mobile=False)._should_instrument_spawn(identifier) is expected


def test_desktop_ignores_added_packages():
    obj = _make_logger(target="curl", mobile=False)
    obj.add_spawn_packages("wget")
    assert not obj._should_instrument_spawn("wget")
