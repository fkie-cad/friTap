"""Tests for the offline-decryptor registry and zero-config discovery.

Covers the registry round-trip and conflict policy, that the built-in
Signal/MTProto decryptors register on import, the drop-in directory scan, the
env opt-out, and that a module missing the discovery marker contributes nothing.
"""

import importlib.util
import textwrap
from pathlib import Path

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

import friTap.offline.discovery as discovery  # noqa: E402
from friTap.flow.layers import AppLayer  # noqa: E402
from friTap.offline.registry import (  # noqa: E402
    OfflineDecryptorEntry,
    OfflineDecryptorRegistry,
    get_offline_decryptor_registry,
)


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "offline_decryptors"


def _noop_emitter(**_kwargs):  # pragma: no cover - never invoked in these tests
    return None


def _make_entry(name: str, *, help_text: str = "") -> OfflineDecryptorEntry:
    return OfflineDecryptorEntry(
        protocol_name=name,
        cli_flag=f"--{name}-keylog",
        cli_dest=f"{name}_keylog",
        requires_tls_strip=False,
        emitter=_noop_emitter,
        layer_cls=AppLayer,
        counter_prefix=name,
        cli_help=help_text,
    )


# ----------------------------------------------------------------------------
# 1. Registry round-trip + conflict policy
# ----------------------------------------------------------------------------

def test_registry_register_get_list_names_roundtrip():
    reg = OfflineDecryptorRegistry()
    entry = _make_entry("alpha")

    reg.register(entry)

    assert reg.get("alpha") is entry
    assert reg.list() == [entry]
    assert reg.names() == ["alpha"]
    assert reg.get("missing") is None


def test_registry_conflict_ignored_without_replace():
    reg = OfflineDecryptorRegistry()
    first = _make_entry("alpha", help_text="first")
    second = _make_entry("alpha", help_text="second")

    reg.register(first)
    reg.register(second)  # conflicting, no replace -> ignored

    assert reg.get("alpha") is first


def test_registry_conflict_honored_with_replace():
    reg = OfflineDecryptorRegistry()
    first = _make_entry("alpha", help_text="first")
    second = _make_entry("alpha", help_text="second")

    reg.register(first)
    reg.register(second, replace=True)

    assert reg.get("alpha") is second


# ----------------------------------------------------------------------------
# 2. Built-ins register on import of pcap_to_tap
# ----------------------------------------------------------------------------

def test_builtins_registered_on_import():
    import friTap.offline.pcap_to_tap  # noqa: F401 — import side effect registers built-ins

    names = get_offline_decryptor_registry().names()
    if _SIGNAL_AVAILABLE:
        assert "signal" in names
    assert "mtproto" in names


# ----------------------------------------------------------------------------
# 3. Drop-in directory discovery
# ----------------------------------------------------------------------------

@pytest.fixture
def reset_discovery(monkeypatch):
    """Isolate discovery: clear cache, ignore real entry points/dirs by default."""
    monkeypatch.setattr(discovery, "_DISCOVERED", None)
    monkeypatch.setattr(discovery, "_load_entrypoint_decryptors", lambda found: None)
    monkeypatch.delenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", raising=False)
    return monkeypatch


def test_dropin_directory_discovery(reset_discovery):
    reset_discovery.setattr(discovery, "_OFFLINE_DECRYPTOR_DIR", FIXTURE_DIR)

    found = discovery.discover_external_offline_decryptors(force=True)

    assert "sampleproto" in found
    assert found["sampleproto"].startswith("dir:")
    assert get_offline_decryptor_registry().get("sampleproto") is not None


# ----------------------------------------------------------------------------
# 4. Env opt-out
# ----------------------------------------------------------------------------

def test_discovery_disabled_reads_env(monkeypatch):
    monkeypatch.delenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", raising=False)
    assert discovery.discovery_disabled() is False

    monkeypatch.setenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", "0")
    assert discovery.discovery_disabled() is False

    monkeypatch.setenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", "1")
    assert discovery.discovery_disabled() is True


def test_discovery_returns_empty_when_disabled(reset_discovery):
    reset_discovery.setattr(discovery, "_OFFLINE_DECRYPTOR_DIR", FIXTURE_DIR)
    reset_discovery.setenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", "1")

    assert discovery.discover_external_offline_decryptors(force=True) == {}


# ----------------------------------------------------------------------------
# 5. A module without the marker contributes nothing
# ----------------------------------------------------------------------------

UNMARKED = textwrap.dedent(
    """
    from friTap.flow.layers import AppLayer
    from friTap.offline.registry import OfflineDecryptorEntry

    # NOTE: no `is_fritap_offline_decryptor = True` marker.

    def _emitter(**_kwargs):
        return None

    UNMARKED_ENTRY = OfflineDecryptorEntry(
        protocol_name="unmarkedproto",
        cli_flag="--unmarkedproto-keylog",
        cli_dest="unmarkedproto_keylog",
        requires_tls_strip=False,
        emitter=_emitter,
        layer_cls=AppLayer,
        counter_prefix="unmarkedproto",
        cli_help="Should never be discovered.",
    )
    """
)


def test_unmarked_module_contributes_nothing(reset_discovery, tmp_path):
    (tmp_path / "unmarked.py").write_text(UNMARKED)
    reset_discovery.setattr(discovery, "_OFFLINE_DECRYPTOR_DIR", tmp_path)

    found = discovery.discover_external_offline_decryptors(force=True)

    assert "unmarkedproto" not in found
    assert get_offline_decryptor_registry().get("unmarkedproto") is None
