"""The shared ``cryptography`` probe (``friTap.protocols.crypto_backend``)."""

from __future__ import annotations

import sys

import pytest

from friTap.protocols.crypto_backend import cryptography_ciphers_available


def test_available_with_cryptography():
    pytest.importorskip("cryptography")
    assert cryptography_ciphers_available() is True


@pytest.mark.parametrize("module", [
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.kdf.hkdf",
])
def test_unavailable_when_any_probed_module_is_missing(monkeypatch, module):
    monkeypatch.setitem(sys.modules, module, None)
    assert cryptography_ciphers_available() is False


def test_every_protocol_probe_aliases_the_shared_one():
    from friTap.offline import rc4, schannel
    from friTap.offline.tls import backend
    from friTap.protocols import mtproto_backend

    for probe in (mtproto_backend.mtproto_backend_available, backend.backend_available,
                  rc4.rc4_backend_available, schannel.schannel_backend_available):
        assert probe is cryptography_ciphers_available
