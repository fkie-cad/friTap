"""Probe for the optional ``cryptography`` AEAD backend used by the TLS 1.3 peel."""

from __future__ import annotations

from ...protocols.crypto_backend import cryptography_ciphers_available

# Return True if the optional ``cryptography`` AEAD backend is importable.
backend_available = cryptography_ciphers_available
