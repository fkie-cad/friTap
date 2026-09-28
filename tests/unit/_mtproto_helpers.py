"""Shared MTProto obfuscated-transport stream primitives for the tests.

The one definition of the AES-CTR helper, the intermediate framer and the
64-byte obfuscation-init builder, used by the unit tests and re-exported by
``tests/integration/_mtproto_helpers.py``. Importing this module requires
``cryptography``; callers ``pytest.importorskip`` it first.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from friTap.offline.mtproto.transport import derive_obfuscation_keys


def aes_ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def intermediate_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def build_obf_init(tag: bytes) -> bytes:
    """On-wire 64-byte init that decrypts to ``tag`` at [56:60]."""
    enc_init = bytearray(os.urandom(64))
    key_out, iv_out, _, _ = derive_obfuscation_keys(bytes(enc_init))
    dec = bytearray(aes_ctr(key_out, iv_out).update(bytes(enc_init)))
    dec[56:60] = tag
    return aes_ctr(key_out, iv_out).update(bytes(dec))
