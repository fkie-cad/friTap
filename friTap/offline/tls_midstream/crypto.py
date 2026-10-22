"""Mid-stream TLS 1.3 record decryption from a raw traffic secret (shim).

The implementation moved to the protocol-neutral
:mod:`friTap.offline.tls.stream`; every name is RE-EXPORTED here so existing
``friTap.offline.tls_midstream.crypto`` imports keep working. See that module
for how the unknown starting record sequence number (and, when unknown, the
cipher suite) is recovered via the AEAD tag as a zero-false-accept oracle.
"""

from __future__ import annotations

from ..tls.stream import (  # noqa: F401
    _VALID_INNER_TYPES,
    APPLICATION_DATA,
    DEFAULT_MAX_SEQ,
    MIN_AEAD_FRAGMENT_LEN,
    decrypt_stream_from,
    pick_suite,
    recover_seq,
)
from ..tls.tls13 import SUITES, inner_content_type, try_decrypt  # noqa: F401
