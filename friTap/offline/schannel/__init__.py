"""Offline Schannel secret correlation (PUBLIC).

The Schannel mem-scan engine recovers TLS 1.2 masters and TLS 1.3 secrets from
lsass.exe but cannot read the ClientHello random, so it writes them UNPAIRED to a
``.schannel.unpaired`` sidecar. This package joins each secret to its
``client_random`` by trial decryption against the pcap (TLS 1.2 via a decrypted
Finished, TLS 1.3 via the AEAD tag) and produces a standard NSS keylog.

  * :mod:`.unpaired`  parses the sidecar,
  * :mod:`.correlate` is the trial-decryption correlation,
  * :mod:`.oracle`    answers clean cases in pure Python so tshark runs less,
  * :mod:`.pidmap`    attributes secrets to a PID via the TCP 4-tuple join,
  * :mod:`.sspi`      holds in-process byte-equality correlation helpers,
  * :mod:`.offline_decryptor` is the registry entry and emitter.

Correlation needs tshark and never touches lsass. Importing this package
self-registers the decryptor via the discovery marker below; the emitter
log-and-skips on any recoverable problem. Schannel is PUBLIC (not in ``private.txt``).
"""

from __future__ import annotations

# True if the optional AEAD backend (pure-Python TLS 1.3 peel) is importable.
from ..tls.backend import backend_available as schannel_backend_available  # noqa: F401


class SchannelError(Exception):
    """Base class for offline Schannel correlation errors."""


# Discovery marker read by
# :func:`friTap.offline.pcap_to_tap._discover_offline_decryptor_extensions`.
is_fritap_offline_decryptor = True


def _register_schannel_offline_decryptor() -> None:
    """Register the decryptor; guarded so importing this package never raises."""
    from friTap.offline.registry import register_offline_decryptors_safely

    register_offline_decryptors_safely(
        __name__, ("build_schannel_offline_decryptor_entry",),
        "Schannel offline decryptor self-registration skipped",
    )


_register_schannel_offline_decryptor()


__all__ = [
    "SchannelError",
    "schannel_backend_available",
    "is_fritap_offline_decryptor",
]
