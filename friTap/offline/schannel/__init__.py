"""Offline Schannel secret correlation (PUBLIC).

The read-only Schannel mem-scan engine recovers TLS 1.2 masters and TLS 1.3 secrets
from lsass.exe but cannot read the ClientHello random (Schannel keeps none near the
key object), so it emits them UNPAIRED to a ``.schannel.unpaired`` sidecar. This
package joins each unpaired secret to its ``client_random`` by TRIAL DECRYPTION
against the captured pcap (TLS 1.2 via a decrypted Finished, TLS 1.3 via the AEAD
tag), producing a STANDARD NSS keylog that tshark/Wireshark can then use.

Layout mirrors :mod:`friTap.offline.rc4` / :mod:`friTap.offline.signal`:

  * :mod:`.unpaired`  — parse the ``.schannel.unpaired`` sidecar,
  * :mod:`.correlate` — the trial-decryption correlation (the core),
  * :mod:`.pidmap`    — per-PID attribution via the TCP 4-tuple join,
  * :mod:`.sspi`      — in-process byte-equality correlation helpers,
  * :mod:`.offline_decryptor` — the registry entry + emitter.

The correlation needs tshark (reused from :mod:`friTap.offline.tshark`); it never
touches lsass. Like the RC4/Signal packages this subpackage self-registers on
import via the discovery marker below, and its emitter log-and-skips (never raises)
on any recoverable problem. Schannel is PUBLIC — not listed in ``private.txt``.
"""

from __future__ import annotations

# True if the optional AEAD backend (for the pure-Python TLS 1.3 peel, used by the
# pidmap/sspi trial-decrypt helpers) is importable. Never raises; the primary
# tshark-driven correlation path does not depend on it.
from ..tls.backend import backend_available as schannel_backend_available  # noqa: F401


class SchannelError(Exception):
    """Base class for offline Schannel correlation errors."""


# Module-level discovery marker: tells the offline-decryptor discovery scan
# (:func:`friTap.offline.pcap_to_tap._discover_offline_decryptor_extensions`,
# mirroring ``is_fritap_parser`` / ``is_fritap_analyzer``) that importing this
# package self-registers an offline decryptor.
is_fritap_offline_decryptor = True


def _register_schannel_offline_decryptor() -> None:
    """Register the Schannel offline decryptor into the process-global registry.

    Lazy + fully guarded so importing this package can never raise: a missing
    dependency or an import cycle during registration is logged at debug and
    skipped. Re-registration of an identical entry is idempotent.
    """
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
