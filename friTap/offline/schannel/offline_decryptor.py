#!/usr/bin/env python3

"""Schannel offline decryptor: correlate + derive NSS keylog + decrypt (PUBLIC).

The Schannel mem-scan engine recovers TLS secrets from lsass but cannot read the
ClientHello random (it is not memory-resident), so it writes them UNPAIRED to a
``.schannel.unpaired`` sidecar. This decryptor closes that gap OFFLINE:

  1. parse the sidecar (:mod:`.unpaired`),
  2. trial-decrypt each secret against the pcap to find its client_random
     (:mod:`.correlate`, TLS 1.2 AND 1.3), producing a STANDARD NSS keylog
     (``CLIENT_RANDOM``/``*_TRAFFIC_SECRET_0``/…),
  3. write that derived keylog next to the sidecar, and
  4. feed it into the SAME TLS single-pass that the ``--keylog`` path uses, so the
     recovered TLS flows are decrypted and reconstructed exactly like any other.

INTEGRATION CHOICE — option (a): emit a standard NSS keylog and let the existing
TLS single-pass consume it, rather than (b) emitting ``DatalogEvent``s directly.
Producing a standard NSS keylog is the whole point of the correlation — it is what
makes the secrets Wireshark-/tshark-loadable — and reusing
``_emit_tls_streams_singlepass`` means the decrypted Schannel flows get the exact
same TLS layer, SNI/cipher/ALPN metadata, direction tracking and reconstruction as
a normal ``--keylog`` capture, with no bespoke event plumbing to keep in sync.

The entry registers ``requires_tls_strip=False`` (an INDEPENDENT emitter): it does
not consume tshark's already-decrypted bytes; it supplies its OWN derived keylog
and drives a fresh TLS pass over it. The derived keylog is written to disk (a real,
reusable artifact) at ``<sidecar-with-.unpaired-stripped>.nss.keylog``.
"""

from __future__ import annotations

import logging
import os

from friTap.offline.registry import OfflineDecryptorEntry
from friTap.offline.schannel.unpaired import looks_like_unpaired

logger = logging.getLogger(__name__)


def _derived_keylog_path(sidecar_path: str) -> str:
    """Where the correlated NSS keylog is written (next to the sidecar).

    ``keys.memscan.schannel.unpaired`` -> ``keys.memscan.schannel.nss.keylog``.
    """
    if sidecar_path.endswith(".unpaired"):
        base = sidecar_path[: -len(".unpaired")]
    else:
        base = os.path.splitext(sidecar_path)[0]
    return base + ".nss.keylog"


def _schannel_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result,
) -> None:
    """Correlate the ``.schannel.unpaired`` sidecar and decrypt the paired TLS.

    Never raises for a recoverable problem (missing sidecar, no tshark match, empty
    correlation) — per the offline-emitter contract it logs and returns instead, so
    a capture that yields no Schannel pairing still converts cleanly.

    *proto_keylog* is the ``.schannel.unpaired`` sidecar path (``protocol_keylogs``
    maps ``--schannel-unpaired`` -> ``schannel``). *tls_keylog_path* is the primary
    TLS keylog (may be None); it is unused here because Schannel secrets are, by
    definition, the ones NOT already in that keylog — this emitter supplies keys of
    its own.
    """
    from .correlate import correlate_unpaired
    from .unpaired import parse_unpaired, tls12_masters, tls13_secrets

    try:
        with open(proto_keylog, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        logger.warning("Schannel unpaired sidecar %s unreadable; skipping", proto_keylog)
        return

    records = parse_unpaired(text)
    masters = tls12_masters(records)
    secrets13 = tls13_secrets(records)
    if not masters and not secrets13:
        logger.warning(
            "Schannel unpaired sidecar %s held no usable TLS 1.2/1.3 secrets; "
            "nothing to correlate", proto_keylog,
        )
        return

    try:
        lines = correlate_unpaired(tshark_bin, pcap_path, masters, secrets13)
    except Exception:  # noqa: BLE001 - correlation must never abort the conversion
        logger.warning("Schannel offline correlation failed; skipping", exc_info=True)
        return

    if not lines:
        logger.warning(
            "Schannel: none of %d master(s) / %d TLS 1.3 secret(s) paired to a "
            "client_random in %s (secrets may be from a different capture, or the "
            "connections carried no decryptable records)",
            len(masters), len(secrets13), os.path.basename(pcap_path),
        )
        result.record_protocol("schannel", messages=0,
                               streams=0, undecryptable=len(masters) + len(secrets13))
        return

    derived_keylog = _derived_keylog_path(proto_keylog)
    try:
        with open(derived_keylog, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except OSError:
        logger.warning("Could not write derived Schannel keylog %s; skipping",
                       derived_keylog, exc_info=True)
        return
    logger.info("Schannel: wrote %d correlated NSS keylog line(s) -> %s",
                len(lines), derived_keylog)

    _decrypt_with_derived_keylog(
        pcap_path, derived_keylog, tshark_bin, tls_ports,
        bus=bus, state=state, result=result,
    )
    result.record_protocol("schannel", messages=len(lines))


def _decrypt_with_derived_keylog(
    pcap_path, derived_keylog, tshark_bin, tls_ports, *, bus, state, result,
) -> None:
    """Drive the standard TLS single-pass over the derived keylog (option a).

    Reuses ``_emit_tls_streams_singlepass`` and the TLS metadata pass exactly as the
    ``has_keys`` branch of :func:`convert_pcap_to_tap` does — the recovered Schannel
    flows are decrypted and reconstructed as ordinary TLS flows.
    """
    from friTap.offline.pcap_to_tap import (
        _StreamDirectionTracker,
        _emit_tls_streams_singlepass,
        _extract_tls_metadata_safe,
    )

    tls_tracker = _StreamDirectionTracker(server_ports=tls_ports)
    tls_meta_by_stream = _extract_tls_metadata_safe(
        tshark_bin, pcap_path, derived_keylog,
        tls_ports=tls_ports, extra_decode_as=(), heuristic=False,
    )
    _emit_tls_streams_singlepass(
        tshark_bin, pcap_path, derived_keylog,
        tls_ports=tls_ports, extra_decode_as=(), heuristic=False,
        bus=bus, state=state, result=result, tracker=tls_tracker,
        tls_meta_by_stream=tls_meta_by_stream,
    )


def build_schannel_offline_decryptor_entry() -> OfflineDecryptorEntry:
    """Build the Schannel :class:`OfflineDecryptorEntry`.

    The decrypted output is standard TLS (the derived keylog drives the normal TLS
    pass), so the flow layer is :class:`~friTap.flow.layers.TlsLayer`.
    """
    from friTap.flow.layers import TlsLayer

    return OfflineDecryptorEntry(
        protocol_name="schannel",
        cli_flag="--schannel-unpaired",
        cli_dest="schannel_unpaired",
        requires_tls_strip=False,
        emitter=_schannel_offline_emitter,
        layer_cls=TlsLayer,
        counter_prefix="schannel",
        cli_help=(
            "Schannel mem-scan '.schannel.unpaired' sidecar. friTap trial-decrypts "
            "each recovered TLS 1.2/1.3 secret against the pcap to find its "
            "client_random, writes a derived NSS keylog next to the sidecar, and "
            "decrypts the paired TLS flows. Use when Schannel secrets were recovered "
            "from lsass but carry no client_random."
        ),
        picker_group="tls",
        accepts_keylog=looks_like_unpaired,
    )
