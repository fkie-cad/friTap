"""TlsHygieneAnalyzer: flag deprecated TLS/SSL versions, weak ciphers and cleartext.

Reports problems only; a healthy flow (TLS 1.2/1.3, strong AEAD suite) yields
no finding. Findings are ``category="network"`` (digest ``security``/``all``
focus, never ``privacy``) with a ``cwe`` and a stable ``metadata["check"]`` id
keyed by :mod:`friTap.analysis.masvs`.

Data source: live capture records no handshake metadata, so ``flow.tls``
``version``/``cipher`` exist only on offline pcap-derived ``.tap`` files (see
:mod:`friTap.flow.collector`, ``_stamp_tls_metadata``); live, those checks stay
silent. Cleartext is reported conservatively: no TLS/QUIC layer, a known
plaintext port, and an actually parsed HTTP request/response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from friTap.analysis import Finding, Severity
from friTap.analysis._limits import clip
from friTap.analysis.filtering import with_category

if TYPE_CHECKING:
    from friTap.flow.models import Flow


_CWE_WEAK_CRYPTO = "CWE-327"      # Use of a Broken or Risky Cryptographic Algorithm
_CWE_INADEQUATE_STRENGTH = "CWE-326"  # Inadequate Encryption Strength
_CWE_NO_PFS = "CWE-310"           # Cryptographic Issues (missing forward secrecy)
_CWE_CLEARTEXT = "CWE-319"        # Cleartext Transmission of Sensitive Information

# Ports the offline plaintext-pcap ingest treats as cleartext HTTP servers
# (mirrors friTap.offline.pcap_to_tap._PLAINTEXT_SERVER_PORTS).
_PLAINTEXT_PORTS = frozenset({80, 8080, 8000})


def _normalize_version(version: str) -> str:
    """Collapse spellings (``"TLS 1.2"``, ``"TLSv1.2"``, ``"SSL 3.0"``) to ``"TLS1.2"`` / ``"SSL3.0"`` form."""
    return version.upper().replace("V", "").replace(" ", "").replace("_", "").strip()


def _version_weakness(version: str) -> tuple[Severity, str, str] | None:
    """``(severity, label, cwe)`` for a known-weak version; unrecognized strings and TLS 1.2/1.3 give ``None``."""
    s = _normalize_version(version)
    if not s:
        return None
    if s.startswith("SSL"):
        # SSL 2.0 and 3.0 are both broken (POODLE, DROWN).
        return (Severity.HIGH, "obsolete SSL", _CWE_WEAK_CRYPTO)
    if s in ("TLS1", "TLS1.0"):
        return (Severity.MEDIUM, "deprecated TLS 1.0", _CWE_INADEQUATE_STRENGTH)
    if s == "TLS1.1":
        return (Severity.MEDIUM, "deprecated TLS 1.1", _CWE_INADEQUATE_STRENGTH)
    return None


def _cipher_weakness(cipher: str) -> tuple[Severity, str, str] | None:
    """``(severity, label, cwe)`` for a weak cipher suite (IANA or OpenSSL names), else ``None``.

    Most-severe check first, first match wins (RC4 over missing PFS). TLS 1.3
    suites match no rule.
    """
    c = cipher.upper()
    if not c:
        return None
    if "NULL" in c:
        return (Severity.HIGH, "NULL cipher (no encryption)", _CWE_WEAK_CRYPTO)
    if "EXPORT" in c or "_EXP" in c:
        return (Severity.HIGH, "export-grade cipher", _CWE_WEAK_CRYPTO)
    if "ANON" in c or "AECDH" in c or c.startswith("ADH"):
        return (Severity.HIGH, "anonymous (unauthenticated) cipher", _CWE_WEAK_CRYPTO)
    if "RC4" in c:
        return (Severity.HIGH, "RC4 cipher", _CWE_WEAK_CRYPTO)
    if "3DES" in c:
        return (Severity.MEDIUM, "3DES cipher (Sweet32)", _CWE_WEAK_CRYPTO)
    if "DES" in c:
        return (Severity.HIGH, "DES cipher (56-bit)", _CWE_WEAK_CRYPTO)
    if "MD5" in c:
        return (Severity.MEDIUM, "MD5 MAC", _CWE_WEAK_CRYPTO)
    # Static RSA (no PFS): only the unambiguous IANA form, to avoid false positives.
    if c.startswith("TLS_RSA_WITH") or c.startswith("SSL_RSA_WITH"):
        return (Severity.LOW, "no forward secrecy (static RSA)", _CWE_NO_PFS)
    return None


class TlsHygieneAnalyzer:
    """Flag deprecated TLS versions, weak ciphers, and cleartext transport."""

    name = "tls_hygiene"

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        self._check_transport_security(flow, findings)
        self._check_cleartext(flow, findings)
        return findings

    def _check_transport_security(self, flow: "Flow", findings: list[Finding]) -> None:
        """Check the version/cipher of the flow's TLS or QUIC layer, if any."""
        layer = flow.layer("tls") or flow.layer("quic")
        if layer is None:
            return
        transport = getattr(layer, "name", "tls")
        host = flow.display_host

        weakness = _version_weakness(getattr(layer, "version", "") or "")
        if weakness is not None:
            severity, label, cwe = weakness
            version = getattr(layer, "version", "")
            findings.append(with_category(Finding(
                severity=severity,
                title=f"Weak {transport.upper()} version: {clip(version, 32)}",
                description=(f"{host} negotiated {clip(version, 32)} ({label}); "
                             f"use TLS 1.2 or newer."),
                source=self.name,
                flow_id=flow.flow_id,
                evidence={"type": "tls_version", "value": version,
                          "host": host, "transport": transport},
            ), "network", cwe=cwe, extra_metadata={"check": "weak_tls_version"}))

        weakness = _cipher_weakness(getattr(layer, "cipher", "") or "")
        if weakness is not None:
            severity, label, cwe = weakness
            cipher = getattr(layer, "cipher", "")
            findings.append(with_category(Finding(
                severity=severity,
                title=f"Weak cipher suite: {clip(cipher, 48)}",
                description=(f"{host} negotiated {clip(cipher, 48)} ({label})."),
                source=self.name,
                flow_id=flow.flow_id,
                evidence={"type": "cipher", "value": cipher,
                          "host": host, "transport": transport},
            ), "network", cwe=cwe, extra_metadata={"check": "weak_cipher"}))

    def _check_cleartext(self, flow: "Flow", findings: list[Finding]) -> None:
        """Flag a parsed HTTP flow on a plaintext port with no TLS/QUIC layer (conservative, see module docstring)."""
        if flow.layer("tls") is not None or flow.layer("quic") is not None:
            return
        port = getattr(flow, "dst_port", 0) or 0
        if port not in _PLAINTEXT_PORTS:
            return
        if flow.request is None and flow.response is None:
            return
        host = flow.display_host
        findings.append(with_category(Finding(
            severity=Severity.MEDIUM,
            title="Cleartext HTTP (no TLS)",
            description=(f"{host}:{port} was contacted over unencrypted HTTP; "
                         f"any data on this flow was sent in the clear."),
            source=self.name,
            flow_id=flow.flow_id,
            evidence={"type": "cleartext", "host": host, "port": port},
        ), "network", cwe=_CWE_CLEARTEXT, extra_metadata={"check": "cleartext_transport"}))


__all__ = ["TlsHygieneAnalyzer"]
