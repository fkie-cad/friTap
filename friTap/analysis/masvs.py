"""
OWASP MASVS v2.1 control mapping for friTap findings.

Maps a :class:`~friTap.analysis.Finding` to the Mobile Application Security
Verification Standard controls it bears on, so an agent can report in a
standard vocabulary (plan item #18). This is pure, offline and **additive**: it
derives control ids from a finding's ``metadata["check"]`` (set by the
TLS-hygiene analyzer) and its ``category`` (plus a couple of cheap keyword
refinements), and never mutates the finding.

It is applied only on explicit opt-in (the ``masvs`` flag on ``get_digest`` /
``list_findings``), so default tool output is unchanged. The control ids are
the stable MASVS v2.1 identifiers (reference: https://mas.owasp.org/MASVS/).

The mapping is deliberately conservative: findings with no defensible control
(generic network IOCs, protocol observations) return an empty list and are left
untagged rather than forced into a bucket.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis import Finding

#: MASVS v2.1 controls referenced by this mapping (id -> short description).
MASVS_CONTROLS: dict[str, str] = {
    "MASVS-CRYPTO-1": "Uses current, strong cryptography and key management.",
    "MASVS-AUTH-1": "Uses secure authentication and authorization protocols.",
    "MASVS-NETWORK-1": "Secures all network traffic per current best practices.",
    "MASVS-PRIVACY-1": "Minimizes access to sensitive data and resources.",
    "MASVS-PRIVACY-2": "Prevents identification of the user across services.",
}

#: TLS-hygiene check id (Finding.metadata["check"]) -> MASVS controls.
_CHECK_CONTROLS: dict[str, tuple[str, ...]] = {
    "weak_tls_version": ("MASVS-NETWORK-1",),
    "weak_cipher": ("MASVS-NETWORK-1", "MASVS-CRYPTO-1"),
    "cleartext_transport": ("MASVS-NETWORK-1",),
}

#: Finding category -> baseline MASVS controls.
_CATEGORY_CONTROLS: dict[str, tuple[str, ...]] = {
    "secret": ("MASVS-CRYPTO-1",),
    "pii": ("MASVS-PRIVACY-1",),
}

#: A secret that reads as an auth token/JWT is an authentication concern too.
_AUTH_KEYWORDS = (
    "jwt", "bearer", "oauth", "access token", "refresh token",
    "session token", "auth token", "authorization",
)

#: PII that is a stable device/advertising identifier enables cross-service
#: identification (MASVS-PRIVACY-2), beyond the baseline data-minimization.
_DEVICE_ID_KEYWORDS = (
    "advertising", "aaid", "gaid", "idfa", "android_id", "android id",
    "imei", "device id", "deviceid", "fingerprint", "mac address",
)


def classify_masvs(finding: "Finding") -> list[str]:
    """Return the sorted MASVS control ids a *finding* maps to (``[]`` if none)."""
    controls: set[str] = set()

    check = (finding.metadata or {}).get("check")
    if check in _CHECK_CONTROLS:
        controls.update(_CHECK_CONTROLS[check])

    category = finding.category
    if category in _CATEGORY_CONTROLS:
        controls.update(_CATEGORY_CONTROLS[category])
        text = f"{finding.title} {finding.description}".lower()
        if category == "secret" and any(kw in text for kw in _AUTH_KEYWORDS):
            controls.add("MASVS-AUTH-1")
        if category == "pii" and any(kw in text for kw in _DEVICE_ID_KEYWORDS):
            controls.add("MASVS-PRIVACY-2")

    return sorted(controls)


__all__ = ["classify_masvs", "MASVS_CONTROLS"]
