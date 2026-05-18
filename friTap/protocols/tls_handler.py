#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TLS/SSL protocol handler."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, List, Optional, Pattern, Sequence

from .base import ProtocolHandler, BackendSupport
from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent

TLS_LIBRARY_PATTERNS = [
    "libssl", "libcrypto", "libgnutls", "libwolfssl", "libmbedtls",
    "libnss", "boringssl", "schannel", "secur32", "conscrypt",
    "cronet", "flutter", "monotls",
]


# Declarative table of "split-topology" relationships: modules whose BoringSSL
# handshake state machine (and ssl_log_secret) actually lives in a sibling
# module loaded alongside them.  When such a sibling is present, scanning the
# higher-level module is futile by construction and friTap should skip it.
#
# Each entry:
#   module_regex   — matches the *covered* module name (e.g. libmainlinecronet.<ver>.so)
#   library_type   — required library_type on both the covered module AND the sibling
#                    (the sibling must itself be confirmed BoringSSL, not just a name match)
#   sibling_regexes — list of regexes; ANY match against another loaded module name
#                     of the same library_type triggers suppression
#   reason         — user-facing explanation
CRONET_SPLIT_TOPOLOGIES: List[Dict] = [
    {
        "module_regex": re.compile(r"^libmainlinecronet\.[\d.]+\.so$"),
        "library_type": "boringssl",
        "sibling_regexes": [re.compile(r"^stable_cronet_libssl\.so$")],
        "reason": (
            "Cronet APEX split: BoringSSL handshake state machine lives in "
            "stable_cronet_libssl.so; libmainlinecronet is the higher-level "
            "runtime and contains no ssl_log_secret of its own."
        ),
    },
]


def _force_scan_matches(name: str, force_scan_modules: Sequence[str]) -> bool:
    """Return True if `name` matches any entry in `force_scan_modules`.

    A force-scan entry may be a literal module name, a stem prefix (suffix
    with ``*``), or a regex prefixed with ``re:``.
    """
    for spec in force_scan_modules:
        if not spec:
            continue
        if spec.startswith("re:"):
            try:
                if re.search(spec[3:], name):
                    return True
            except re.error:
                continue
        elif spec == name or name.startswith(spec.rstrip("*")):
            return True
    return False


def covered_by_sibling(
    detected_libraries: List[Dict],
    force_scan_modules: Sequence[str] = (),
) -> Dict[str, Dict[str, str]]:
    """Compute the set of modules that should be skipped because a sibling
    library already covers their BoringSSL surface.

    Returns a mapping ``module_name -> {"sibling": str, "reason": str}``
    for every entry that has a confirmed sibling in the same scan. Returns
    ``{}`` when there is nothing to suppress.
    """
    if not detected_libraries:
        return {}

    covered: Dict[str, Dict[str, str]] = {}

    for entry in detected_libraries:
        name = entry.get("name")
        lib_type = entry.get("library_type")
        if not name or not lib_type:
            continue
        if _force_scan_matches(name, force_scan_modules):
            continue

        for topology in CRONET_SPLIT_TOPOLOGIES:
            if topology["library_type"] != lib_type:
                continue
            module_regex: Pattern[str] = topology["module_regex"]
            if not module_regex.match(name):
                continue

            sibling_name = _find_sibling(
                name,
                lib_type,
                topology["sibling_regexes"],
                detected_libraries,
            )
            if sibling_name is None:
                continue

            covered[name] = {
                "sibling": sibling_name,
                "reason": topology["reason"],
            }
            break

    return covered


def _find_sibling(
    self_name: str,
    library_type: str,
    sibling_regexes: List[Pattern[str]],
    detected_libraries: List[Dict],
) -> Optional[str]:
    """Return the name of a trusted sibling matching any of ``sibling_regexes``.

    A trusted sibling is another entry in ``detected_libraries`` with the same
    ``library_type`` and a different name.  Returns ``None`` if no sibling
    qualifies.
    """
    for other in detected_libraries:
        other_name = other.get("name")
        other_type = other.get("library_type")
        if not other_name or other_name == self_name:
            continue
        if other_type != library_type:
            continue
        for sibling_regex in sibling_regexes:
            if sibling_regex.match(other_name):
                return other_name
    return None


def strip_covered_modules(
    pattern_data: Optional[Dict],
    covered: Dict[str, Dict[str, str]],
    force_scan_modules: Sequence[str] = (),
) -> Optional[Dict]:
    """Remove covered-by-sibling module entries from a pattern.json structure.

    Pattern keys are coarse (``libmainlinecronet.so``) while runtime module
    names are versioned (``libmainlinecronet.141.0.7340.3.so``), so matching
    is done by stem prefix. Entries marked ``"_force_scan": true`` are kept
    regardless of the sibling check.
    """
    if not pattern_data or not isinstance(pattern_data, dict) or not covered:
        return pattern_data

    modules_section = pattern_data.get("modules")
    if not isinstance(modules_section, dict):
        return pattern_data

    covered_stems = {_module_stem(name) for name in covered.keys()}
    if not covered_stems:
        return pattern_data

    new_modules = {}
    for key, value in modules_section.items():
        if isinstance(value, dict) and value.get("_force_scan"):
            new_modules[key] = value
            continue
        if _force_scan_matches(key, force_scan_modules):
            new_modules[key] = value
            continue
        if _module_stem(key) in covered_stems:
            continue
        new_modules[key] = value

    if new_modules == modules_section:
        return pattern_data

    stripped = dict(pattern_data)
    stripped["modules"] = new_modules
    return stripped


def _module_stem(name: str) -> str:
    """Reduce a module filename to its prefix up to the first digit-version run.

    Examples:
        libmainlinecronet.141.0.7340.3.so -> libmainlinecronet
        libmainlinecronet.so              -> libmainlinecronet
        stable_cronet_libssl.so           -> stable_cronet_libssl
        libcronet.107.0.5304.105.so       -> libcronet
    """
    stem = name
    if stem.endswith(".so"):
        stem = stem[:-3]
    # Split off any trailing dot-separated version components.
    parts = stem.split(".")
    head: List[str] = []
    for part in parts:
        if part and part[0].isdigit():
            break
        head.append(part)
    return ".".join(head) if head else stem


class TlsKeylogFormatter(KeylogFormatter):
    """NSS SSLKEYLOGFILE-style passthrough.

    TLS agents already emit ``KeylogEvent.key_data`` pre-formatted as
    ``CLIENT_RANDOM <hex> <hex>`` / ``EXPORTER-* <…>`` / etc., so the
    base :meth:`KeylogFormatter.format` default already does the right
    thing; only the dedup key needs a cheaper override.
    """

    @property
    def protocol(self) -> str:
        return "tls"

    def dedup_key(self, event: "KeylogEvent") -> str:
        return event.key_data


class TLSHandler(ProtocolHandler):
    """Handler for TLS/SSL protocol key material and data."""

    library_patterns = TLS_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "tls"

    @property
    def display_name(self) -> str:
        return "TLS/SSL"

    def get_keylog_format(self) -> str:
        return "NSS Key Log Format"

    def get_wireshark_protocol_preference(self) -> str:
        return "tls.keylog_file"

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return TlsKeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {
            BackendName.FRIDA: BackendSupport.FULL,
            BackendName.GDB: BackendSupport.STUB,
            BackendName.LLDB: BackendSupport.STUB,
            BackendName.EBPF: BackendSupport.STUB,
        }
