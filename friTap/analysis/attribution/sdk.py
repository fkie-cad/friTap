"""Offline SDK attribution: map a captured call stack to its owning SDK.

:class:`SdkResolver` answers "which SDK emitted this request" by matching the
class/package names (Java/ObjC) and native module names found in a captured
backtrace against a bundled, offline signature table
(``data/sdk_signatures.json``). It is the call-stack counterpart to the
host-based :class:`~friTap.analysis.attribution.resolver.TrackerResolver`:

* ``classify_package`` resolves a single fully-qualified class/package name by
  **longest matching dotted prefix** (so ``com.google.firebase.crashlytics.X``
  resolves to Crashlytics rather than the broader Firebase entry).
* ``classify_frames`` scans a whole backtrace top-down and returns the SDK of
  the first frame that matches a signature.

The resolver performs **no network and no I/O at import time**. The bundled
signature file is read once, lazily, when a :class:`SdkResolver` is built.

Trust model: the ``sdk``/``vendor``/``category`` strings come from the bundled
table and are therefore *trusted* — they are safe to surface directly and must
**not** be wrapped in an ``untrusted`` envelope. Only the frame strings handed
in by callers are untrusted input; this module never echoes them back — it
returns only the trusted signature metadata, or ``None``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple, Tuple

_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_SDK_SIGNATURES_PATH = _DATA_DIR / "sdk_signatures.json"

#: Allowed SDK category slugs. A signature's category is normalised to one of
#: these; anything unexpected is surfaced verbatim from the trusted table.
SDK_CATEGORIES = (
    "advertising",
    "analytics",
    "social",
    "attribution",
    "crash_reporting",
    "push",
    "payment",
    "maps",
    "networking",
    "framework",
    "other",
)

#: Package/module prefixes that are platform runtime or generic transport noise
#: — never an SDK identity on their own. Used ONLY to skip non-matching frames
#: while scanning a backtrace; a frame is always tested against the SDK
#: signatures first, so a real SDK frame is never skipped by this set.
_IGNORED_PREFIXES = frozenset(
    {
        "java.",
        "javax.",
        "android.",
        "androidx.",
        "dalvik.",
        "sun.",
        "kotlin.",
        "kotlinx.",
        "com.android.okhttp",
        "okhttp3.internal",
        "com.android.org.conscrypt",
        "org.conscrypt",
    }
)


@dataclass(frozen=True)
class Sdk:
    """Identity of a single SDK resolved from a call stack.

    :param sdk: the SDK's display name, e.g. ``"Facebook SDK"``.
    :param vendor: the owning organisation, e.g. ``"Meta"``.
    :param category: one of :data:`SDK_CATEGORIES` (e.g. ``advertising``,
        ``analytics``, ``crash_reporting``, ``networking``, ``framework``).
    """

    sdk: str
    vendor: str
    category: str

    def as_dict(self) -> Dict[str, str]:
        """Return a plain ``dict`` view (stable key order) for serialisation."""
        return {"sdk": self.sdk, "vendor": self.vendor, "category": self.category}


def _normalize_prefix(prefix: str) -> str:
    """Strip surrounding whitespace and any trailing dot from a signature key.

    Signature keys are written both with and without a trailing dot (e.g.
    ``"com.facebook."`` and ``"okhttp3"``); normalising to the dot-free form
    lets the dot-boundary matcher treat them uniformly.
    """
    return prefix.strip().rstrip(".")


def _matches_prefix(name: str, prefix: str) -> bool:
    """Return ``True`` if ``name`` sits under ``prefix`` on a dot boundary.

    The name must either equal the prefix or continue it after a literal dot,
    so ``"com.facebook"`` matches ``"com.facebook.appevents.X"`` but not
    ``"com.facebookx.Foo"``. For non-dotted native module keys this reduces to
    an exact or ``"<key>.<rest>"`` match (so ``libcronet`` matches
    ``libcronet.so``). Matching is case-sensitive.
    """
    return name == prefix or name.startswith(prefix + ".")


class SdkResolver:
    """Resolve class/package/module names to an owning :class:`Sdk`.

    The bundled signature table is loaded once on construction and reused
    across calls; no network or implicit I/O happens afterwards.
    """

    def __init__(self, signatures_path: Path | str = DEFAULT_SDK_SIGNATURES_PATH) -> None:
        self._signatures = self._load_signatures(Path(signatures_path))

    @staticmethod
    def _load_signatures(path: Path) -> Dict[str, Sdk]:
        """Load the bundled ``prefix -> Sdk`` table from JSON (offline)."""
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
        table: Dict[str, Sdk] = {}
        for prefix, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            key = _normalize_prefix(prefix)
            if not key:
                continue
            table[key] = Sdk(
                sdk=meta.get("sdk", ""),
                vendor=meta.get("vendor", ""),
                category=meta.get("category", "other"),
            )
        return table

    def _match(self, name: str) -> Optional[Tuple[str, Sdk]]:
        """Return the longest matching signature ``(prefix, Sdk)`` or ``None``.

        A specific entry (``com.google.firebase.crashlytics``) always beats a
        broader one (``com.google.firebase``) because the longest dot-boundary
        prefix wins.
        """
        if not name:
            return None
        best_prefix: Optional[str] = None
        for prefix in self._signatures:
            if _matches_prefix(name, prefix) and (
                best_prefix is None or len(prefix) > len(best_prefix)
            ):
                best_prefix = prefix
        if best_prefix is None:
            return None
        return best_prefix, self._signatures[best_prefix]

    def classify_package(self, name: str) -> Optional[Sdk]:
        """Resolve a fully-qualified class/package name by longest prefix.

        Scans every signature whose prefix matches ``name`` on a dot boundary
        and returns the :class:`Sdk` of the **longest** such prefix, so a
        specific entry (``com.google.firebase.crashlytics``) always beats a
        broader one (``com.google.firebase``). Returns ``None`` when nothing
        matches.
        """
        match = self._match(name)
        return match[1] if match is not None else None

    def classify_frames(
        self,
        java_frames: Iterable[str] = (),
        native_modules: Iterable[str] = (),
    ) -> Optional[Sdk]:
        """Resolve a backtrace to the SDK of its first matching frame.

        :param java_frames: fully-qualified Java/ObjC class names, ordered
            top-of-stack first.
        :param native_modules: native library names (e.g. ``"libflutter.so"``),
            ordered top-of-stack first.

        Java frames are scanned first, top-down: each frame is tested against
        the SDK signatures, and the first match is returned. A frame is skipped
        as runtime/transport noise when a known ignored prefix (see
        :data:`_IGNORED_PREFIXES`) matches it *more specifically* than any SDK
        signature does — so ``okhttp3.internal.*`` is dropped while a genuine
        ``okhttp3.*`` SDK frame, matched at least as specifically, is kept.
        Native modules are scanned the same way. Returns ``None`` if nothing
        matches.
        """
        for frame in java_frames:
            match = self._match(frame)
            if match is not None and len(match[0]) >= _longest_ignored_len(frame):
                return match[1]
            # Otherwise the frame is noise (pure platform/transport, or an
            # ignored sub-namespace that is more specific than its broad SDK
            # prefix, e.g. okhttp3.internal under okhttp3): skip it.
        for module in native_modules:
            matched = self.classify_package(module)
            if matched is not None:
                return matched
        return None


def _longest_ignored_len(name: str) -> int:
    """Return the length of the longest ignored prefix matching ``name``.

    ``0`` when ``name`` is not platform runtime or transport noise. Used to
    decide whether a frame's noise classification is *more specific* than its
    SDK-signature match (e.g. ``okhttp3.internal`` beats the broad ``okhttp3``).
    """
    best = 0
    for prefix in _IGNORED_PREFIXES:
        if _matches_prefix(name, prefix) and len(prefix) > best:
            best = len(prefix)
    return best


_default_resolver: Optional[SdkResolver] = None


def _resolver() -> SdkResolver:
    """Return the cached default resolver, building it on first use."""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = SdkResolver()
    return _default_resolver


def classify_package(name: str) -> Optional[Sdk]:
    """Resolve a single class/package name via the cached default resolver."""
    return _resolver().classify_package(name)


def classify_frames(
    java_frames: Iterable[str] = (),
    native_modules: Iterable[str] = (),
) -> Optional[Sdk]:
    """Resolve a backtrace via the cached default resolver."""
    return _resolver().classify_frames(java_frames, native_modules)
