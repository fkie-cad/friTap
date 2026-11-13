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
  the first frame that matches a signature. Native modules whose signature
  carries a ``transport_kind`` (Cronet, Chrome/WebView, Flutter, ...) are the
  *transport* that carried the flow, not its *originator*, so they are skipped
  there (the deny-list).
* ``classify_transport`` answers the other half: which transport module carried
  the flow (``{"module", "kind"}``), matched on the module basename.

Extra signature files can be layered over the bundled table, either via the
``extra_paths`` constructor argument or, for the module-level singleton, via
the ``FRITAP_SDK_SIGNATURES`` environment variable (``os.pathsep``-separated).
An overlay's ``chromium_browser_packages`` and ``chromium_internal_hosts``
lists are unioned with the bundled ones.

:func:`is_chromium_internal_host` answers whether a host is a Chromium/WebView/
Cronet background service (Safe Browsing, component updater, variations, ...)
listed under ``chromium_internal_hosts``: the ``chromium-internal`` bucket.

The resolver performs **no network and no I/O at import time**. The bundled
signature file is read once, lazily, when a :class:`SdkResolver` is built.

Trust model: the ``sdk``/``vendor``/``category`` strings come from the bundled
table and are therefore *trusted* — they are safe to surface directly and must
**not** be wrapped in an ``untrusted`` envelope. Only the frame strings handed
in by callers are untrusted input; this module never echoes them back — it
returns only the trusted signature metadata, or ``None``.
"""

from __future__ import annotations

import functools
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Optional, Sequence, Tuple

from friTap.analysis.attribution.resolver import normalize_hostname
from friTap.flow.attribution import KIND_PATTERN, module_basename

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_SDK_SIGNATURES_PATH = _DATA_DIR / "sdk_signatures.json"

#: Environment variable naming extra signature overlay files
#: (``os.pathsep``-separated), merged over the bundled table by the singleton.
SDK_SIGNATURES_ENV = "FRITAP_SDK_SIGNATURES"

#: ``transport_kind`` sentinel for libraries shared by Chrome and WebView
#: (libmonochrome, libchrome); resolved per process by :func:`_resolve_kind`.
CHROME_OR_WEBVIEW = "chrome-or-webview"

#: Top-level signature-file key listing the Chromium-based browsers whose own
#: network stack a ``chrome-or-webview`` module is (kind ``chrome``); any other
#: process loading that module is a WebView host (kind ``webview``).
CHROMIUM_BROWSER_PACKAGES_KEY = "chromium_browser_packages"

#: Top-level signature-file key listing the hosts of Chromium's own background
#: services (exact ``host`` or ``*.suffix`` patterns): an unattributed
#: Chromium-family flow to one of them gets ``attribution.bucket =
#: "chromium-internal"`` (see :func:`is_chromium_internal_host`).
CHROMIUM_INTERNAL_HOSTS_KEY = "chromium_internal_hosts"

#: Fallback internal-host patterns, used only when the bundled signature file
#: has no :data:`CHROMIUM_INTERNAL_HOSTS_KEY` list: none (no bucket is filled).
DEFAULT_CHROMIUM_INTERNAL_HOSTS: Tuple[str, ...] = ()

#: Fallback browser patterns, used only when the bundled signature file has no
#: :data:`CHROMIUM_BROWSER_PACKAGES_KEY` list. Exact names, or a ``prefix*``
#: pattern; matched case-insensitively. Keep in sync with
#: ``_CHROME_FAMILY_TARGETS`` in ``friTap/friTap.py`` (the CLI's Chrome
#: subprocess hint), which also lists the Frida friendly name ``Chrome``.
DEFAULT_CHROMIUM_BROWSER_PACKAGES = (
    "com.android.chrome",
    "com.google.android.apps.chrome",
    "org.chromium.chrome",
    "chrome",  # the friendly name Frida resolves on Android
    "com.chrome.*",  # beta/dev/canary
)

#: Path markers that identify the Play-services (GMS) Cronet provider.
_GMS_PATH_MARKERS = ("com.google.android.gms", "/dynamite")

#: Characters allowed directly after a transport key in a module basename.
_TRANSPORT_KEY_BOUNDARY = frozenset(("", ".", "_", "-"))

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
    "transport",
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
class ChromiumBrowserPackages:
    """Matcher for the package/process names of Chromium-based browsers.

    :param exact: lower-cased exact names.
    :param prefixes: lower-cased prefixes (from ``prefix*`` patterns).
    """

    exact: FrozenSet[str] = frozenset()
    prefixes: Tuple[str, ...] = ()

    @classmethod
    def from_patterns(cls, patterns: Iterable[str]) -> "ChromiumBrowserPackages":
        """Build a matcher from already-validated ``name`` / ``prefix*`` patterns."""
        lowered = {pattern.strip().lower() for pattern in patterns}
        return cls(
            exact=frozenset(p for p in lowered if not p.endswith("*")),
            prefixes=tuple(sorted(p[:-1] for p in lowered if p.endswith("*"))),
        )

    def matches(self, name: str) -> bool:
        """``True`` if ``name`` (``:suffix`` stripped, any case) is a listed browser."""
        base = (name or "").split(":", 1)[0].strip().lower()
        if not base:
            return False
        return base in self.exact or base.startswith(self.prefixes)


@dataclass(frozen=True)
class ChromiumInternalHosts:
    """Matcher for the hosts of Chromium's own background services.

    :param exact: lower-cased exact hosts.
    :param suffixes: lower-cased ``.suffix`` strings (from ``*.suffix``
        patterns); ``*.gvt1.com`` matches ``a.gvt1.com`` but not ``gvt1.com``.
    """

    exact: FrozenSet[str] = frozenset()
    suffixes: Tuple[str, ...] = ()

    @classmethod
    def from_patterns(cls, patterns: Iterable[str]) -> "ChromiumInternalHosts":
        """Build a matcher from already-validated ``host`` / ``*.suffix`` patterns."""
        lowered = {normalize_hostname(pattern) for pattern in patterns}
        return cls(
            exact=frozenset(p for p in lowered if not p.startswith("*.")),
            suffixes=tuple(sorted(p[1:] for p in lowered if p.startswith("*."))),
        )

    def matches(self, host: str) -> bool:
        """``True`` if ``host`` (port and trailing dot stripped, any case) is listed."""
        base = normalize_host(host)
        if not base:
            return False
        return base in self.exact or base.endswith(self.suffixes)


def normalize_host(host: str) -> str:
    """Lower-cased *host* without port, trailing dot or spaces; IPv6 literals kept as-is."""
    base = str(host or "").strip().lower()
    if base.startswith("["):
        return base.split("]", 1)[0] + "]" if "]" in base else ""
    if base.count(":") == 1:
        base = base.split(":", 1)[0]
    return normalize_hostname(base)


@dataclass(frozen=True)
class Sdk:
    """Identity of a single SDK resolved from a call stack.

    :param sdk: the SDK's display name, e.g. ``"Facebook SDK"``.
    :param vendor: the owning organisation, e.g. ``"Meta"``.
    :param category: one of :data:`SDK_CATEGORIES` (e.g. ``advertising``,
        ``analytics``, ``crash_reporting``, ``networking``, ``framework``).
    :param transport_kind: non-empty for transport modules (e.g. ``cronet``,
        ``webview``); such entries are never returned as an originator from
        native frames. Deliberately not part of :meth:`as_dict`.
    """

    sdk: str
    vendor: str
    category: str
    transport_kind: str = ""

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

    def __init__(
        self,
        signatures_path: Path | str = DEFAULT_SDK_SIGNATURES_PATH,
        extra_paths: Sequence[Path | str] = (),
    ) -> None:
        payload = _read_payload(Path(signatures_path))
        self._signatures = _build_table(_payload_entries(payload))
        browser_patterns = set(_browser_patterns(
            payload, Path(signatures_path), default=DEFAULT_CHROMIUM_BROWSER_PACKAGES))
        internal_hosts = set(_internal_host_patterns(
            payload, Path(signatures_path), default=DEFAULT_CHROMIUM_INTERNAL_HOSTS))
        for extra_path in extra_paths:
            overlay = _load_overlay_payload(Path(extra_path))
            self._signatures.update(_build_table(_payload_entries(overlay)))
            browser_patterns.update(_browser_patterns(overlay, Path(extra_path)))
            internal_hosts.update(_internal_host_patterns(overlay, Path(extra_path)))
        self._chromium_browsers = ChromiumBrowserPackages.from_patterns(browser_patterns)
        self._chromium_internal_hosts = ChromiumInternalHosts.from_patterns(internal_hosts)
        self._transports = {
            key.lower(): entry
            for key, entry in self._signatures.items()
            if entry.transport_kind
        }

    def is_chromium_internal_host(self, host: str) -> bool:
        """``True`` if *host* is a listed Chromium background-service host."""
        return self._chromium_internal_hosts.matches(host)

    def _match_transport(self, module: str) -> Optional[Sdk]:
        """Return the longest transport entry matching ``module``'s basename."""
        basename = module_basename(module).lower()
        best_key: Optional[str] = None
        for key in self._transports:
            if _matches_transport_key(basename, key) and (
                best_key is None or len(key) > len(best_key)
            ):
                best_key = key
        return self._transports[best_key] if best_key is not None else None

    def classify_transport(
        self,
        module: str,
        path: str = "",
        process_name: str = "",
        package_name: str = "",
    ) -> Optional[Dict[str, str]]:
        """Resolve the transport module that carried a flow.

        Returns ``{"module": <basename>, "kind": <kind>}`` or ``None`` for an
        empty or unknown module. ``chrome-or-webview`` libraries resolve to
        ``chrome`` inside a Chromium-based browser (the
        ``chromium_browser_packages`` list) and ``webview`` elsewhere;
        ``cronet`` loaded from a Play-services path resolves to ``gms-cronet``.
        """
        if not module:
            return None
        entry = self._match_transport(module)
        if entry is None:
            return None
        is_browser = _is_chrome_process(process_name, package_name, self._chromium_browsers)
        kind = _resolve_kind(entry.transport_kind, path, is_browser)
        return {"module": module_basename(module), "kind": kind}

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
        Native modules are scanned the same way. In both scans a frame whose
        best match is a transport entry (one with a ``transport_kind``) is
        skipped (deny-list): a transport such as ``libcronet`` (or an overlay's
        Java transport package) carried the request but did not originate it.
        Returns ``None`` if nothing matches.
        """
        for frame in java_frames:
            match = self._match(frame)
            if match is None or match[1].transport_kind:
                continue  # unknown, or the transport that carried the request
            if len(match[0]) >= _longest_ignored_len(frame):
                return match[1]
            # Otherwise the frame is noise (an ignored sub-namespace more
            # specific than its broad SDK prefix, e.g. okhttp3.internal under
            # okhttp3): skip it.
        for module in native_modules:
            matched = self.classify_package(module)
            if matched is not None and not matched.transport_kind:
                return matched
        return None


def _build_table(entries: object) -> Dict[str, Sdk]:
    """Build the normalised ``prefix -> Sdk`` table from raw JSON entries."""
    table: Dict[str, Sdk] = {}
    if not isinstance(entries, dict):
        return table
    for prefix, meta in entries.items():
        key = _normalize_prefix(prefix)
        if isinstance(meta, dict) and key:
            table[key] = Sdk(
                sdk=meta.get("sdk", ""),
                vendor=meta.get("vendor", ""),
                category=meta.get("category", "other"),
                transport_kind=_validated_transport_kind(key, meta.get("transport_kind")),
            )
    return table


def _validated_transport_kind(key: str, raw: object) -> str:
    """*raw* when it is a valid transport kind, else ``""`` (with a warning).

    Valid: a :data:`~friTap.flow.attribution.KIND_PATTERN` slug or the
    :data:`CHROME_OR_WEBVIEW` sentinel. Anything else (a non-string, an
    upper-case or over-long name) is warned about and the entry is treated as
    having no transport kind, so it never reaches ``attribution.transport``.
    """
    if raw is None or raw == "":
        return ""
    if isinstance(raw, str) and (raw == CHROME_OR_WEBVIEW or KIND_PATTERN.fullmatch(raw)):
        return raw
    logger.warning("Ignoring invalid transport_kind %r for SDK signature %r", raw, key)
    return ""


def _read_payload(path: Path) -> object:
    """The parsed JSON of a signature file.

    Raises :class:`OSError` / :class:`ValueError` when the file is unreadable
    or not JSON.
    """
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _payload_entries(payload: object) -> object:
    """The raw ``entries`` value of a parsed signature file (``None`` when absent)."""
    return payload.get("entries") if isinstance(payload, dict) else None


def _load_overlay_payload(path: Path) -> Optional[dict]:
    """Parse an overlay file; warn and return ``None`` if unusable.

    Usable means a JSON object with an ``entries`` object and/or a
    :data:`CHROMIUM_BROWSER_PACKAGES_KEY` / :data:`CHROMIUM_INTERNAL_HOSTS_KEY`
    list.
    """
    try:
        payload = _read_payload(path)
    except (OSError, ValueError) as exc:
        logger.warning("Skipping SDK signature overlay %s: %s", path, exc)
        return None
    if not isinstance(payload, dict) or not (
        isinstance(payload.get("entries"), dict)
        or CHROMIUM_BROWSER_PACKAGES_KEY in payload
        or CHROMIUM_INTERNAL_HOSTS_KEY in payload
    ):
        logger.warning("Skipping SDK signature overlay %s: no 'entries' object", path)
        return None
    return payload


def _browser_patterns(
    payload: object, path: Path, default: Tuple[str, ...] = ()
) -> Tuple[str, ...]:
    """Valid :data:`CHROMIUM_BROWSER_PACKAGES_KEY` patterns of a payload (invalid ones warned and dropped)."""
    return _pattern_list(payload, path, CHROMIUM_BROWSER_PACKAGES_KEY,
                         _is_valid_browser_pattern, default)


def _internal_host_patterns(
    payload: object, path: Path, default: Tuple[str, ...] = ()
) -> Tuple[str, ...]:
    """Valid :data:`CHROMIUM_INTERNAL_HOSTS_KEY` patterns of a payload (invalid ones warned and dropped)."""
    return _pattern_list(payload, path, CHROMIUM_INTERNAL_HOSTS_KEY,
                         _is_valid_host_pattern, default)


def _pattern_list(
    payload: object, path: Path, key: str, is_valid, default: Tuple[str, ...] = ()
) -> Tuple[str, ...]:
    """Stripped valid items of *payload*'s *key* list; *default* when absent, ``()`` for a non-list."""
    if not isinstance(payload, dict) or key not in payload:
        return tuple(default)
    raw = payload[key]
    if not isinstance(raw, list):
        logger.warning("Ignoring non-list %s in %s", key, path)
        return ()
    valid = tuple(item.strip() for item in raw if is_valid(item))
    if len(valid) != len(raw):
        logger.warning("Ignoring invalid %s items in %s", key, path)
    return valid


def _is_valid_browser_pattern(item: object) -> bool:
    """``True`` for ``name`` or ``prefix*`` (non-empty, ``*`` only at the end)."""
    if not isinstance(item, str):
        return False
    stem = item.strip()
    stem = stem[:-1] if stem.endswith("*") else stem
    return bool(stem) and "*" not in stem and ":" not in stem


def _is_valid_host_pattern(item: object) -> bool:
    """``True`` for ``host`` or ``*.suffix``: non-empty dot-separated labels,
    no other ``*``, no port, path, scheme or whitespace."""
    if not isinstance(item, str):
        return False
    stem = item.strip().lower()
    stem = stem[2:] if stem.startswith("*.") else stem
    stem = stem.rstrip(".")
    if not stem or any(ch in stem for ch in "*:/@ \t"):
        return False
    return all(stem.split("."))


def _matches_transport_key(basename: str, key: str) -> bool:
    """Return ``True`` if lower-cased ``basename`` matches transport ``key``.

    Keys ending in ``.so``/``.dll`` must match exactly; other keys match as a
    prefix followed by end, ``.``, ``_`` or ``-`` (``libmonochrome_64.so``).
    """
    if key.endswith((".so", ".dll")):
        return basename == key
    if not basename.startswith(key):
        return False
    return basename[len(key):len(key) + 1] in _TRANSPORT_KEY_BOUNDARY


def _is_chrome_process(
    process_name: str,
    package_name: str,
    browsers: ChromiumBrowserPackages,
) -> bool:
    """Return ``True`` if the package or process (``:suffix`` stripped) is a
    Chromium-based browser in ``browsers``.

    Case-insensitive. A numeric PID cannot be resolved here: the caller must
    pass the resolved process name.
    """
    return browsers.matches(package_name) or browsers.matches(process_name)


def _resolve_kind(kind: str, path: str, is_chromium_browser: bool) -> str:
    """Apply the process- and path-dependent transport kind rules."""
    if kind == CHROME_OR_WEBVIEW:
        return "chrome" if is_chromium_browser else "webview"
    if kind == "cronet" and any(m in (path or "").lower() for m in _GMS_PATH_MARKERS):
        return "gms-cronet"
    return kind


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
        _default_resolver = SdkResolver(extra_paths=_env_overlay_paths())
    return _default_resolver


def _env_overlay_paths() -> Tuple[str, ...]:
    """Return the overlay paths named by :data:`SDK_SIGNATURES_ENV`."""
    raw = os.environ.get(SDK_SIGNATURES_ENV, "")
    return tuple(part for part in raw.split(os.pathsep) if part.strip())


def reset_default_resolver() -> None:
    """Drop the cached default resolver so the next call rebuilds it.

    Intended for tests that change :data:`SDK_SIGNATURES_ENV`.
    """
    global _default_resolver
    _default_resolver = None
    _cached_transport.cache_clear()
    _cached_java_frames.cache_clear()
    _cached_internal_host.cache_clear()


def classify_package(name: str) -> Optional[Sdk]:
    """Resolve a single class/package name via the cached default resolver."""
    return _resolver().classify_package(name)


def classify_frames(
    java_frames: Iterable[str] = (),
    native_modules: Iterable[str] = (),
) -> Optional[Sdk]:
    """Resolve a backtrace via the cached default resolver."""
    return _resolver().classify_frames(java_frames, native_modules)


def classify_transport(
    module: str,
    path: str = "",
    process_name: str = "",
    package_name: str = "",
) -> Optional[Dict[str, str]]:
    """Resolve a flow's transport module via the cached default resolver.

    Memoised (the same module/process repeats on every flow and HTTP/2
    stream); each call returns a fresh dict the caller may keep or mutate.
    """
    classified = _cached_transport(module, path, process_name, package_name)
    return dict(classified) if classified is not None else None


#: Bound on the memoised :func:`classify_transport` results.
_TRANSPORT_CACHE_SIZE = 256


@functools.lru_cache(maxsize=_TRANSPORT_CACHE_SIZE)
def _cached_transport(
    module: str, path: str, process_name: str, package_name: str
) -> Optional[Dict[str, str]]:
    """Shared, never-mutated classification result; cleared by :func:`reset_default_resolver`."""
    return _resolver().classify_transport(module, path, process_name, package_name)


def classify_java_frames(java_frames: Tuple[str, ...]) -> Optional[Dict[str, str]]:
    """``{sdk, vendor, category}`` of a Java-only backtrace, else ``None``.

    Memoised like :func:`classify_transport` (request contexts repeat the same
    stacks); each call returns a fresh dict.
    """
    classified = _cached_java_frames(tuple(java_frames))
    return dict(classified) if classified is not None else None


#: Bound on the memoised :func:`classify_java_frames` results.
_JAVA_FRAMES_CACHE_SIZE = 256


@functools.lru_cache(maxsize=_JAVA_FRAMES_CACHE_SIZE)
def _cached_java_frames(java_frames: Tuple[str, ...]) -> Optional[Dict[str, str]]:
    """Shared, never-mutated result; cleared by :func:`reset_default_resolver`."""
    sdk = _resolver().classify_frames(java_frames=java_frames)
    return sdk.as_dict() if sdk is not None else None


def is_chromium_internal_host(host: str) -> bool:
    """``True`` if *host* (Host/``:authority`` or SNI; port and case ignored)
    is a Chromium background-service host of the default resolver.

    Memoised; cleared by :func:`reset_default_resolver`.
    """
    if not host:
        return False
    return _cached_internal_host(str(host))


#: Bound on the memoised :func:`is_chromium_internal_host` results.
_INTERNAL_HOST_CACHE_SIZE = 1024


@functools.lru_cache(maxsize=_INTERNAL_HOST_CACHE_SIZE)
def _cached_internal_host(host: str) -> bool:
    """Uncached :func:`is_chromium_internal_host`; cleared by :func:`reset_default_resolver`."""
    return _resolver().is_chromium_internal_host(host)
