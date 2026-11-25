"""Adapter over tlsLibHunter's Android process discovery (``tlslibhunter.discovery``).

A discovery *profile* names the processes that carry an app's TLS traffic:
the app itself, its ``:process`` siblings, delegate apps (e.g. Google Search
for Gemini), SDK sandboxes and shared system processes. friTap reads only a
few of its fields, so ``--profile`` works without tlsLibHunter installed; only
live discovery (``--discover``) needs it, imported lazily like in inspector.py.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .text_safety import visible_controls

PROFILE_SCHEMA = "tlslibhunter.profile/1"

ROLE_TARGET = "target"
ROLE_SIBLING = "sibling"
ROLE_DELEGATE = "delegate"
ROLE_SDK_SANDBOX = "sdk_sandbox"
ROLE_SHARED_SYSTEM = "shared_system"

DISCOVERY_SAMPLE_INTERVAL = 2.0

# Dot-separated identifiers ("com.example.app"); no shell metacharacter can match.
_ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# A package's own process ("pkg") or one of its ":name" processes ("pkg:googleapp").
_PROCESS_SUFFIX_RE = re.compile(r"^[A-Za-z0-9_.]+$")
# Characters of an untrusted value quoted in an error message.
_EXCERPT_LIMIT = 80


class DiscoveryUnavailableError(RuntimeError):
    """tlsLibHunter (with its ``discovery`` package) is not installed."""


class DiscoveryFailedError(RuntimeError):
    """Live discovery (``--discover``) failed unexpectedly on the device."""


def is_valid_android_package(name: object) -> bool:
    """True for an Android package name shape (``com.example.app``); always shell safe."""
    return isinstance(name, str) and bool(_ANDROID_PACKAGE_RE.fullmatch(name))


def is_valid_android_process(name: object) -> bool:
    """True for ``pkg`` or ``pkg:proc`` where *pkg* is a valid package name."""
    if not isinstance(name, str):
        return False
    package, sep, suffix = name.partition(":")
    if not is_valid_android_package(package):
        return False
    return not sep or bool(_PROCESS_SUFFIX_RE.fullmatch(suffix))


def untrusted_excerpt(value: object) -> str:
    """*value* with control characters escaped and cut short, for an error message."""
    text = visible_controls(value)
    return text if len(text) <= _EXCERPT_LIMIT else text[:_EXCERPT_LIMIT] + "..."


def require_android_package(name: object, what: str) -> str:
    """*name* if it is a valid package name, else ValueError naming *what*."""
    if not is_valid_android_package(name):
        raise ValueError(f"invalid Android package name in {what}: {untrusted_excerpt(name)!r}")
    return name


@dataclass(frozen=True)
class ProfileCandidate:
    """One process of a profile: what friTap needs to gate, attach or report it."""

    pid: int
    process: str
    package: str
    role: str

    @property
    def is_attributable(self) -> bool:
        """False for shared system processes whose traffic mixes many apps."""
        return self.role != ROLE_SHARED_SYSTEM


@dataclass(frozen=True)
class CaptureProfile:
    """friTap's read-only view of a ``tlslibhunter.profile/1`` document."""

    target_package: str
    gate_packages: tuple = ()
    process_patterns: tuple = ()
    candidates: tuple = field(default_factory=tuple)

    def attributable_candidates(self) -> list:
        return [cand for cand in self.candidates if cand.is_attributable]

    def shared_candidates(self) -> list:
        return [cand for cand in self.candidates if not cand.is_attributable]

    def role_by_process(self) -> dict:
        """``process name -> role`` of the attributable candidates."""
        return {cand.process: cand.role for cand in self.attributable_candidates()}


def _candidate_from_dict(data: dict) -> ProfileCandidate:
    cand = ProfileCandidate(pid=int(data["pid"]), process=str(data["process"]),
                            package=str(data["package"]), role=str(data["role"]))
    if cand.is_attributable:
        _require_valid_candidate_names(cand)
    return cand


def _require_valid_candidate_names(cand: ProfileCandidate) -> None:
    """Attributable candidates are gated, force-stopped and attached: their names must be clean.

    Shared system processes (e.g. ``system_server``) are only reported, so they are not checked.
    """
    require_android_package(cand.package, "candidate package")
    if not is_valid_android_process(cand.process):
        raise ValueError(f"invalid Android process name in candidate: "
                         f"{untrusted_excerpt(cand.process)!r}")


def profile_from_dict(data: dict) -> CaptureProfile:
    """Build a view; raises ValueError on a wrong schema or a malformed document."""
    if not isinstance(data, dict) or data.get("schema") != PROFILE_SCHEMA:
        found = data.get("schema") if isinstance(data, dict) else type(data).__name__
        raise ValueError(f"unsupported profile schema: {found!r} (expected {PROFILE_SCHEMA!r})")
    try:
        return CaptureProfile(
            target_package=require_android_package(data["target_package"], "target_package"),
            gate_packages=tuple(require_android_package(pkg, "gate_packages")
                                for pkg in data.get("gate_packages") or ()),
            process_patterns=tuple(str(p) for p in data.get("process_patterns") or ()),
            candidates=tuple(_candidate_from_dict(c) for c in data.get("candidates") or ()),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed discovery profile: {exc}") from exc


def load_profile(path: str) -> CaptureProfile:
    """Read a profile JSON file written by tlsLibHunter (no tlsLibHunter needed)."""
    with open(path, encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: not a JSON discovery profile ({exc})") from exc
    return profile_from_dict(data)


def _import_discovery():
    """tlsLibHunter's discovery engine module, or DiscoveryUnavailableError."""
    try:
        from tlslibhunter.discovery import engine
    except ImportError as exc:
        raise DiscoveryUnavailableError(
            "--discover needs tlsLibHunter with process discovery "
            "(tlslibhunter.discovery); install or upgrade tlsLibHunter, or pass a "
            "saved profile with --profile") from exc
    return engine


def discover_profile(serial: Optional[str], target_package: str, duration: float) -> CaptureProfile:
    """Sample the device for *duration* seconds and return the discovered profile."""
    return profile_from_dict(discover_profile_document(serial, target_package, duration))


def discover_profile_document(serial: Optional[str], target_package: str,
                              duration: float) -> dict:
    """Like :func:`discover_profile`, but the raw ``tlslibhunter.profile/1`` dict.

    The document keeps the fields friTap's view drops (``evidence``, ``uid``, ...) so it can be
    saved as a ``--profile`` file. It is validated with :func:`profile_from_dict` first.
    """
    engine = _import_discovery()
    try:
        runner = engine.make_adb_runner(serial)
        found = engine.discover(runner, target_package, duration, DISCOVERY_SAMPLE_INTERVAL)
        data = found.to_dict()
    except (OSError, ValueError):
        raise
    except Exception as exc:  # noqa: BLE001 - any engine failure becomes one clean error
        raise DiscoveryFailedError(
            f"process discovery failed: {type(exc).__name__}: {untrusted_excerpt(exc)}") from exc
    profile_from_dict(data)
    return data


def shared_only_packages(profile: CaptureProfile) -> set:
    """Packages seen only in shared system candidates (never gated: they serve many apps)."""
    shared = {cand.package for cand in profile.shared_candidates()}
    return shared - set(non_shared_packages(profile))


def non_shared_packages(profile: CaptureProfile) -> list:
    """Packages of attributable candidates, in first-seen order."""
    return _unique(cand.package for cand in profile.attributable_candidates())


def running_candidates(profile: CaptureProfile) -> list:
    """Attributable candidates other than the target's main process (friTap spawns or attaches that one)."""
    return [cand for cand in profile.attributable_candidates()
            if cand.process != profile.target_package]


def _unique(items: Iterable[str]) -> list:
    return list(dict.fromkeys(items))
