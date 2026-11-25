"""Android multi-process capture from a discovery profile (--profile/--discover/--also-package).

Apps such as Gemini send their traffic through delegate apps (Google Search's
``:googleapp``/``:interactor``). Those processes respawn ~0.1 s after
``am force-stop``, so the order is fixed: gate their packages, turn spawn
gating on, *then* force-stop them, so the respawn arrives gated and is
instrumented from its first connection. Candidates still running afterwards
are attached late. Shared system processes mix many apps' traffic and are
only reported, never hooked.
"""

from __future__ import annotations

import logging
import shlex
from typing import Callable, Iterable, Optional

from ..android import run_adb
from ..android_discovery import (
    CaptureProfile,
    discover_profile,
    is_valid_android_package,
    load_profile,
    non_shared_packages,
    running_candidates,
    shared_only_packages,
)
from ..text_safety import visible_controls

USAP_POOL_PROPERTY = "persist.device_config.runtime_native.usap_pool_enabled"
ADB_TIMEOUT = 15

logger = logging.getLogger("friTap.profile_capture")

Shell = Callable[[str], str]


def capture_continues_after_main_detach(profile_active: bool, capture_started: bool,
                                        child_pids: Iterable[int]) -> bool:
    """Whether the main target's detach leaves the capture running.

    Only with a profile, only once the capture started (a death during startup
    stays a startup failure), and only while an instrumented child/spawn lives.
    """
    return bool(profile_active and capture_started and set(child_pids))


def gate_packages(profile: Optional[CaptureProfile], also_packages: Iterable[str]) -> list:
    """The profile's gate packages (minus shared-system-only ones) plus --also-package ones, deduplicated."""
    packages = _profile_gate_packages(profile) if profile is not None else []
    return list(dict.fromkeys([*packages, *(pkg for pkg in also_packages if pkg)]))


def _profile_gate_packages(profile: CaptureProfile) -> list:
    """Gate packages of *profile* without packages only shared system processes use."""
    shared = shared_only_packages(profile)
    return [pkg for pkg in profile.gate_packages if pkg not in shared]


def packages_to_force_stop(profile: Optional[CaptureProfile], also_packages: Iterable[str],
                           target: str) -> list:
    """Non-shared packages other than the target: stopped so they respawn gated."""
    packages = non_shared_packages(profile) if profile is not None else []
    return [pkg for pkg in dict.fromkeys([*packages, *also_packages]) if pkg and pkg != target]


def parse_ps_names(text: str) -> dict:
    """``{pid: name}`` from ``ps -A -o PID,NAME`` output (header and junk lines skipped)."""
    running = {}
    for line in text.splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2 and fields[0].isdigit():
            running[int(fields[0])] = fields[1].strip()
    return running


def still_running(candidates: Iterable, running: dict) -> list:
    """Candidates whose pid still runs under the same process name (no pid reuse)."""
    return [cand for cand in candidates if running.get(cand.pid) == cand.process]


def summary_lines(profile: Optional[CaptureProfile], packages: Iterable[str]) -> list:
    """Startup summary: gate packages, candidate roles, shared processes reported only."""
    shown = ", ".join(visible_controls(pkg) for pkg in packages)
    lines = [f"Profile capture: spawn-gating packages {shown or '(none)'}"]
    if profile is None:
        return lines
    for cand in profile.attributable_candidates():
        lines.append(_candidate_line(cand))
    for cand in profile.shared_candidates():
        lines.append(_candidate_line(cand) + " - reported only, not hooked")
    return lines


def _candidate_line(cand) -> str:
    """``  <role> <process> (pid N)`` with the profile's (untrusted) strings escaped."""
    return f"  {visible_controls(cand.role):<12} {visible_controls(cand.process)} (pid {cand.pid})"


def make_adb_shell(serial: Optional[str]) -> Shell:
    """``cmd -> stdout`` over ``adb [-s serial] shell``; empty on failure."""
    base = ["adb", "-s", serial] if serial else ["adb"]

    def shell(cmd: str) -> str:
        try:
            result = run_adb([*base, "shell", cmd], capture_output=True, text=True,
                             timeout=ADB_TIMEOUT, check=False)
        except (OSError, ValueError) as exc:
            logger.warning("adb shell %r failed: %s", cmd, exc)
            return ""
        return result.stdout or ""

    return shell


def resolve_profile(device_config, target: str, serial: Optional[str]) -> Optional[CaptureProfile]:
    """The profile from --profile, or a fresh --discover run, else None."""
    if device_config.profile_path:
        return load_profile(device_config.profile_path)
    if device_config.discover_seconds:
        logger.info("Discovering the processes that carry %s for %.0f s; use the app now.",
                    target, device_config.discover_seconds)
        return discover_profile(serial, target, device_config.discover_seconds)
    return None


def adb_serial_of(ssl_logger) -> Optional[str]:
    """The adb serial: ``-m <serial>``, else the Frida device id."""
    if isinstance(ssl_logger.mobile, str):
        return ssl_logger.mobile
    return getattr(getattr(ssl_logger, "device", None), "id", None)


class ProfileCaptureWorkflow:
    """Gate, force-stop and late-attach the processes of one profile capture."""

    def __init__(self, ssl_logger, profile: Optional[CaptureProfile],
                 also_packages: Iterable[str], shell: Shell):
        self._logger = ssl_logger
        self.profile = profile
        self.also_packages = list(also_packages)
        self._shell = shell

    @classmethod
    def for_logger(cls, ssl_logger) -> Optional["ProfileCaptureWorkflow"]:
        """The workflow when -m with --profile/--discover/--also-package asked for one, else None."""
        device_config = ssl_logger._config.device
        if not ssl_logger.mobile or not device_config.profile_capture_requested:
            return None
        serial = adb_serial_of(ssl_logger)
        profile = resolve_profile(device_config, ssl_logger.target_app, serial)
        return cls(ssl_logger, profile, device_config.also_packages, make_adb_shell(serial))

    @property
    def target(self) -> str:
        return self._logger.target_app

    def prepare(self, enable_gating: Callable[[], None]) -> None:
        """Gate the packages, enable spawn gating, and only then force-stop the delegates."""
        packages = gate_packages(self.profile, self.also_packages)
        for line in summary_lines(self.profile, packages):
            logger.info(line)
        self._logger.add_spawn_packages(*packages)
        if self.profile is not None:
            self._logger.set_process_roles(self.profile.role_by_process())
        self._logger.keep_capture_while_children_alive()
        enable_gating()
        self._warn_if_usap_pool_enabled()
        self._force_stop(packages_to_force_stop(self.profile, self.also_packages, self.target))

    def _warn_if_usap_pool_enabled(self) -> None:
        if self._shell(f"getprop {USAP_POOL_PROPERTY}").strip().lower() != "true":
            return
        logger.warning(
            "The USAP pool is enabled: pre-forked app processes may escape spawn gating. "
            "Disable it with: adb shell su -c 'setprop %s false' (then restart the device)",
            USAP_POOL_PROPERTY)

    def _force_stop(self, packages: Iterable[str]) -> None:
        for package in packages:
            if not is_valid_android_package(package):
                logger.warning("Not force-stopping %s: not a valid Android package name",
                               visible_controls(package))
                continue
            logger.info("Force-stopping %s so it respawns under spawn gating", package)
            self._shell(f"am force-stop {shlex.quote(package)}")

    def attach_survivors(self) -> None:
        """Attach late to profile candidates still running after the force-stop."""
        if self.profile is None:
            return
        survivors = still_running(running_candidates(self.profile),
                                  parse_ps_names(self._shell("ps -A -o PID,NAME")))
        already = self._logger.tracked_child_pids()
        for cand in survivors:
            if cand.pid not in already:
                self._logger.instrument_running(cand.pid, cand.process, cand.role)
