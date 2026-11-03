"""Apple platform binaries (``/usr/bin/curl`` & co.) as friTap spawn targets.

On Apple silicon every binary Apple ships is an *arm64e platform binary*
(``codesign -dv`` reports ``Platform identifier=<n>``). Frida can only inject
into such a process when the kernel accepts third-party arm64e code (boot-arg
``-arm64e_preview_abi``) and frida runs as root; without that, the kernel kills
frida-helper and Frida reports ``PermissionDeniedError: oops, frida-helper
appears to have crashed ...``. Disabling SIP alone is not enough.

What works from user space (verified on macOS 26.6, Frida 17.24): a *copy* of
the binary, thinned to its native slice and ad-hoc re-signed
(``codesign -f -s -``), is no longer a platform binary and is instrumentable
without root or boot-args. Its LibreSSL/BoringSSL libraries still come from the
system, so the normal friTap hooks capture keys and plaintext. The Rosetta
(x86_64) slice does *not* help: Frida 17 fails on translated processes
("unexpected error while probing dyld" / "unable to read from process memory").

This module (a) detects the case before spawning and fails fast with the exact
options, (b) implements the opt-in ``--macos-unsign-copy`` workaround and
(c) turns the cryptic frida-helper crash into the same hint for attach mode.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.fritap_utility import Failure

ARM64E_BOOT_ARG = "-arm64e_preview_abi"
BOOT_ARGS_COMMAND = f'sudo nvram boot-args="{ARM64E_BOOT_ARG}"'
# The fuller variant Frida itself prints in its frida-helper crash message.
FRIDA_BOOT_ARGS_COMMAND = (
    f'sudo nvram boot-args="{ARM64E_BOOT_ARG} thid_should_crash=0 tss_should_crash=0"'
)
UNSIGN_COPY_FLAG = "--macos-unsign-copy"
_HARDENED_CRASH_MARKERS = ("frida-helper appears to have crashed", "hardened process")
_PROBE_TIMEOUT = 5

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class MacOSTargetInfo:
    """What codesign/lipo say about a target executable."""

    path: str
    archs: tuple
    platform_binary: bool

    @property
    def has_arm64e(self) -> bool:
        return "arm64e" in self.archs

    @property
    def native_slice(self) -> Optional[str]:
        """The Apple-silicon slice the kernel runs natively (arm64e before arm64)."""
        for arch in ("arm64e", "arm64"):
            if arch in self.archs:
                return arch
        return None


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def _run(run: Runner, cmd: Sequence[str]) -> Optional[subprocess.CompletedProcess]:
    try:
        return run(list(cmd), capture_output=True, text=True, timeout=_PROBE_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None


def probe_target(path: str, run: Runner = subprocess.run) -> Optional[MacOSTargetInfo]:
    """Return slice/platform-binary facts for ``path``, or None if not probe-able."""
    sign = _run(run, ["codesign", "-dv", path])
    archs = _run(run, ["lipo", "-archs", path])
    if sign is None or archs is None or archs.returncode != 0:
        return None
    sign_text = (sign.stderr or "") + (sign.stdout or "")
    return MacOSTargetInfo(
        path=path,
        archs=tuple((archs.stdout or "").split()),
        platform_binary="Platform identifier=" in sign_text,
    )


def read_boot_args(run: Runner = subprocess.run) -> str:
    """Return the active kernel boot-args (``sysctl kern.bootargs``)."""
    result = _run(run, ["sysctl", "-n", "kern.bootargs"])
    return (result.stdout or "").strip() if result is not None else ""


def host_is_apple_silicon(run: Runner = subprocess.run) -> bool:
    """True on Apple silicon, also when Python itself runs under Rosetta."""
    if platform.machine() == "arm64":
        return True
    result = _run(run, ["sysctl", "-n", "hw.optional.arm64"])
    return result is not None and (result.stdout or "").strip() == "1"


def privileged_injection_possible(boot_args: str) -> bool:
    """The arm64e boot-arg is the hard prerequisite Frida names for platform binaries."""
    return ARM64E_BOOT_ARG in boot_args.split()


def resolve_executable(token: str) -> Optional[str]:
    """Resolve a spawn token (``curl`` or ``/usr/bin/curl``) to a real file path."""
    candidate = token if os.sep in token else shutil.which(token)
    if candidate and os.path.isfile(candidate):
        return os.path.realpath(candidate)
    return None


def is_hardened_process_error(message: str) -> bool:
    """True for Frida's 'frida-helper appears to have crashed' denial."""
    lowered = (message or "").lower()
    return any(marker in lowered for marker in _HARDENED_CRASH_MARKERS)


# --------------------------------------------------------------------------
# User-facing text
# --------------------------------------------------------------------------

def platform_binary_hint_lines(path: str, info: Optional[MacOSTargetInfo] = None) -> List[str]:
    """Return the exact, actionable options for an Apple platform binary target."""
    name = os.path.basename(path) or path
    what = "an Apple platform binary"
    if info is not None and info.archs:
        what += f" ({', '.join(info.archs)})"
    return [
        f"{path} is {what}. Frida cannot inject into it without root and the "
        f"arm64e boot-arg: the kernel kills frida-helper when it touches the process.",
        "  Options:",
        f"  1) No root, no reboot: re-run with -s {UNSIGN_COPY_FLAG}. friTap spawns an "
        f"ad-hoc signed copy of {name} from a temp dir (thinned to arm64e, deleted "
        "afterwards). It is a copy: Apple's entitlements are dropped.",
        f"  2) Use a non-Apple build, e.g. Homebrew: `brew install {name}`, then spawn "
        f"`$(brew --prefix {name})/bin/{name}`.",
        "  3) Instrument the original: with SIP disabled (`csrutil status`), set the "
        f"boot-arg `{BOOT_ARGS_COMMAND}` (Frida suggests `{FRIDA_BOOT_ARGS_COMMAND}`), "
        "REBOOT, then run friTap as root (`sudo fritap ...`).",
    ]


def hardened_process_hint_lines(message: str, target: str = "") -> List[str]:
    """Hint lines for a frida-helper crash on macOS; [] when it does not apply."""
    if platform.system() != "Darwin" or not is_hardened_process_error(message):
        return []
    path = resolve_executable(target.split()[0]) if target.strip() else None
    return platform_binary_hint_lines(path or target or "The target")


# --------------------------------------------------------------------------
# The --macos-unsign-copy workaround
# --------------------------------------------------------------------------

def make_unsigned_copy(info: MacOSTargetInfo, run: Runner = subprocess.run,
                       tmp_root: Optional[str] = None) -> str:
    """Copy, thin and ad-hoc sign ``info.path``; return the copy's path.

    Raises RuntimeError with the failing tool's stderr when a step fails.
    """
    work_dir = tempfile.mkdtemp(prefix="fritap-unsigned-", dir=tmp_root)
    copy = os.path.join(work_dir, os.path.basename(info.path))
    try:
        slice_ = info.native_slice
        if slice_ and len(info.archs) > 1:
            _checked(run, ["lipo", info.path, "-thin", slice_, "-output", copy])
        else:
            shutil.copy2(info.path, copy)
        os.chmod(copy, 0o755)
        _checked(run, ["codesign", "--force", "--sign", "-", copy])
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    return copy


def _checked(run: Runner, cmd: Sequence[str]) -> None:
    result = _run(run, cmd)
    if result is None or result.returncode != 0:
        detail = (result.stderr or "").strip() if result is not None else "could not run"
        raise RuntimeError(f"`{' '.join(cmd)}` failed: {detail}")


def schedule_cleanup(path: str, owner_pid: Optional[int] = None,
                     popen: Optional[Callable[..., object]] = None) -> None:
    """Remove ``path`` once friTap exits.

    friTap leaves through ``os._exit`` (no atexit), so a tiny detached watcher
    waits for the friTap pid to disappear. It runs in its own session, so it
    survives Ctrl-C, ``Failure`` exits and a SIGKILL of friTap alike. Unlinking
    the binary of a still running copy is harmless on macOS.
    """
    pid = str(owner_pid or os.getpid())
    script = 'while kill -0 "$1" 2>/dev/null; do sleep 2; done; rm -rf -- "$2"'
    (popen or subprocess.Popen)(
        ["/bin/sh", "-c", script, "fritap-cleanup", pid, path],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)


# --------------------------------------------------------------------------
# Entry point used by friTap.cli()
# --------------------------------------------------------------------------

def _spawn_token(parsed) -> Optional[str]:
    argv = getattr(parsed, "exec_argv", None) or (
        [parsed.exec] if getattr(parsed, "exec", None) else []
    )
    return argv[0] if argv else None


def _applies(parsed) -> bool:
    return (platform.system() == "Darwin" and bool(getattr(parsed, "spawn", False))
            and not getattr(parsed, "mobile", False) and not getattr(parsed, "host", None))


def _fail(lines: List[str], logger) -> None:
    raise Failure(info="\n".join(lines), logger=logger, code=EXIT_RUNTIME_ERROR)


def _replace_spawn_path(parsed, new_path: str) -> None:
    argv = list(getattr(parsed, "exec_argv", None) or [parsed.exec])
    argv[0] = new_path
    parsed.exec_argv = argv
    parsed.exec = " ".join(argv)


def prepare_macos_spawn_target(parsed, logger, run: Runner = subprocess.run,
                               cleanup: Optional[Callable[[str], None]] = None) -> None:
    """Fail fast (exit 1) or swap in an ad-hoc signed copy for Apple platform binaries.

    No-op unless: macOS host on Apple silicon, local spawn (-s), and the target
    is a platform binary with an arm64e slice. ``cleanup`` defaults to
    :func:`schedule_cleanup` (looked up at call time, so tests can replace it).
    """
    if not _applies(parsed):
        return
    token = _spawn_token(parsed)
    path = resolve_executable(token) if token else None
    if path is None or not host_is_apple_silicon(run):
        return
    info = probe_target(path, run)
    if info is None or not (info.platform_binary and info.has_arm64e):
        if getattr(parsed, "macos_unsign_copy", False):
            logger.info("%s is not an Apple platform binary; %s not needed.",
                        path, UNSIGN_COPY_FLAG)
        return
    if getattr(parsed, "macos_unsign_copy", False):
        _spawn_unsigned_copy(parsed, logger, info, run, cleanup or schedule_cleanup)
        return
    if privileged_injection_possible(read_boot_args(run)):
        if os.geteuid() != 0:
            logger.warning("%s is an Apple platform binary: run friTap as root "
                           "(sudo) or injection will most likely fail.", path)
        return
    _fail(platform_binary_hint_lines(path, info), logger)


def _spawn_unsigned_copy(parsed, logger, info: MacOSTargetInfo, run: Runner,
                         cleanup: Callable[[str], None]) -> None:
    if ".app/Contents/" in info.path:
        _fail([f"{UNSIGN_COPY_FLAG} supports plain executables only, not app "
               f"bundles ({info.path})."], logger)
    try:
        copy = make_unsigned_copy(info, run)
    except (OSError, RuntimeError) as exc:
        _fail([f"{UNSIGN_COPY_FLAG}: could not prepare a signed copy of "
               f"{info.path}: {exc}"], logger)
    work_dir = os.path.dirname(copy)
    try:
        cleanup(work_dir)
    except Exception as exc:
        # No watcher, no deferred removal: delete now rather than leak the copy.
        shutil.rmtree(work_dir, ignore_errors=True)
        _fail([f"{UNSIGN_COPY_FLAG}: could not schedule removal of {work_dir}: {exc}"], logger)
    _replace_spawn_path(parsed, copy)
    logger.warning(
        "%s: spawning an ad-hoc signed copy %s (slice %s) instead of the Apple "
        "platform binary %s. Entitlements of the original are dropped; the copy "
        "is deleted when friTap exits.",
        UNSIGN_COPY_FLAG, copy, info.native_slice or "original", info.path)
