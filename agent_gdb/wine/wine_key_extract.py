#!/usr/bin/env python3

import argparse
import glob
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
from typing import List, Optional


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def resolve_wine_loader(wine_cmd: str = "wine", prefer_64: bool = True) -> str:
    """Resolve a wine command to the actual ELF loader gdb can ``file``.

    Different Wine installs expose ``wine`` very differently: a bare ELF loader
    (older Wine), a symlink chain into ``/etc/alternatives``, or a POSIX shell
    wrapper (Debian/Ubuntu ``wine-stable``) that execs ``/usr/lib/wine/wine64``.
    gdb's ``file`` needs a real ELF, so we chase the command down to one. The
    newer "wow64" layout has no ``wine-preloader`` and a separate ``wine64``.

    Returns the resolved ELF path, or *wine_cmd* unchanged if nothing better is
    found (gdb will then surface the error itself).
    """
    # An explicit ELF path (e.g. caller already passed /usr/lib/wine/wine64).
    if os.path.sep in wine_cmd and _is_elf(wine_cmd):
        return wine_cmd

    resolved = shutil.which(wine_cmd) or wine_cmd
    try:
        resolved = os.path.realpath(resolved)
    except OSError:
        pass
    if _is_elf(resolved):
        return resolved

    candidates: List[str] = []
    env_loader = os.environ.get("WINELOADER")
    if env_loader:
        candidates.append(env_loader)

    # If it is a shell wrapper, mine it for wine64=/wine= assignments.
    try:
        with open(resolved, "r", errors="ignore") as fh:
            text = fh.read(8192)
        for m in re.finditer(r"^\s*wine(?:64)?=(\S+)", text, re.MULTILINE):
            candidates.append(m.group(1))
    except OSError:
        pass

    # Common on-disk loader locations across distros.
    globs = [
        "/usr/lib/wine/wine64",
        "/usr/lib/wine/wine",
        "/usr/lib/*/wine/wine64",
        "/usr/lib/*/wine/wine",
        "/usr/lib64/wine/wine64",
        "/usr/lib64/wine/wine",
        "/usr/lib/*/wine/*-unix/wine",
        "/opt/wine*/bin/wine64",
        "/opt/wine*/bin/wine",
    ]
    for pattern in globs:
        candidates.extend(sorted(glob.glob(pattern)))

    # Prefer a 64-bit loader (wine64) when asked, else first ELF that exists.
    def _rank(path: str) -> int:
        is64 = path.endswith("wine64")
        return (0 if is64 == prefer_64 else 1)

    for path in sorted((c for c in candidates if _is_elf(c)), key=_rank):
        return path

    return wine_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wine_key_extract.py",
        description="Export TLS-Keys from running wine programs",
        usage="\n"
        r"%(prog)s --spawn prog.exe -k output.log -- <program arguments>"
        "\n"
        r"%(prog)s --attach 6548 -k output.log"
        "\n"
        r"%(prog)s --spawn prog.exe -k output.log --patterns patterns.json -- <program arguments>",
    )
    parser.add_argument(
        "-a", "--attach", metavar="PID", help="PID of program to attach to"
    )
    parser.add_argument("-s", "--spawn", metavar="EXECUTABLE", help="Program to spawn")
    parser.add_argument(
        "-k",
        "--keylog",
        metavar="LOCATION",
        help="write extracted keys to this file location",
    )
    parser.add_argument(
        "-p",
        "--patterns",
        metavar="FILE",
        help="functions patterns to hook",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose logging",
    )
    parser.add_argument(
        "-do",
        "--debug-output",
        dest="debug_output",
        action="store_true",
        help="enable debug output",
    )
    parser.add_argument(
        "-g", "--gdb", action="store_true", help="print gdb output for debugging"
    )
    parser.add_argument(
        "--wine-bin",
        dest="wine_bin",
        metavar="PATH",
        default="wine",
        help="wine loader binary used in spawn mode (default: wine)",
    )
    parser.add_argument(
        "program_args",
        nargs=argparse.REMAINDER,
        help=r"Arguments to pass to TARGET when spawning it (requires --spawn), "
        r"e.g. %(prog)s --spawn ./foo -- --bar baz",
    )

    return parser


def resolve_gdb_script_path() -> str:
    """Return the on-disk path to gdb_wine_extract.py.

    Works both from a source checkout (sibling directory) and from an installed
    wheel (the script ships as package data of ``agent_gdb.wine``). The gdb
    script is *data*, never imported as a module (it subclasses ``gdb.Breakpoint``
    at import time), so we only need a filesystem path to feed to ``gdb -x``.
    """
    try:
        from importlib.resources import files

        res = files("agent_gdb.wine").joinpath("gdb_script", "gdb_wine_extract.py")
        if res.is_file():
            return str(res)
    except (ImportError, ModuleNotFoundError, FileNotFoundError, AttributeError, TypeError):
        pass
    return str(
        pathlib.Path(__file__).resolve().parent / "gdb_script" / "gdb_wine_extract.py"
    )


def run_wine_key_extraction(
    *,
    attach: Optional[str] = None,
    spawn: Optional[str] = None,
    keylog: Optional[str] = None,
    patterns: Optional[str] = None,
    program_args: Optional[List[str]] = None,
    wine_bin: str = "wine",
    verbose: bool = False,
    debug_output: bool = False,
    gdb_output: bool = False,
    forward_signals: bool = True,
    on_process=None,
) -> int:
    """Run the gdb-based Wine TLS key extractor.

    Exactly one of ``attach`` (a PID) or ``spawn`` (an executable) must be given.
    Returns the gdb process exit code. This is the importable entry point used by
    both the standalone CLI below and friTap's Wine routing.

    ``on_process``, if given, is called once with the ``gdb`` ``Popen`` object
    right after it starts, so a caller running this in a background thread can
    terminate gdb (and thereby detach) during its own teardown.
    """
    if bool(attach) == bool(spawn):
        raise ValueError("exactly one of attach= or spawn= must be provided")

    script_path = resolve_gdb_script_path()

    log_fd = os.dup(sys.stdout.fileno())
    stdout_fd = os.dup(sys.stdout.fileno())
    stderr_fd = os.dup(sys.stderr.fileno())

    environment = os.environ.copy()

    # Spawn mode: gdb must `file` a real ELF loader, and the wine64 loader needs
    # WINELOADER to re-exec its child stages. Resolve whatever wine command we
    # were given down to the on-disk loader so this works across Wine layouts.
    if spawn:
        wine_bin = resolve_wine_loader(wine_bin or "wine")
        environment.setdefault("WINELOADER", wine_bin)
        server = os.path.join(os.path.dirname(wine_bin), "wineserver")
        if os.path.exists(server):
            environment.setdefault("WINESERVER", server)
    arguments = {
        "attach": attach,
        "spawn": spawn,
        "keylog": keylog,
        "patterns": patterns,
        "verbose": verbose,
        "debug_output": debug_output,
        "gdb": gdb_output,
        "wine-bin": wine_bin,
        "program_args": list(program_args or []),
        "log-fd": log_fd,
        "stdout-fd": stdout_fd,
        "stderr-fd": stderr_fd,
    }
    environment["FRITAP_ARGS"] = json.dumps(arguments)

    # Wire a --patterns FILE into the gdb script, which only reads the
    # FRITAP_PATTERNS env var (JSON hex-signature -> metadata). Without this the
    # CLI/caller-supplied patterns file would be ignored entirely.
    if patterns:
        with open(patterns) as pf:
            environment["FRITAP_PATTERNS"] = pf.read()

    cmd = ["gdb", "-ex", " set debuginfod enabled off ", "-x", script_path]
    popen_kwargs = {
        "env": environment,
        "pass_fds": (log_fd, stdout_fd, stderr_fd),
        # Own session so a caller can tear gdb down with killpg even if it has
        # spawned children; terminal SIGINT no longer reaches it, so the
        # KeyboardInterrupt forwarding below explicitly relays Ctrl-C.
        "start_new_session": True,
    }
    if not gdb_output:
        popen_kwargs["stdout"] = subprocess.DEVNULL
        popen_kwargs["stderr"] = subprocess.DEVNULL

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
        if on_process is not None:
            on_process(proc)
        while True:
            try:
                return proc.wait()
            except KeyboardInterrupt:
                # Forward Ctrl-C to gdb so it detaches/stops the target cleanly,
                # then keep waiting for it to exit. friTap installs its own
                # signal handler, so we cannot rely on terminal signal delivery.
                if forward_signals:
                    proc.send_signal(signal.SIGINT)
    finally:
        for fd in (log_fd, stdout_fd, stderr_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def _find_wine_app_pid(exe_basename, exclude_pids, deadline):
    """Poll /proc for the Wine process that actually does the TLS.

    Wine spawns the app as a child of an initial launcher process, and several
    processes share the exe name in their cmdline. We must attach to the one that
    *maps the TLS library* (where the keylog function lives) -- attaching to the
    short-lived parent makes gdb detach when it exits. So we keep polling until a
    matching process has libgnutls/libssl mapped, and only fall back to any name
    match once the timeout expires.
    """
    import time

    fallback = None
    while time.time() < deadline:
        for d in glob.glob("/proc/[0-9]*"):
            pid = d.split("/")[-1]
            if pid in exclude_pids:
                continue
            try:
                cmdline = open(d + "/cmdline", "rb").read().decode("latin1")
            except OSError:
                continue
            if exe_basename.lower() not in cmdline.lower():
                continue
            try:
                maps = open(d + "/maps").read()
            except OSError:
                maps = ""
            if "libgnutls" in maps or "libssl" in maps:
                return pid  # the process doing TLS -- attach here
            fallback = fallback or pid
        time.sleep(0.3)
    return fallback


def launch_and_attach(
    *,
    wine_cmd,
    program,
    program_args=None,
    keylog=None,
    patterns=None,
    verbose=False,
    debug_output=False,
    gdb_output=False,
    startup_timeout=20.0,
    on_process=None,
    logger=None,
) -> int:
    """Launch a Wine program normally, then attach the gdb extractor to it.

    Preferred over gdb-spawning Wine: under gdb's ``follow-fork``/
    ``detach-on-fork off``, Wine's cold boot (wineserver + services) can deadlock
    on the newer wow64 layout, so the app never runs. Launching via the normal
    ``wine`` wrapper gives a full bootstrap, and attaching then captures reliably
    (new_objfile hooks the TLS library whenever it is mapped). Requires
    ``kernel.yama.ptrace_scope=0`` (or root) so gdb may attach to a non-child.

    The launcher is started in its own session (``start_new_session=True``), so we
    launched the whole Wine process tree; ``on_process`` is called with that
    launcher ``Popen`` (its pid is the session leader) so a caller can tear the
    tree down with ``killpg``. We also kill the session ourselves on the way out.
    """
    import time

    before = {d.split("/")[-1] for d in glob.glob("/proc/[0-9]*")}
    argv = [wine_cmd, program, *(program_args or [])]
    proc = subprocess.Popen(argv, start_new_session=True)
    if on_process is not None:
        on_process(proc)

    def _kill_tree():
        # Kill the whole session we launched (the wine launcher + the actual app
        # process gdb attached to); wineserver is a separate daemon and is left.
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass

    try:
        pid = _find_wine_app_pid(
            os.path.basename(program), before, time.time() + startup_timeout
        )
        if pid is None:
            msg = (
                f"could not find the Wine process for {program!r} within "
                f"{startup_timeout:.0f}s; aborting (nothing to attach to)."
            )
            if logger is not None:
                logger.error("%s", msg)
            else:
                print(msg, file=sys.stderr)
            _kill_tree()
            return 1
        return run_wine_key_extraction(
            attach=pid,
            keylog=keylog,
            patterns=patterns,
            verbose=verbose,
            debug_output=debug_output,
            gdb_output=gdb_output,
            on_process=on_process,  # also register gdb for teardown
        )
    finally:
        _kill_tree()


def main() -> int:
    args = build_parser().parse_args()

    if bool(args.attach) == bool(args.spawn):
        build_parser().error("exactly one of --attach or --spawn is required")

    # argparse REMAINDER keeps a leading "--"; drop it so it is not passed to wine.
    program_args = list(args.program_args or [])
    if program_args and program_args[0] == "--":
        program_args = program_args[1:]

    return run_wine_key_extraction(
        attach=args.attach,
        spawn=args.spawn,
        keylog=args.keylog,
        patterns=args.patterns,
        program_args=program_args,
        wine_bin=args.wine_bin,
        verbose=args.verbose,
        debug_output=args.debug_output,
        gdb_output=args.gdb,
    )


if __name__ == "__main__":
    sys.exit(main())
