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
import tempfile
from dataclasses import dataclass
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
    run_as=None,
    ready_file=None,
) -> int:
    """Run the gdb-based Wine TLS key extractor.

    Exactly one of ``attach`` (a PID) or ``spawn`` (an executable) must be given.
    Returns the gdb process exit code. This is the importable entry point used by
    both the standalone CLI below and friTap's Wine routing.

    ``on_process``, if given, is called once with the ``gdb`` ``Popen`` object
    right after it starts, so a caller running this in a background thread can
    terminate gdb (and thereby detach) during its own teardown.

    ``run_as`` (a :class:`WineRunAs`) runs gdb itself as that user instead of
    the caller; see :func:`unprivileged_gdb_blocker` for when that can work.

    ``ready_file``, if given, is passed to gdb as ``FRITAP_WINE_READY_FILE``:
    the gdb script creates it once its hooks are installed (see
    :func:`launch_and_attach`).
    """
    if bool(attach) == bool(spawn):
        raise ValueError("exactly one of attach= or spawn= must be provided")

    script_path = resolve_gdb_script_path()

    log_fd = os.dup(sys.stdout.fileno())
    stdout_fd = os.dup(sys.stdout.fileno())
    stderr_fd = os.dup(sys.stderr.fileno())

    environment = os.environ.copy()
    if ready_file:
        environment["FRITAP_WINE_READY_FILE"] = ready_file

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
    popen_kwargs.update(_run_as_popen_kwargs(run_as, environment))
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


def iter_proc_cmdlines(exclude=()):
    """Yield ``(pid, cmdline)`` for each readable /proc process, NULs turned
    into spaces. *pid* is a string; PIDs (strings) in *exclude* are skipped."""
    for entry in glob.glob("/proc/[0-9]*"):
        pid = entry.rsplit("/", 1)[-1]
        if pid in exclude:
            continue
        try:
            with open(entry + "/cmdline", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        yield pid, raw.replace(b"\0", b" ").decode("latin1")


def own_process_lineage():
    """PIDs (as strings) of this process and its ancestors, via /proc/<pid>/stat."""
    lineage = {str(os.getpid())}
    pid = os.getppid()
    while pid > 1 and str(pid) not in lineage:
        lineage.add(str(pid))
        try:
            with open(f"/proc/{pid}/stat") as fh:
                # "<pid> (<comm>) <state> <ppid> ..." -- comm may contain spaces.
                pid = int(fh.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return lineage


def _find_wine_app_pid(exe_basename, exclude_pids, deadline, freeze=False,
                       poll_interval=0.01):
    """Poll /proc for the Wine process that actually runs the target app.

    The app process is the one that maps the exe image (``curl.exe``) — the
    transient ``wine`` launcher only has it in its cmdline. That single signal
    identifies the app for BOTH statically linked TLS (curl-for-win's curl.exe,
    which embeds LibreSSL and maps no libssl/libgnutls) and dynamically linked
    TLS. The libssl/libgnutls-in-maps check is kept as an additional accept.

    ``freeze=True`` sends ``SIGSTOP`` the instant the app is identified and
    returns immediately. This is essential for a short one-shot like ``curl``:
    the whole run is ~0.5 s and the TLS handshake fires ~150 ms after the image
    is mapped — far too fast to win by attaching (gdb-attach latency alone loses
    the race). Freezing is instantaneous, so it halts the app *before* TLS; gdb
    then attaches to the frozen process at leisure, installs its hooks, and the
    gdb side resumes it with ``SIGCONT`` (see ``attach()`` in the gdb script).
    ``poll_interval`` defaults to 10 ms so detection lands well inside that
    window.
    """
    import time

    def _try_freeze(pid):
        if freeze:
            try:
                os.kill(int(pid), signal.SIGSTOP)
            except (OSError, ValueError):
                pass
        return pid

    exe_lc = exe_basename.lower()
    fallback = None
    while time.time() < deadline:
        for pid, cmdline in iter_proc_cmdlines(exclude=exclude_pids):
            if exe_lc not in cmdline.lower():
                continue
            try:
                with open(f"/proc/{pid}/maps") as fh:
                    maps = fh.read()
            except OSError:
                maps = ""
            # The app maps its own exe image (static OR dynamic). Freeze + take it
            # immediately — this is the earliest reliable identification, before
            # the handshake. (For the static LibreSSL repro this is the only
            # signal; ws2_32/libssl load slightly later.)
            if exe_lc in maps.lower():
                return _try_freeze(pid)
            if "libgnutls" in maps or "libssl" in maps:
                return _try_freeze(pid)  # dynamic TLS before the exe image shows
            fallback = fallback or pid
        time.sleep(poll_interval)
    return _try_freeze(fallback) if fallback else None


@dataclass(frozen=True)
class WineRunAs:
    """The unprivileged identity to launch Wine as (root via sudo -> the invoking
    user), so Wine uses that user's own prefix instead of refusing it."""

    uid: int
    gid: int
    user: str
    home: str


def _run_as_popen_kwargs(run_as: Optional[WineRunAs], env: dict) -> dict:
    """Extra ``Popen`` kwargs that drop a child process to *run_as*.

    Empty when *run_as* is None, so the plain launch stays unchanged. The env is
    a copy of *env* with HOME/USER/LOGNAME pointing at the target user.
    """
    if run_as is None:
        return {}
    env = dict(env)
    env.update(HOME=run_as.home, USER=run_as.user, LOGNAME=run_as.user)
    return {
        "user": run_as.uid,
        "group": run_as.gid,
        "extra_groups": os.getgrouplist(run_as.user, run_as.gid),
        "env": env,
    }


def _getpwuid(uid):
    """The passwd entry for *uid*, or None (no entry, bad uid, or no ``pwd``
    module on this platform)."""
    try:
        import pwd
        return pwd.getpwuid(int(uid))
    except (ImportError, KeyError, ValueError):
        return None


def _user_name(uid) -> str:
    """Login name for *uid*, or the uid itself when it has no passwd entry."""
    entry = _getpwuid(uid)
    return entry.pw_name if entry is not None else str(uid)


def sudo_invoker() -> Optional[WineRunAs]:
    """The invoking user (a :class:`WineRunAs`) when running as root via sudo.

    None for a non-root run or a real root shell (no sudo user).
    """
    if os.geteuid() != 0:
        return None
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid or uid == "0":
        return None
    entry = _getpwuid(uid)
    if entry is None:
        return None
    return WineRunAs(uid=int(uid), gid=int(gid), user=entry.pw_name, home=entry.pw_dir)


def wine_prefix_problem(run_as: Optional[WineRunAs] = None) -> Optional[str]:
    """Error message if the Wine prefix belongs to someone other than the
    identity Wine will run as (Wine would refuse it and exit), else None.

    The prefix is ``$WINEPREFIX`` or ``~/.wine`` of that identity (the sudo
    user's home when *run_as* is given). A missing prefix is fine: Wine
    creates one.
    """
    uid = run_as.uid if run_as is not None else os.geteuid()
    home = run_as.home if run_as is not None else os.path.expanduser("~")
    prefix = os.environ.get("WINEPREFIX") or os.path.join(home, ".wine")
    try:
        owner = os.stat(prefix).st_uid
    except OSError:
        return None
    if owner == uid:
        return None
    return (
        f"Wine prefix {prefix} is owned by {_user_name(owner)} (uid {owner}), "
        f"but Wine would run as uid {uid}; Wine refuses a prefix it does not own "
        "and exits. Fix: run friTap as the prefix owner (with "
        "`sysctl kernel.yama.ptrace_scope=0`), or use sudo so friTap launches "
        "Wine as you, or set WINEPREFIX to a prefix you own. See "
        "docs/platforms/wine.md."
    )


YAMA_PTRACE_SCOPE = "/proc/sys/kernel/yama/ptrace_scope"


def ptrace_scope() -> int:
    """The Yama ``kernel.yama.ptrace_scope`` level (0 when Yama is absent).

    An unreadable or garbled value is treated as restrictive (1).
    """
    try:
        with open(YAMA_PTRACE_SCOPE) as fh:
            return int(fh.read().strip())
    except FileNotFoundError:
        return 0
    except (OSError, ValueError):
        return 1


def _proc_ids(pid) -> Optional[tuple]:
    """(uids, gids) of *pid* from ``/proc/<pid>/status``, or None if unreadable.

    Each is the list of real/effective/saved/fs ids from the ``Uid:``/``Gid:``
    lines.
    """
    ids = {}
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                key, _, value = line.partition(":")
                if key in ("Uid", "Gid"):
                    ids[key] = [int(v) for v in value.split()]
    except (OSError, ValueError):
        return None
    if "Uid" not in ids or "Gid" not in ids:
        return None
    return ids["Uid"], ids["Gid"]


def _can_access_as(run_as: WineRunAs, *test_args: str) -> bool:
    """Whether ``test <test_args>`` succeeds when run as *run_as*.

    Probing as the user (rather than ``os.access``, which checks root's real
    uid) honours that user's groups and ACLs exactly as gdb will see them.
    """
    try:
        result = subprocess.run(
            ["test", *test_args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **_run_as_popen_kwargs(run_as, os.environ),
        )
    except OSError:
        return False
    return result.returncode == 0


def _prepare_keylog_for(run_as: WineRunAs, path: str) -> Optional[str]:
    """Make *path* writable by *run_as*; return a reason string on failure.

    An existing keylog is only probed (never chowned). A missing one is created
    exclusively (no symlink follow) and handed to the user, which is safe
    because we just created it. If the user still cannot reach it (e.g. a
    parent directory they cannot traverse), the new file is removed again.
    """
    if os.path.lexists(path):
        if _can_access_as(run_as, "-w", path):
            return None
        return f"keylog {path} is not writable by {run_as.user}"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchown(fd, run_as.uid, run_as.gid)
        finally:
            os.close(fd)
    except OSError as exc:
        return f"could not create keylog {path} for {run_as.user}: {exc}"
    if _can_access_as(run_as, "-w", path):
        return None
    _remove_quietly(path)
    return f"keylog {path} is not reachable by {run_as.user}"


def _remove_quietly(path: str) -> None:
    """Unlink *path*, ignoring a failure (best-effort cleanup)."""
    try:
        os.unlink(path)
    except OSError:
        pass


def unprivileged_gdb_blocker(run_as: WineRunAs, keylog: str,
                             target_pid=None) -> Optional[str]:
    """Why gdb cannot run as *run_as* (a short reason), or None if it can.

    Checks, in order: Yama ``ptrace_scope`` (an unprivileged gdb is not the
    target's ancestor, so only scope 0 allows the attach), the target's ids
    (attach mode), the gdb script's readability and the keylog. The keylog step
    runs last because it may create the file for the user.
    """
    scope = ptrace_scope()
    if scope != 0:
        return (f"kernel.yama.ptrace_scope={scope} blocks an unprivileged attach "
                "(set it to 0 to let gdb run as the invoking user)")
    if target_pid is not None:
        ids = _proc_ids(target_pid)
        if ids is None:
            return f"could not read the uid/gid of process {target_pid}"
        uids, gids = ids
        if any(u != run_as.uid for u in uids) or any(g != run_as.gid for g in gids):
            return f"process {target_pid} does not run entirely as {run_as.user}"
    script = resolve_gdb_script_path()
    script_dir = os.path.dirname(script)
    if not _can_access_as(run_as, "-r", script, "-a", "-r", script_dir, "-a", "-x", script_dir):
        return f"{run_as.user} cannot read the gdb script {script}"
    return _prepare_keylog_for(run_as, keylog)


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
    run_as=None,
    gdb_run_as=None,
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

    ``run_as`` (a :class:`WineRunAs`) launches only the Wine process as that
    user; gdb, the /proc scan and the SIGSTOP/SIGCONT handshake stay with the
    caller (root needs no ``ptrace_scope=0`` to attach). ``gdb_run_as``
    additionally runs gdb as that user (the handshake directory is handed to
    it so the unprivileged gdb can create its ready file).
    """
    import time

    before = {d.split("/")[-1] for d in glob.glob("/proc/[0-9]*")}
    argv = [wine_cmd, program, *(program_args or [])]
    proc = subprocess.Popen(argv, start_new_session=True,
                            **_run_as_popen_kwargs(run_as, os.environ))
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
            os.path.basename(program), before, time.time() + startup_timeout,
            freeze=True,
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

        # The app is frozen (SIGSTOP) so gdb can attach and install hooks before
        # it reaches TLS. gdb's attach() installs the hooks synchronously, then
        # touches FRITAP_WINE_READY_FILE and blocks in `c`. It cannot clear the
        # external group-stop itself (a plain `c` hangs; a gdb-internal
        # `signal SIGCONT` resumes it wrong), and SIGCONT'ing *before* gdb has
        # hooked would let the app run free and finish un-hooked. So wait for the
        # ready file, THEN SIGCONT the frozen app (repeatedly, harmless once it is
        # running) while gdb stays blocked in `c`.
        import threading

        with tempfile.TemporaryDirectory(prefix="fritap_wine_ready_",
                                         ignore_cleanup_errors=True) as ready_dir:
            # Handed to an unprivileged gdb so it can create the ready file there
            # (root's tempdir may not be writable for it).
            if gdb_run_as is not None:
                os.chown(ready_dir, gdb_run_as.uid, gdb_run_as.gid)
            ready_path = os.path.join(ready_dir, "ready")  # gdb creates the file
            resume_stop = threading.Event()

            def _resumer():
                # Wait until gdb signals "hooks installed", then clear the group-stop.
                while not os.path.exists(ready_path):
                    if resume_stop.wait(0.02):
                        return
                while not resume_stop.wait(0.1):
                    try:
                        os.kill(int(pid), signal.SIGCONT)
                    except (OSError, ValueError):
                        return

            resumer = threading.Thread(target=_resumer, name="fritap-wine-resume", daemon=True)
            resumer.start()
            try:
                return run_wine_key_extraction(
                    attach=pid,
                    keylog=keylog,
                    patterns=patterns,
                    verbose=verbose,
                    debug_output=debug_output,
                    gdb_output=gdb_output,
                    on_process=on_process,  # also register gdb for teardown
                    run_as=gdb_run_as,
                    ready_file=ready_path,
                )
            finally:
                resume_stop.set()
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
