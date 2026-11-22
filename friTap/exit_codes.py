"""Process exit codes of the live-capture CLI (``fritap <target>``).

Kept in one place so wrapper scripts, CI jobs and AI agents driving friTap
unattended can rely on them (documented in ``docs/api/cli.md``). Subcommands
such as ``--from-pcap`` and ``analyze`` keep their own, separately documented
codes.
"""

#: Normal stop: Ctrl+C, SIGINT, ``--duration`` elapsed, or a clean return.
EXIT_OK = 0

#: Runtime error: attach/spawn failure, agent script load failure, backend error.
EXIT_RUNTIME_ERROR = 1

#: Usage error: invalid command line / configuration (argparse).
EXIT_USAGE_ERROR = 2

#: The target process died or detached before friTap was asked to stop.
EXIT_TARGET_DETACHED = 3

#: Forced quit: a 3rd Ctrl+C during the teardown, or the teardown still running
#: 60 s after the 2nd one. The outputs may be incomplete. An earlier non-zero
#: status (e.g. EXIT_TARGET_DETACHED) still wins: the first non-zero status is kept.
EXIT_FORCED_SIGINT = 130

#: Forced quit after repeated SIGTERM (same rules as EXIT_FORCED_SIGINT).
EXIT_FORCED_SIGTERM = 143


def forced_exit_code(signum: int) -> int:
    """Exit code of a forced quit after repeated *signum*: the shell's ``128 + signum``."""
    return 128 + int(signum)


__all__ = [
    "EXIT_OK",
    "EXIT_RUNTIME_ERROR",
    "EXIT_USAGE_ERROR",
    "EXIT_TARGET_DETACHED",
    "EXIT_FORCED_SIGINT",
    "EXIT_FORCED_SIGTERM",
]
