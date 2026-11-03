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

__all__ = [
    "EXIT_OK",
    "EXIT_RUNTIME_ERROR",
    "EXIT_USAGE_ERROR",
    "EXIT_TARGET_DETACHED",
]
