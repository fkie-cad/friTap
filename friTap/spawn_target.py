#!/usr/bin/env python3

"""Resolution of the spawn target argv for LOCAL spawns.

The target positional is ``nargs="+"``: ``config.target`` keeps the space-joined
string (attach-by-name / display) and ``config.target_argv`` the original tokens.

A single token containing whitespace is ambiguous:

* command + args: ``fritap -s "$(which curl) https://example.com"`` (the shell
  collapses it into ONE token, which must be split again for ``device.spawn()``);
* one executable whose path has a space: ``fritap -s "/Applications/Some App.app/..."``
  (splitting would shred the path).

Tie-breaker: a filesystem probe of the literal token. If it names an executable
file it is that executable, otherwise a command with arguments. The probe is only
valid for LOCAL spawns, so ``SessionManager`` calls this only on the local branch.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import List, Optional, Sequence

__all__ = ["resolve_spawn_target"]


def resolve_spawn_target(
    target_argv: Optional[Sequence[str]],
    target_app: Optional[str],
    logger: Optional[logging.Logger] = None,
) -> List[str]:
    """The argv to hand to ``device.spawn()`` for a LOCAL spawn.

    *target_argv* are the parsed tokens (``None`` for programmatic/TUI configs),
    *target_app* the space-joined string used when there is no argv. With a
    *logger*, the chosen interpretation is logged at INFO and an unresolvable
    target at WARNING; without one the function is side-effect free.
    Never raises for an unresolvable target (the backend reports it).
    """
    if not target_argv:
        # No argv tokens: use the single-token resolver so the executable probe still
        # runs (a path with spaces stays whole, an Android package name draws no warning).
        return _resolve_single_token(target_app or "", logger)

    if len(target_argv) > 1:
        # The shell already tokenized this; there is nothing to guess.
        argv = list(target_argv)
        _log(logger, logging.INFO, "spawn target from argv tokens: argv=%r", argv)
        return argv

    return _resolve_single_token(target_argv[0], logger)


def _resolve_single_token(token: str, logger: Optional[logging.Logger]) -> List[str]:
    """Disambiguate the one-token case."""
    if not _contains_whitespace(token):
        # Not gated on existence: a relative launcher such as './app' is resolved by the backend.
        _log(logger, logging.INFO, "spawn target is a single token: argv=%r", [token])
        return [token]

    if _is_executable_file(token):
        _log(
            logger,
            logging.INFO,
            "spawn target is a single executable '%s' "
            "(executable file exists, path contains whitespace)",
            _absolute(token),
        )
        return [token]

    return _split_into_argv(token, logger, evidence=_absolute(token))


def _split_into_argv(
    token: str, logger: Optional[logging.Logger], evidence: Optional[str]
) -> List[str]:
    """Read ``token`` as "command + args" and return its argv.

    Plain :meth:`str.split` is deliberate: unlike ``shlex.split`` it does not
    re-apply quote/backslash rules to an already shell-parsed string
    (``C:\\Program Files\\app.exe`` would become ``['C:Program', 'Filesapp.exe']``).
    """
    tokens = token.split()
    if evidence is None:
        _log(logger, logging.INFO, "spawn target as command + args: argv=%r", tokens)
    else:
        _log(
            logger,
            logging.INFO,
            "spawn target as command + args: argv=%r (no executable file at '%s')",
            tokens,
            evidence,
        )
    _warn_if_unresolvable(token, tokens, logger)
    return tokens


def _warn_if_unresolvable(
    token: str, tokens: List[str], logger: Optional[logging.Logger]
) -> None:
    """Warn when neither interpretation of ``token`` resolves.

    A warning, not an error: the target may exist only on a PATH from ``-env``. Without
    it the split would make frida's error name a prefix the user never typed ('/p/My').
    """
    if not tokens:
        return
    command = tokens[0]
    if _is_executable_file(command) or shutil.which(command) is not None:
        return
    _log(
        logger,
        logging.WARNING,
        "spawn target '%s' resolved neither as a single executable whose path "
        "contains whitespace (no executable file at '%s') nor as a command "
        "with arguments ('%s' is not an executable file and is not on PATH). "
        "Proceeding with the command + args reading argv=%r.",
        token,
        _absolute(token),
        command,
        tokens,
    )


def _is_executable_file(token: str) -> bool:
    """Whether ``token`` names an executable regular file (``~`` expanded; ``isfile`` so a directory with a space never matches)."""
    path = os.path.expanduser(token)
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _absolute(token: str) -> str:
    """CWD-independent rendering of ``token`` for logs; an absolute token is shown verbatim
    (``abspath`` would collapse the ``//`` in ``https://example.com``)."""
    path = os.path.expanduser(token)
    return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


def _contains_whitespace(token: str) -> bool:
    return token.split() != [token]


def _log(logger: Optional[logging.Logger], level: int, message: str, *args) -> None:
    if logger is not None:
        logger.log(level, message, *args)
