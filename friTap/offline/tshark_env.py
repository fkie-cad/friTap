"""tshark run limits read from the environment (time budget, output cap).

Parses ``$FRITAP_TSHARK_TIMEOUT`` / ``$FRITAP_TSHARK_MAX_OUTPUT``.
:mod:`friTap.offline.tshark` re-exports every name and owns the size-scaled
:func:`~friTap.offline.tshark.tshark_timeout_for`.
"""

from __future__ import annotations

import logging
import math
import os
from typing import Callable, Sequence

from .._warn_once import warn_once

# Shares the tshark driver's logger so limit warnings land with its other messages.
logger = logging.getLogger("friTap.offline.tshark")

# Run time budget in seconds. Unset: size-scaled; "0" or "none": no limit; invalid: ignored.
TSHARK_TIMEOUT_ENV = "FRITAP_TSHARK_TIMEOUT"
# Cap on a buffered run's stdout in bytes, optional binary K/M/G/T suffix; "0" or "none": no cap.
TSHARK_MAX_OUTPUT_ENV = "FRITAP_TSHARK_MAX_OUTPUT"

# Default budget max(600 s, 10 s per MiB): tshark dissects at several MB/s, so this is a 100x+ margin; it only ends a stuck dissector.
_MIN_TSHARK_TIMEOUT = 600.0
_TSHARK_SECONDS_PER_MIB = 10.0
_MIB = 1024 * 1024

# Buffered outputs are small; 4 GiB only stops a runaway.
_DEFAULT_MAX_TSHARK_OUTPUT = 4 * 1024 ** 3

_LIMIT_DISABLED_VALUES = frozenset({"0", "none"})
_BYTE_SIZE_SUFFIXES = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
# Marks "no usable environment override" (unset, or invalid and ignored).
_NO_OVERRIDE = object()


def tshark_max_output_bytes() -> int | None:
    """Most stdout bytes one buffered run may produce; ``None`` = no cap.

    ``$FRITAP_TSHARK_MAX_OUTPUT`` (bytes, ``512M``, ``8G``; ``0`` / ``none`` disables) wins when valid; default 4 GiB.
"""
    override = _env_limit(TSHARK_MAX_OUTPUT_ENV, _parse_byte_size)
    return _DEFAULT_MAX_TSHARK_OUTPUT if override is _NO_OVERRIDE else override


def _env_limit(env_var: str, parse: Callable[[str], float]):
    """*env_var* parsed by *parse*: ``None`` when it disables the limit, :data:`_NO_OVERRIDE` when unset or invalid (warned once)."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return _NO_OVERRIDE
    if raw.lower() in _LIMIT_DISABLED_VALUES:
        return None
    try:
        value = parse(raw)
    except ValueError:
        _warn_invalid_env_once(env_var, raw)
        return _NO_OVERRIDE
    return None if value == 0 else value


def _warn_invalid_env_once(env_var: str, raw: str) -> None:
    """Warn (once per value) that *env_var* holds an unusable *raw* value."""
    warn_once(logger, ("tshark-env", env_var, raw),
              "Ignoring invalid %s=%r; using the default limit "
              "(set it to 0 or 'none' to disable the limit).", env_var, raw)


def _parse_seconds(raw: str) -> float:
    """A non-negative, finite number of seconds; ``ValueError`` otherwise."""
    seconds = float(raw)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError(raw)
    return seconds


def _parse_byte_size(raw: str) -> int:
    """``"4294967296"``, ``"512M"``, ``"8G"``, ``"8GiB"`` -> bytes (binary units)."""
    text = raw.lower().removesuffix("ib").removesuffix("b")
    multiplier = _BYTE_SIZE_SUFFIXES.get(text[-1:], 1)
    if multiplier != 1:
        text = text[:-1]
    value = float(text)
    if not math.isfinite(value) or value < 0:
        raise ValueError(raw)
    return int(value * multiplier)


def _total_size(path_or_paths) -> int:
    """Summed size in bytes of the existing files among *path_or_paths*."""
    if path_or_paths is None:
        return 0
    if isinstance(path_or_paths, (str, bytes, os.PathLike)):
        path_or_paths = [path_or_paths]
    total = 0
    for path in path_or_paths:
        try:
            total += os.path.getsize(path)
        except (OSError, TypeError, ValueError):
            continue
    return total


def _capture_inputs(argv: Sequence[str]) -> list[str]:
    """The files *argv* reads with ``-r`` (what the time budget scales with)."""
    return [argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "-r"]


def _format_seconds(seconds: float) -> str:
    """``600.0`` -> ``"600"``, ``0.5`` -> ``"0.5"``."""
    return f"{seconds:.1f}".rstrip("0").rstrip(".")
