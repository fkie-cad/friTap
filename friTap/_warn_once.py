"""Log a message at most once per key (leaf module, stdlib only)."""

import functools
import logging
import threading

_MAX_KEYS = 4096  # bound so hostile input cannot grow the set without limit
_seen: set = set()
_lock = threading.Lock()


def warn_once(logger: logging.Logger, key, msg: str, *args,
              level: int = logging.WARNING, **log_kwargs) -> bool:
    """Log *msg* the first time *key* is seen; return whether it was logged.

    Once the key set is full, unseen keys are not logged.
    """
    with _lock:
        if key in _seen or len(_seen) >= _MAX_KEYS:
            return False
        _seen.add(key)
    emit = getattr(logger, logging.getLevelName(level).lower(), None) or functools.partial(logger.log, level)
    emit(msg, *args, **log_kwargs)
    return True


def _key_family(key):
    """First element of a tuple key, else the key itself."""
    return key[0] if isinstance(key, tuple) and key else key


def reset_warn_once(family=None) -> None:
    """Forget warn-once keys: all of them, or only those of one *family*.

    A key's family is its first element when it is a tuple (``("tcp_state:drop", r)``
    -> ``"tcp_state:drop"``), otherwise the key itself.
    """
    with _lock:
        if family is None:
            _seen.clear()
        else:
            _seen.difference_update([k for k in _seen if _key_family(k) == family])
