"""Session glue for the learned plaintext-RVA cache (:mod:`friTap.learned_offsets`).

Loads the cache once per session, hands the agent its entries (the agent
itself prefers the user's ``--offsets`` per module), records
``plaintext_api_learned`` and ``module_offsets_learned`` reports and persists
them on a background saver thread, so the message-routing thread never does
file I/O. Every method swallows cache errors: a broken cache costs a locator
scan on the next run, never the capture.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Callable, Optional

from ..constants import ContentType
from ..learned_offsets import LearnedOffsetsStore

#: Set to a non-empty value other than ``0`` to neither read nor write the cache.
LEARNED_OFFSETS_DISABLE_ENV = "FRITAP_NO_LEARNED_OFFSETS"

logger = logging.getLogger("friTap.learned_offsets")

_SAVER_JOIN_TIMEOUT_S = 5.0
# A burst of reports (one per hooked module at startup) collapses into one write.
_SAVE_DEBOUNCE_S = 1.0


def learned_offsets_disabled() -> bool:
    return os.environ.get(LEARNED_OFFSETS_DISABLE_ENV, "").strip() not in ("", "0")


def _learned_what(payload: dict) -> str:
    if payload.get("contentType") != ContentType.MODULE_OFFSETS_LEARNED:
        return "SSL_read/SSL_write offsets"
    names = [name for field in ("functions", "layout")
             if isinstance(payload.get(field), dict) for name in payload[field]]
    return "offsets of " + ", ".join(sorted(names)[:8])


class LearnedOffsetsSession:
    """One capture's view of the learned-offsets store."""

    def __init__(self, store: LearnedOffsetsStore,
                 save_debounce_s: float = _SAVE_DEBOUNCE_S) -> None:
        self._store = store
        self._save_debounce_s = save_debounce_s
        # Set until a save succeeds, so a failed background write is retried at shutdown.
        self._dirty = False
        self._dirty_lock = threading.Lock()
        # One Event coalesces any burst of reports into at most one pending save.
        self._save_requested = threading.Event()
        self._stopping = False
        self._stop_requested = threading.Event()
        self._saver: Optional[threading.Thread] = None

    @classmethod
    def open(cls, store_factory: Callable[[], LearnedOffsetsStore] = LearnedOffsetsStore
             ) -> Optional["LearnedOffsetsSession"]:
        """A loaded session, or None when disabled or the store cannot be built."""
        if learned_offsets_disabled():
            logger.debug("learned offsets: disabled via %s", LEARNED_OFFSETS_DISABLE_ENV)
            return None
        try:
            store = store_factory()
            count = store.load()
        except Exception:  # noqa: BLE001
            logger.debug("learned offsets: cache unavailable", exc_info=True)
            return None
        logger.debug("learned offsets: %d cached entries from %s", count, store.path)
        return cls(store)

    def agent_entries(self) -> dict:
        """``config_batch.learned_plaintext``: every cached entry, unfiltered."""
        try:
            return self._store.entries_for_agent()
        except Exception:  # noqa: BLE001
            logger.debug("learned offsets: could not build agent entries", exc_info=True)
            return {}

    def record(self, payload: dict) -> None:
        """Store a ``plaintext_api_learned`` / ``module_offsets_learned`` report (or refresh a cache hit).

        The background saver persists it promptly so a capture ending in a hard exit keeps it."""
        is_cache_hit = payload.get("cache_hit") is True
        try:
            key = self._store.touch(payload) if is_cache_hit else self._store.record(payload)
        except Exception:  # noqa: BLE001
            logger.debug("learned offsets: record failed", exc_info=True)
            return
        if key is None:
            return
        if not is_cache_hit:
            logger.info("Learned %s for %s; the next run skips the scan",
                        _learned_what(payload), payload.get("module"))
        with self._dirty_lock:
            self._dirty = True
        self._request_background_save()

    def save_if_dirty(self) -> None:
        """Final synchronous save at shutdown; stops the background saver first."""
        self._stop_saver()
        self._save_now()

    def _request_background_save(self) -> None:
        if self._stopping:
            return
        if self._saver is None:
            self._saver = threading.Thread(target=self._saver_loop,
                                           name="fritap-learned-offsets-saver", daemon=True)
            self._saver.start()
        self._save_requested.set()

    def _saver_loop(self) -> None:
        while True:
            self._save_requested.wait()
            if self._stop_requested.wait(self._save_debounce_s):
                return
            self._save_requested.clear()
            self._save_now()

    def _stop_saver(self) -> None:
        self._stopping = True
        self._stop_requested.set()
        self._save_requested.set()
        saver = self._saver
        if saver is not None and saver is not threading.current_thread():
            saver.join(_SAVER_JOIN_TIMEOUT_S)

    def _save_now(self) -> None:
        with self._dirty_lock:
            if not self._dirty:
                return
            # Cleared before writing so a report arriving mid-save re-dirties it.
            self._dirty = False
        try:
            saved = self._store.save()
        except Exception:  # noqa: BLE001
            logger.debug("learned offsets: save failed", exc_info=True)
            saved = False
        if not saved:
            with self._dirty_lock:
                self._dirty = True
