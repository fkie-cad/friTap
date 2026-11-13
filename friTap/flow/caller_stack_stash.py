"""Bounded stash of caller stacks that arrived before their flow.

A ``CallerStackEvent`` can reach the collector before the first data record of
its connection. It is parked here under a join key -- ``("cr", client_random)``,
an unordered 4-tuple, or ``("sid", ssl_session_id)`` -- and drained when the
connection's first flow is born. The stash holds at most :data:`MAX_STASHED`
entries in total, and entries expire :data:`STASH_TTL_SECONDS` after they were
parked. Time always comes from the caller (the collector's ``_now()``), never
from the wall clock here: offline conversion runs on the event clock.

Entries arrive in time order, so one global FIFO (``_arrivals``) is also the
expiry order: expiry and the over-cap drop work from its front in amortized
O(1). Each key keeps its own FIFO for :meth:`CallerStackStash.take`; a taken
entry is only flagged dead in the global FIFO and skipped when it reaches the
front.

One entry may be indexed under SEVERAL keys (:meth:`CallerStackStash.put_under`,
e.g. its client_random and its 4-tuple): whichever key drains first consumes it,
and the other keys skip the dead slot. It counts once against the cap.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Optional, Tuple

#: Total entries kept across every key.
MAX_STASHED = 1024
#: Seconds a parked caller stack stays claimable.
STASH_TTL_SECONDS = 120.0


@dataclass
class StashedCallerStack:
    """One parked join: the trusted SDK (or ``None``) and the compact stack."""
    sdk: Optional[dict]
    caller_stack: dict
    stashed_at: float


@dataclass(eq=False)
class _Slot:
    """A parked entry plus its keys; ``live`` turns False once taken."""
    keys: Tuple[tuple, ...]
    entry: StashedCallerStack
    live: bool = True


class CallerStackStash:
    """``join key -> FIFO of StashedCallerStack`` with a total cap and a TTL."""

    def __init__(self) -> None:
        self._by_key: Dict[tuple, Deque[_Slot]] = {}
        self._arrivals: Deque[_Slot] = deque()
        self._count = 0

    def __len__(self) -> int:
        """Live entries parked across all keys."""
        return self._count

    def __contains__(self, key: object) -> bool:
        """True when *key* still indexes a live entry."""
        return any(slot.live for slot in self._by_key.get(key, ()))  # type: ignore[arg-type]

    def is_empty(self) -> bool:
        return self._count == 0

    def clear(self) -> None:
        self._by_key.clear()
        self._arrivals.clear()
        self._count = 0

    def put(self, key: tuple, entry: StashedCallerStack, now: float) -> None:
        """Park *entry* under *key*, dropping expired and then the oldest entries."""
        self.put_under([key], entry, now)

    def put_under(self, keys: Iterable[tuple], entry: StashedCallerStack,
                  now: float) -> None:
        """Park ONE *entry* under every key of *keys* (taken at most once)."""
        self.expire(now)
        slot = _Slot(tuple(dict.fromkeys(keys)), entry)
        for key in slot.keys:
            self._by_key.setdefault(key, deque()).append(slot)
        self._arrivals.append(slot)
        self._count += 1
        while self._count > MAX_STASHED:
            self._drop_front()

    def take(self, keys: Iterable[tuple], now: float) -> Optional[StashedCallerStack]:
        """Pop the oldest live entry under the first of *keys* that has one."""
        self.expire(now)
        for key in keys:
            slot = self._pop_live(key)
            if slot is not None:
                self._kill(slot)
                return slot.entry
        return None

    def expire(self, now: float) -> None:
        """Drop every entry parked more than the TTL before *now*."""
        while self._arrivals:
            front = self._arrivals[0]
            if front.live and now - front.entry.stashed_at <= STASH_TTL_SECONDS:
                return
            self._drop_front()

    def _drop_front(self) -> None:
        """Remove the oldest slot of the global FIFO (live or already taken).

        FIFO per key and globally: every older slot already left its key
        queues, so this slot heads each queue it is still in.
        """
        slot = self._arrivals.popleft()
        if slot.live:
            self._kill(slot)
        for key in slot.keys:
            queue = self._by_key.get(key)
            if queue and queue[0] is slot:
                self._pop_front(key, queue)

    def _kill(self, slot: _Slot) -> None:
        """Mark *slot* taken; its other keys skip it from now on."""
        slot.live = False
        self._count -= 1

    def _pop_live(self, key: tuple) -> Optional[_Slot]:
        """Pop *key*'s oldest LIVE slot (discarding dead ones before it), else ``None``."""
        queue = self._by_key.get(key)
        while queue:
            slot = self._pop_front(key, queue)
            if slot.live:
                return slot
        return None

    def _pop_front(self, key: tuple, queue: Deque[_Slot]) -> _Slot:
        """Pop *queue*'s front slot, forgetting *key* once its queue is empty."""
        slot = queue.popleft()
        if not queue:
            del self._by_key[key]
        return slot
