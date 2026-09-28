"""Tests for MTProto key-type scoping, poll-loop backoff, and the bottom-up
scan-ended signal on the memory-scan engine.

Hermetic (no device / Frida). Covers:

  * ``_e2e_requested`` — telegram (protocol or -ms arg) enables E2E, mtproto does not;
  * ``_apply_e2e_scope`` — disables the Tier C (Secret-Chat/E2E) tier on a COPY for
    mtproto-only runs, leaves AUTH/OBF tiers and the shared DB untouched, and is a
    passthrough when E2E was requested;
  * ``_poll_loop`` — snapshot + exponential backoff schedule (reset on emit, grow to
    the cap otherwise), and the scan-ended callback fired only for the self session
    on an UNEXPECTED end.
"""

from __future__ import annotations

from friTap.memory_scanning import MemoryScanEngine
from friTap.memory_scanning.engine import (
    MS_BACKOFF_CAP_SECONDS,
    MS_SELF_POLL_NAME,
)


def _mtproto_profile() -> dict:
    """A minimal mtproto profile shaped like the shipped one (tiers.*.enabled)."""
    return {
        "engine": "mtproto",
        "id": "tgnet-android-arm64-2026",
        "tiers": {
            "A_bytearray_authkey": {"enabled": True},
            "B_authkeyid_roundtrip": {"label": "MTPROTO_AUTH_KEY"},
            "C_art_secretchat_key": {"enabled": True, "label": "MTPROTO_E2E_KEY"},
            "E_connection_ctr_state": {"enabled": True, "label": "MTPROTO_OBF_KEY"},
        },
    }


# --------------------------------------------------------------------------- #
# _e2e_requested
# --------------------------------------------------------------------------- #


def test_e2e_requested_true_for_telegram_protocol():
    assert MemoryScanEngine(protocols=["telegram"])._e2e_requested is True


def test_e2e_requested_true_for_telegram_and_mtproto_together():
    # `--protocol telegram,mtproto` is the same as `--protocol telegram`.
    assert MemoryScanEngine(protocols=["telegram", "mtproto"])._e2e_requested is True


def test_e2e_requested_false_for_mtproto_only():
    assert MemoryScanEngine(protocols=["mtproto"])._e2e_requested is False


def test_e2e_requested_follows_targeted_ms_arg():
    assert MemoryScanEngine(patterns_path="telegram")._e2e_requested is True
    assert MemoryScanEngine(patterns_path="mtproto")._e2e_requested is False


# --------------------------------------------------------------------------- #
# _apply_e2e_scope
# --------------------------------------------------------------------------- #


def test_scope_disables_tierc_for_mtproto_on_a_copy():
    eng = MemoryScanEngine(protocols=["mtproto"])
    profiles = [_mtproto_profile()]
    out = eng._apply_e2e_scope(profiles)
    # E2E (Tier C) disabled on the returned copy...
    assert out[0]["tiers"]["C_art_secretchat_key"]["enabled"] is False
    # ...while AUTH (A/B) and OBF (E) tiers are untouched.
    assert out[0]["tiers"]["A_bytearray_authkey"]["enabled"] is True
    assert out[0]["tiers"]["E_connection_ctr_state"]["enabled"] is True
    # The shared pattern-database object is NOT mutated.
    assert profiles[0]["tiers"]["C_art_secretchat_key"]["enabled"] is True


def test_scope_is_passthrough_when_e2e_requested():
    eng = MemoryScanEngine(protocols=["telegram"])
    profiles = [_mtproto_profile()]
    out = eng._apply_e2e_scope(profiles)
    assert out is profiles  # same object, nothing stamped
    assert out[0]["tiers"]["C_art_secretchat_key"]["enabled"] is True


def test_scope_leaves_non_mtproto_profiles_alone():
    eng = MemoryScanEngine(protocols=["mtproto"])
    other = {"engine": "boringssl", "id": "bs"}
    out = eng._apply_e2e_scope([other])
    assert out[0] is other  # untouched, same object


# --------------------------------------------------------------------------- #
# _poll_loop backoff + scan-ended signal
# --------------------------------------------------------------------------- #


class _FakeStop:
    """Stand-in for the engine's threading.Event that records wait() durations
    and never reports 'set' (the loop then ends only via scanOnce raising)."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return False

    def wait(self, timeout=None) -> bool:
        self.waits.append(timeout)
        return False


class _FakeRpc:
    """scanOnce() returns each queued emitted-count, then raises to end the loop
    (simulating the agent script being destroyed)."""

    def __init__(self, emissions) -> None:
        self._emissions = list(emissions)

    def scanOnce(self):
        if not self._emissions:
            raise RuntimeError("script has been destroyed")
        return {"emitted": self._emissions.pop(0), "durationMs": 1}


def _run_poll(interval, emissions, name=MS_SELF_POLL_NAME):
    eng = MemoryScanEngine(interval=interval)
    fake_stop = _FakeStop()
    eng._stop = fake_stop  # type: ignore[assignment]
    eng._poll_loop(_FakeRpc(emissions), name)
    return fake_stop.waits


def test_backoff_resets_on_emit_and_grows_when_idle():
    # base=2: emit keeps base, idle doubles, an emit resets back to base.
    waits = _run_poll(2.0, [1, 0, 0, 0, 5, 0])
    assert waits == [2.0, 4.0, 8.0, 16.0, 2.0, 4.0]


def test_backoff_is_capped():
    waits = _run_poll(2.0, [0, 0, 0, 0, 0, 0, 0])
    assert waits == [4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0]
    assert max(waits) == MS_BACKOFF_CAP_SECONDS


def test_scan_ended_callback_fires_for_self_session():
    eng = MemoryScanEngine(interval=1.0)
    eng._stop = _FakeStop()  # type: ignore[assignment]
    fired = []
    eng.set_scan_ended_callback(lambda: fired.append(True))
    eng._poll_loop(_FakeRpc([]), MS_SELF_POLL_NAME)  # raises immediately
    assert fired == [True]


def test_scan_ended_callback_not_fired_for_lsass_session():
    eng = MemoryScanEngine(interval=1.0)
    eng._stop = _FakeStop()  # type: ignore[assignment]
    fired = []
    eng.set_scan_ended_callback(lambda: fired.append(True))
    eng._poll_loop(_FakeRpc([]), "fritap-memscan-lsass")
    assert fired == []
