"""Unit tests for the fuzz-suite contract runner (:mod:`tests.unit._fuzz_helpers`)."""

from __future__ import annotations

import random
import tracemalloc
from types import SimpleNamespace

import pytest

from tests.unit import _fuzz_helpers as fh


def _recording_action(calls: list):
    return lambda: calls.append(tracemalloc.is_tracing())


def test_untraced_contract_runs_once_without_tracemalloc():
    calls: list = []
    fh.run_contract("case", _recording_action(calls), "<repro>")
    assert calls == [False]


def test_traced_contract_times_an_untraced_run_then_traces_memory():
    calls: list = []
    fh.run_contract("case", _recording_action(calls), "<repro>", trace_memory=True)
    assert calls == [False, True]
    assert not tracemalloc.is_tracing()


def _fake_clock(monkeypatch, untraced_cost: float, traced_cost: float):
    """Patch the helper's clock; the action advances it by a per-mode cost."""
    now = [0.0]
    monkeypatch.setattr(fh, "time", SimpleNamespace(perf_counter=lambda: now[0]))

    def action():
        now[0] += traced_cost if tracemalloc.is_tracing() else untraced_cost
    return action


def test_time_budget_ignores_tracemalloc_overhead(monkeypatch):
    """A run that is slow only under tracemalloc must not fail the time budget."""
    action = _fake_clock(monkeypatch, untraced_cost=0.5, traced_cost=10 * fh.MAX_CASE_SECONDS)
    fh.run_contract("case", action, "<repro>", trace_memory=True)


def test_time_budget_still_enforced(monkeypatch):
    slow = fh.MAX_CASE_SECONDS + 1
    action = _fake_clock(monkeypatch, untraced_cost=slow, traced_cost=0.0)
    with pytest.raises(AssertionError, match=rf"case: took {slow:.2f} s \(>"):
        fh.run_contract("case", action, "<repro>", trace_memory=True)


def test_traced_run_gets_a_stretched_hang_guard(monkeypatch):
    guards: list = []
    real_guard = fh.hang_guard

    def recording_guard(seconds):
        guards.append((tracemalloc.is_tracing(), seconds))
        return real_guard(seconds)

    monkeypatch.setattr(fh, "hang_guard", recording_guard)
    fh.run_contract("case", lambda: None, "<repro>", trace_memory=True, hang_seconds=2.0)
    assert guards == [(False, 2.0), (True, 2.0 * fh.TRACED_HANG_FACTOR)]


def test_memory_budget_still_enforced(monkeypatch):
    monkeypatch.setattr(fh, "MAX_CASE_PEAK_BYTES", 1024)
    with pytest.raises(AssertionError, match="tracemalloc peak"):
        fh.run_contract("case", lambda: bytearray(fh.MIB), "<repro>", trace_memory=True)
    assert not tracemalloc.is_tracing()


def test_uncaught_exception_fails_the_contract():
    def boom():
        raise ValueError("bad input")

    with pytest.raises(pytest.fail.Exception, match="case: uncaught ValueError: bad input"):
        fh.run_contract("case", boom, "<repro>", trace_memory=True)
    assert not tracemalloc.is_tracing()


def test_allowed_exception_passes():
    def boom():
        raise ValueError("documented")

    fh.run_contract("case", boom, "<repro>", allowed=(ValueError,), trace_memory=True)


def test_fuzz_bytes_function_gives_both_runs_the_same_rng():
    """Timed and traced runs of one input see identical random choices."""
    draws: list = []

    def action(_data: bytes, rng: random.Random) -> None:
        draws.append((tracemalloc.is_tracing(), rng.random()))

    fh.fuzz_bytes_function("t", 0, [b"seed"], action, (), mutants=1)
    assert [traced for traced, _ in draws] == [False, True]
    assert draws[0][1] == draws[1][1]
