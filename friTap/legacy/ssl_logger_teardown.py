"""Teardown for :class:`SSL_Logger`: the graceful_detach RPC, child-agent release,
the bounded unload/detach thread and the cleanup() chokepoint.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import os
import threading
import time

from ..events import DetachReportEvent
from ..pcap import PCAP
from .android_unfreeze import unfreeze_android_pids
from .ssl_logger_state import _ChildAgent
from .ssl_logger_state import core_module as _core


class TeardownMixin:
    """The shutdown sequence (see the step list below) and cleanup()."""


    # Shutdown sequence, shared by SIGINT, --duration, target death, API stop
    # and the TUI:
    #   0. disable spawn gating and resume the spawns it still holds, so no
    #      unrelated app is held (or "skipped") while teardown runs;
    #   1. stop the instrumentation thread; on Android, thaw the instrumented
    #      processes the cached-apps freezer froze (they cannot run the RPC);
    #   2. graceful_detach RPC while the consumer runs and outputs are open
    #      (its reply is the DetachReport);
    #   3. stop the consumer and drain the queue; everything sent before the
    #      RPC reply is already enqueued (same channel);
    #   4./5. cleanup steps, output close, finalizers (_run_cleanup_steps);
    #   6. unload + session.detach on a daemon thread (detach_with_timeout),
    #      without a second graceful_detach.
    # Steps 2 and 6 target the main agent (self.script) and every gated child
    # agent together: their graceful_detach RPCs run at once under one deadline
    # (_detach_all_agents_gracefully), and their unloads run at once under one
    # 5 s deadline (_unload_main_script_bounded, _release_child_agents), so
    # teardown time does not grow with the number of processes.

    # Default bound for the graceful RPC and for the unload/detach thread;
    # --timeout overrides both (see _detach_timeout).
    DEFAULT_DETACH_TIMEOUT = 30

    # The agent's DetachReport dict; None if the RPC returned nothing, failed,
    # was skipped or timed out.
    detach_report = None
    # None = not attempted yet; else one of the GRACEFUL_* outcomes below.
    _graceful_detach_outcome = None
    _last_detach_progress = None
    _agent_shutdown_done = False
    # Set by _end_session: the target is gone, so its script cannot answer.
    _target_gone = False

    GRACEFUL_OK = "ok"
    GRACEFUL_FAILED = "failed"          # the RPC raised (e.g. script destroyed)
    GRACEFUL_TIMEOUT = "timeout"        # the RPC is wedged on the agent side
    GRACEFUL_SKIPPED = "skipped"        # no script / dead script / no export

    # A graceful_detach RPC that has not entered its agent (no detach_progress
    # marker, sent as gracefulDetach's first statement) within this many
    # seconds is abandoned as GRACEFUL_TIMEOUT: the target cannot run the
    # agent's JS thread (process frozen by Android's cached-app freezer,
    # stopped, or wedged in a hook), so waiting the full timeout only delays
    # teardown. Bounded by the RPC timeout itself.
    GRACEFUL_ENTRY_TIMEOUT = 10.0
    _GRACEFUL_POLL_SECONDS = 0.05

    def _detach_timeout(self) -> int:
        """--timeout when set (> 0), else DEFAULT_DETACH_TIMEOUT."""
        device = getattr(getattr(self, "_config", None), "device", None)
        cli_timeout = getattr(device, "timeout", None)
        if isinstance(cli_timeout, int) and not isinstance(cli_timeout, bool) and cli_timeout > 0:
            return cli_timeout
        return self.DEFAULT_DETACH_TIMEOUT

    def _script_is_dead(self) -> bool:
        script = getattr(self, "script", None)
        return (script is None or getattr(self, "_target_gone", False)
                or bool(getattr(script, "is_destroyed", False)))

    def _graceful_detach_export(self, script=None):
        """The graceful_detach RPC callable of *script* (default: main agent), or None.

        Frida 17 splits the proxy into exports_sync and async exports; prefer
        exports_sync so the call blocks until JS returns (async would race unload)."""
        target = self.script if script is None else script
        for proxy_name in ("exports_sync", "exports"):
            proxy = getattr(target, proxy_name, None)
            graceful = getattr(proxy, "graceful_detach", None) if proxy is not None else None
            if callable(graceful):
                return graceful
        return None

    def _call_graceful_detach_bounded(self, timeout) -> None:
        """Call graceful_detach once on a daemon worker bounded by *timeout*; never raises.

        The agent sets its shutdown flag, runs its registered teardowns, then
        Interceptor.detachAll, and returns its DetachReport. The worker keeps a
        wedged agent from blocking teardown: after *timeout* the RPC is abandoned
        (GRACEFUL_TIMEOUT). Records ``detach_report`` and the outcome.
        """
        main = self._start_main_graceful_detach()
        if main is None:
            return
        self._await_graceful_workers([(self.script, main[0])], timeout)
        self._graceful_detach_outcome = self._graceful_outcome_of(*main, timeout)

    def _start_main_graceful_detach(self):
        """Start the main agent's graceful_detach once; ``(worker, result)``, or None when skipped."""
        if self._graceful_detach_outcome is not None:
            return None  # never call graceful_detach a second time
        self._graceful_detach_outcome = self.GRACEFUL_SKIPPED
        if self._script_is_dead():
            self.logger.debug("graceful_detach skipped: script missing or target gone")
            return None
        graceful = self._graceful_detach_export()
        if graceful is None:
            return None
        return self._start_graceful_detach_worker(graceful)

    def _await_graceful_workers(self, workers, timeout) -> None:
        """Wait for ``(script, worker)`` RPC workers under one *timeout* deadline.

        Stops waiting for a worker whose RPC has not entered its agent by
        GRACEFUL_ENTRY_TIMEOUT; returns as soon as nothing is left to wait for."""
        started = time.monotonic()
        deadline = started + timeout
        entry_deadline = started + min(self.GRACEFUL_ENTRY_TIMEOUT, timeout)
        waiting = [(script, worker) for script, worker in workers if worker.is_alive()]
        while waiting:
            now = time.monotonic()
            if now >= deadline:
                return
            if now >= entry_deadline:
                waiting = [(script, worker) for script, worker in waiting
                           if script in self._detach_entered_scripts]
                if not waiting:
                    return
            waiting[0][1].join(min(self._GRACEFUL_POLL_SECONDS, deadline - now))
            waiting = [(script, worker) for script, worker in waiting if worker.is_alive()]

    @staticmethod
    def _start_graceful_detach_worker(graceful):
        """Start graceful_detach on a daemon worker; return ``(worker, result)``.

        *result* gets ``"report"`` or ``"error"``; the caller bounds it with join()."""
        result = {}

        def call():
            try:
                result["report"] = graceful()
            except Exception as exc:  # noqa: BLE001 - e.g. "script has been destroyed"
                result["error"] = exc

        worker = threading.Thread(target=call, daemon=True, name="fritap-graceful-detach")
        worker.start()
        return worker, result

    @property
    def _detach_entered_scripts(self) -> "set":
        """Scripts whose agent sent a detach_progress marker (their RPC entered the agent)."""
        return self.__dict__.setdefault("_detach_entered_scripts_set", set())

    def _note_detach_progress(self, script, marker) -> None:
        """A detach_progress *marker* from *script*'s agent; runs on Frida's callback thread."""
        if script is None or not isinstance(marker, dict):
            return
        self._detach_entered_scripts.add(script)
        if script is self.script:
            self._record_detach_progress(marker)

    def _record_detach_progress(self, marker) -> None:
        if not isinstance(marker, dict):
            return
        phase, step = marker.get("phase"), marker.get("step")
        if phase == "entered":
            self._last_detach_progress = "RPC entered"
        elif phase in ("started", "finished") and isinstance(step, str):
            self._last_detach_progress = f"{phase} step {step[:200]!r}"

    def _graceful_outcome_of(self, worker, result, timeout) -> str:
        if worker.is_alive():
            if self._last_detach_progress is None:
                self.logger.warning(
                    "Agent graceful_detach did not return: no RPC-entry marker arrived "
                    "within %ss (the target process may be frozen, stopped or "
                    "unresponsive); continuing teardown",
                    min(self.GRACEFUL_ENTRY_TIMEOUT, timeout))
            else:
                self.logger.warning(
                    "Agent graceful_detach did not return within %ss (%s); continuing teardown",
                    timeout, self._last_detach_progress)
            return self.GRACEFUL_TIMEOUT
        if "error" in result:
            self.logger.debug("graceful_detach RPC failed: %s", result["error"])
            return self.GRACEFUL_FAILED
        report = result.get("report")
        self.detach_report = report if isinstance(report, dict) else None
        return self.GRACEFUL_OK

    def _detach_agent_gracefully(self) -> None:
        """Step 2: the bounded graceful_detach RPCs (main and child agents at once), then render the main report."""
        self._detach_all_agents_gracefully(self._detach_timeout())
        if self._graceful_detach_outcome == self.GRACEFUL_OK:
            from ..detach_report import log_detach_report
            try:
                log_detach_report(self.logger, self.detach_report)
            except Exception:  # noqa: BLE001 - rendering must not break teardown
                self.logger.debug("detach report rendering failed", exc_info=True)

    def _emit_detach_report(self) -> None:
        """Emit the detach report (or why there is none) to the still-open outputs.

        No-op when graceful_detach was never attempted."""
        outcome = self._graceful_detach_outcome
        if outcome is None:
            return
        if outcome == self.GRACEFUL_SKIPPED and getattr(self, "script", None) is None:
            return  # no agent was ever loaded (e.g. spawn failed): nothing to report
        report = self.detach_report if outcome == self.GRACEFUL_OK else None
        status = None if report is not None else (
            outcome if outcome != self.GRACEFUL_OK else "unavailable")
        try:
            self._event_bus.emit(DetachReportEvent(report=report, status=status))
        except Exception:  # noqa: BLE001 - never break teardown
            self.logger.debug("detach report emit failed", exc_info=True)

    def _child_agents_snapshot(self) -> "list[_ChildAgent]":
        with self._child_agents_lock:
            return list(self._child_agents)

    def _detach_child_agents_gracefully(self, timeout) -> None:
        """graceful_detach on every child agent, after the main one; idempotent.

        One daemon worker per child, all under one shared *timeout* deadline so
        many or wedged children cannot multiply teardown time. Results go to
        DEBUG only; ``detach_report`` stays the main target's."""
        pending = self._start_child_graceful_detaches()
        self._await_graceful_workers([(child.script, worker) for child, worker, _ in pending],
                                     timeout)
        self._classify_child_graceful_detaches(pending)

    def _detach_all_agents_gracefully(self, timeout) -> None:
        """graceful_detach on the main agent and every child agent at once; idempotent.

        One shared *timeout* deadline (and GRACEFUL_ENTRY_TIMEOUT for an RPC
        that never enters its agent), so a wedged or frozen process delays
        teardown once, not once per agent. Only the main RPC sets
        ``detach_report`` and the outcome; child results go to DEBUG."""
        self._unfreeze_android_targets()
        main = self._start_main_graceful_detach()
        children = self._start_child_graceful_detaches()
        workers = [(child.script, worker) for child, worker, _ in children]
        if main is not None:
            workers.insert(0, (self.script, main[0]))
        self._await_graceful_workers(workers, timeout)
        if main is not None:
            self._graceful_detach_outcome = self._graceful_outcome_of(*main, timeout)
        self._classify_child_graceful_detaches(children)

    def _start_child_graceful_detaches(self) -> list:
        """Start graceful_detach on every child agent not yet attempted; ``[(child, worker, result)]``."""
        pending = []
        for child in self._child_agents_snapshot():
            if child.graceful_outcome is not None:
                continue
            child.graceful_outcome = self.GRACEFUL_SKIPPED
            graceful = (None if getattr(child.script, "is_destroyed", False)
                        else self._graceful_detach_export(child.script))
            if graceful is not None:
                pending.append((child, *self._start_graceful_detach_worker(graceful)))
        return pending

    def _classify_child_graceful_detaches(self, pending) -> None:
        for child, worker, result in pending:
            child.graceful_outcome = self._child_graceful_outcome(child, worker, result)

    def _child_graceful_outcome(self, child, worker, result) -> str:
        """Classify one child's graceful_detach and log it at DEBUG."""
        if worker.is_alive():
            self.logger.debug("child pid %s: graceful_detach did not return in time",
                              child.pid)
            return self.GRACEFUL_TIMEOUT
        if "error" in result:
            self.logger.debug("child pid %s: graceful_detach failed: %s",
                              child.pid, result["error"])
            return self.GRACEFUL_FAILED
        from ..detach_report import summary_line
        self.logger.debug("child pid %s: %s", child.pid, summary_line(result.get("report")))
        return self.GRACEFUL_OK

    # Bound for the unloads of all child agents together. They start alongside
    # the main agent's unload (its own 5 s bound), so both bounds overlap.
    CHILD_UNLOAD_TIMEOUT = 5.0

    @property
    def _child_unloads_in_flight(self) -> "list":
        """``(child, worker)`` unloads started but not yet joined; mutate only under _child_agents_lock."""
        return self.__dict__.setdefault("_child_unloads_in_flight_list", [])

    def _start_child_unloads(self) -> None:
        """Start the unload of every registered child agent on its own daemon worker; never raises.

        A failed or destroyed child is left to process exit; a wedged one (RPC
        timed out) gets a bounded unload + detach (_release_wedged_agent). The first
        start of a batch sets the batch's shared CHILD_UNLOAD_TIMEOUT deadline."""
        with self._child_agents_lock:
            children = list(self._child_agents)
            self._child_agents.clear()
        started = []
        for child in children:
            if (child.graceful_outcome == self.GRACEFUL_FAILED
                    or getattr(child.script, "is_destroyed", False)):
                self.logger.debug("child pid %s: agent gone; not unloading it", child.pid)
                continue
            if child.graceful_outcome == self.GRACEFUL_TIMEOUT:
                # Unload + detach at once inside the worker (bounded); no
                # second detach afterwards (see _release_child_agents).
                self._wedged_child_releases.add(id(child))
                worker = threading.Thread(
                    target=self._release_wedged_agent,
                    args=(child.script, child.session, f"child pid {child.pid}"),
                    daemon=True, name="fritap-child-wedged-release")
                worker.start()
                started.append((child, worker))
                continue
            worker = threading.Thread(target=self._backend.unload_script, args=(child.script,),
                                      daemon=True, name="fritap-child-unload")
            worker.start()
            started.append((child, worker))
        with self._child_agents_lock:
            if started and not self._child_unloads_in_flight:
                self._child_unload_deadline = time.monotonic() + self.CHILD_UNLOAD_TIMEOUT
            self._child_unloads_in_flight.extend(started)

    def _release_child_agents(self) -> None:
        """Unload every child agent, then detach its session; idempotent, never raises.

        Same rules as the main agent: a wedged, failed or destroyed child is
        left to process exit, unloads share one deadline (also those already
        started alongside the main unload), and a session is detached only
        after its unload returned."""
        self._start_child_unloads()
        with self._child_agents_lock:
            unloads = list(self._child_unloads_in_flight)
            self._child_unloads_in_flight.clear()
            deadline = self._child_unload_deadline
        for child, worker in unloads:
            worker.join(max(0.0, deadline - time.monotonic()))
            if id(child) in self._wedged_child_releases:
                continue  # its worker already detached the session (bounded)
            if worker.is_alive():
                # Seen on a Pixel 5 (GSA children re-gated after the main target
                # died): unload never returns and a session.detach does not either,
                # so the inert agent (hooks already reverted by graceful_detach)
                # stays mapped until the process exits.
                self.logger.debug("child pid %s: unload did not return in time; "
                                  "leaving its session", child.pid)
                continue
            try:
                self._backend.detach(child.session)
            except Exception:  # noqa: BLE001 - best effort, like the main detach
                self.logger.debug("child pid %s: session detach failed", child.pid,
                                  exc_info=True)

    _child_unload_deadline = 0.0

    @property
    def _wedged_child_releases(self) -> "set":
        """ids of children released by _release_wedged_agent (unload + detach in one worker)."""
        return self.__dict__.setdefault("_wedged_child_releases_set", set())

    # Set by session_manager when it turned Frida spawn gating on.
    _spawn_gating_enabled = False
    _spawn_gating_disabled_for_teardown = False

    def _disable_spawn_gating_for_teardown(self) -> None:
        """Step 0: turn spawn gating off, then resume the spawns it still holds; idempotent, never raises.

        Without this, unrelated apps spawned after Ctrl+C were held and only
        resumed one by one ("Skipping unrelated spawn") until teardown ended."""
        if not self._spawn_gating_enabled or self._spawn_gating_disabled_for_teardown:
            return
        self._spawn_gating_disabled_for_teardown = True
        device = getattr(self, "device", None)
        try:
            self._backend.disable_spawn_gating(device)
        except Exception:  # noqa: BLE001 - device gone, backend without gating
            self.logger.debug("disable_spawn_gating failed", exc_info=True)
            return
        self._resume_pending_spawns(device)

    def _resume_pending_spawns(self, device) -> None:
        """Resume every spawn still held by our gating; the instrument worker is stopping anyway."""
        try:
            pending = self._backend.enumerate_pending_spawn(device)
        except Exception:  # noqa: BLE001
            self.logger.debug("enumerate_pending_spawn failed", exc_info=True)
            return
        for spawn in pending:
            pid = getattr(spawn, "pid", None)
            if pid is None:
                continue
            self.logger.debug("Teardown: resuming held spawn pid %s (%s)", pid,
                              getattr(spawn, "identifier", "?"))
            self._resume_suspended(pid)

    _android_unfreeze_done = False

    def _unfreeze_android_targets(self) -> None:
        """Android: thaw the main target and every child before their RPCs; once, bounded, never raises.

        A process frozen by the cached-apps freezer cannot run graceful_detach
        or unload (see android_unfreeze). Needs adb and root; otherwise a no-op."""
        if self._android_unfreeze_done:
            return
        self._android_unfreeze_done = True
        try:
            if getattr(self, "_target_gone", False) or not self._is_android_target():
                return
            pids = [self._main_target_pid()] + [c.pid for c in self._child_agents_snapshot()]
            from .profile_capture import adb_serial_of
            unfreeze_android_pids(adb_serial_of(self), pids)
        except Exception:  # noqa: BLE001 - best effort, must not break teardown
            self.logger.debug("unfreeze before detach failed", exc_info=True)

    def _main_target_pid(self):
        """The main target's pid: ``self.pid``, else the Frida session's."""
        pid = getattr(self, "pid", None)
        if pid:
            return pid
        impl = getattr(getattr(self, "process", None), "_impl", None)
        return getattr(impl, "pid", None)

    def _shutdown_agent_and_drain(self) -> None:
        """Steps 1-3 of the shutdown sequence; idempotent."""
        if self._agent_shutdown_done:
            return
        self._agent_shutdown_done = True
        self._disable_spawn_gating_for_teardown()  # step 0: before any agent goes
        self._stop_instrument_thread()  # also resumes every pid left suspended
        self._detach_agent_gracefully()  # the main agent and its children at once
        # Any child not covered above, while the consumer still takes their messages.
        self._detach_child_agents_gracefully(self._detach_timeout())
        self._stop_consumer_thread()  # drains everything sent before the reply

    def detach_with_timeout(self, timeout=30):
        """Unload and detach the main agent on a daemon thread joined for *timeout* seconds.

        30 s default: script.unload() waits for in-flight Interceptor callbacks,
        and a heavily hooked process (Chrome QUIC) can stay busy >5 s after
        Ctrl+C, causing spurious "Detach process timed out" warnings.
        """
        self._disable_spawn_gating_for_teardown()  # no-op after _shutdown_agent_and_drain
        # For the post-detach crash report: did the target outlive the teardown so far?
        note_alive = getattr(self, "_note_target_alive_at_detach", None)
        if callable(note_alive):
            note_alive()

        def detach():
            try:
                self._detach_main_agent(timeout)
            except Exception as e:
                self.logger.error(f"Error while detaching: {e}")
            finally:
                # Step 6 for child agents, also when the main target is gone or
                # wedged: a child may outlive it.
                self._release_child_agents()

        # daemon=True: a timed-out detach thread is abandoned. A non-daemon one
        # would block threading._shutdown() and hang the host until a second
        # Ctrl+C. The OS reclaims the Frida session on exit anyway.
        detach_thread = threading.Thread(target=detach, daemon=True)
        detach_thread.start()
        detach_thread.join(timeout=timeout)

        if detach_thread.is_alive():
            if self.debug_output:
                self.logger.warning(f"Detach process timed out after {timeout} seconds.")
            # Frida offers no forced detach; the thread is left to finish.
        elif self._main_session_detached and self.debug_output:
            self.logger.debug("Detached friTap from process successfully.")

    def _detach_main_agent(self, timeout) -> None:
        """Steps 1-4 for the main agent, run on detach_with_timeout's thread."""
        if self.debug_output or self.debug:
            self.logger.debug("Attempting to detach from instrumented process...")

        # Fast path: a dead target (native crash in a hook surfaces as
        # 'process-terminated' and destroys the script) would make every Frida
        # call below block until the outer timeout, delaying cleanup()'s goodbye
        # and os._exit so users press Ctrl+C again.
        # A script this class unloaded (finish_fritap first, the TUI's order) is
        # destroyed too, but its session is still attached, so detach still runs.
        unloaded_by_us = self._main_script_unloaded
        script_dead = ((bool(getattr(self.script, "is_destroyed", False))
                        and not unloaded_by_us)
                       or self._target_gone)

        # Step 1: graceful_detach. Usually already done by
        # _shutdown_agent_and_drain, so a no-op here; direct callers still get it.
        # The agent sets its shutdown flag before Interceptor.detachAll, so queued
        # callbacks short-circuit at sendDatalog / emit.
        # Child agents too (idempotent per child), at once with the main agent;
        # unloaded alongside the main unload, joined in the finally.
        self._detach_all_agents_gracefully(timeout)
        outcome = self._graceful_detach_outcome
        script_dead = script_dead or self._target_gone or (
            not unloaded_by_us and bool(getattr(self.script, "is_destroyed", False)))
        if outcome == self.GRACEFUL_TIMEOUT:
            # Agent wedged in gracefulDetach (or its process frozen): a plain
            # unload would serialize behind it. Still free what we can: unload
            # and session.detach at once, bounded by WEDGED_RELEASE_TIMEOUT, so
            # frida-server drops the agent instead of leaving it mapped.
            self._start_child_unloads()  # alongside, not after, the main release
            if not script_dead:
                self._release_wedged_main_agent()
            return

        # Target gone: return now so cleanup() exits without delay.
        if script_dead:
            if self.debug_output or self.debug:
                self.logger.debug(
                    "target/script already gone — skipping unload + "
                    "session.detach()"
                )
            return
        if outcome == self.GRACEFUL_FAILED and not unloaded_by_us:
            self.logger.warning("Skipping unload and session detach after graceful_detach RPC failure.")
            return

        # Step 2: let pending JS callbacks drain (each is one shutdown-flag
        # check, so 200 ms covers thousands) before unload runs.
        try:
            threading.Event().wait(0.2)
        except Exception:
            pass

        unload_thread = self._unload_main_script_bounded(unloaded_by_us)

        # Step 4: session.detach(), only when unload returned. Keep this
        # conditional: detaching while unload is still in flight serializes
        # behind it (the 30 s "Detach process timed out" hang under heavy QUIC
        # capture). Hooks are already gone via gracefulDetach's detachAll, so a
        # wedged unload is left to process exit / frida-server.
        if unload_thread is not None and unload_thread.is_alive():
            self.logger.warning(
                "script.unload() did not return within 5s; skipping session.detach()."
            )
        else:
            self._detach_main_session_once()

    # Bound for releasing an agent whose graceful_detach timed out: its unload
    # and session.detach run at once, so the detach can end a stuck unload.
    WEDGED_RELEASE_TIMEOUT = 2.0

    def _release_wedged_agent(self, script, session, label) -> bool:
        """Unload *script* and detach *session* concurrently within WEDGED_RELEASE_TIMEOUT.

        True when the session detach returned. Never raises; a call still
        stuck at the bound is left to process exit (daemon threads)."""
        outcome = {}

        def detach_session():
            try:
                self._backend.detach(session)
                outcome["detached"] = True
            except Exception:  # noqa: BLE001 - best effort
                self.logger.debug("%s: session detach failed", label, exc_info=True)

        workers = [threading.Thread(target=self._backend.unload_script, args=(script,),
                                    daemon=True, name="fritap-wedged-unload")]
        if session is not None:
            workers.append(threading.Thread(target=detach_session, daemon=True,
                                            name="fritap-wedged-detach"))
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + self.WEDGED_RELEASE_TIMEOUT
        for worker in workers:
            worker.join(max(0.0, deadline - time.monotonic()))
        self.logger.debug("%s: wedged agent released (session detach %s)", label,
                          "returned" if outcome.get("detached") else "did not return")
        return bool(outcome.get("detached"))

    def _release_wedged_main_agent(self) -> None:
        """The main agent's graceful_detach timed out: bounded concurrent unload + detach."""
        if self._main_session_detach_attempted:
            return
        self._main_session_detach_attempted = True
        session = self.process
        self._main_session_detached = self._release_wedged_agent(
            self.script, session, "main target")

    def _unload_main_script_bounded(self, unloaded_by_us):
        """Step 3: unload the main script on a daemon thread joined for 5 s; the thread, or None.

        The child agents' unloads start right after the main one, so they run
        concurrently instead of after it (_release_child_agents joins them)."""
        # script.unload() has no native timeout and blocks forever on a busy JS
        # thread. Skipped without a main script (memory-scan-only run, whose
        # plugin scripts unload via the plugin loader). None lets step 4's
        # liveness check work in that case.
        unload_thread = None
        if self.script is not None and not unloaded_by_us:
            unload_thread = threading.Thread(
                target=lambda: self._backend.unload_script(self.script),
                daemon=True,
            )
            unload_thread.start()
        self._start_child_unloads()
        if unload_thread is not None:
            unload_thread.join(timeout=5)
        return unload_thread

    # Class-level defaults so bare ``SSL_Logger.__new__`` test instances have them.
    _main_script_unloaded = False
    _main_session_detach_attempted = False
    _main_session_detached = False

    def _detach_main_session_once(self) -> None:
        """``session.detach()`` the main session, at most once per session."""
        if self._main_session_detach_attempted or self.process is None:
            return
        self._main_session_detach_attempted = True
        try:
            self._backend.detach(self.process)
        except Exception as exc:
            self.logger.error("Backend session detach failed: %s", exc)
        else:
            self._main_session_detached = True

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        self._session_manager.pcap_cleanup(is_full_capture, is_mobile, pcap_name)

    def cleanup(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False,
                *, exit_process=True):
        """The one teardown every stop path funnels through (idempotent).

        ``exit_process=False`` (embedding callers such as ``FriTapSession.stop``)
        runs every step and closes outputs as on the CLI, but skips the goodbye
        banner and ``os._exit``.
        """
        if self._cleanup_done:
            return
        self._cleanup_done = True

        # Wine GDB extraction first: the SIGINT handler force-exits right after
        # cleanup, so this is the only place that keeps the ptrace-attached gdb
        # from being orphaned. No-op otherwise.
        self._terminate_wine_gdb()

        # The goodbye and exit in the finally run even if a step raised. Callers:
        # SIGINT (main thread), target death (Frida callback thread via
        # on_detach), and the CLI's finally block in friTap.py.
        try:
            self._run_cleanup_steps(live, socket_trace, full_capture, debug_output, debug)
        except Exception as _cleanup_err:
            try:
                self.logger.error(f"Error during cleanup: {_cleanup_err}")
            except Exception:
                pass
        finally:
            # Outputs (the JSON document) must be complete before os._exit, even
            # if a step raised before close_output_handlers(). Idempotent.
            self._close_output_handlers_safely()
            if exit_process and (self._tui_mode or not self._embedded):
                self.special_logger.info("\nThanks for using friTap. Have a great day!")
            if not (exit_process and self._owns_process_exit()):
                # The host keeps running: wait()/running must see the end even
                # if a step raised before _run_cleanup_steps did it.
                self._mark_session_stopped()
            if exit_process and self._owns_process_exit():
                # os._exit, not sys.exit: SystemExit unwinds only this thread,
                # still joins the non-daemon Frida reactor thread (alive while
                # unload drains), and does nothing on a Frida callback thread.
                # os._exit ends the process from any thread; no second Ctrl+C.
                os._exit(self._exit_status)

    def _release_lsass_contributor(self):
        """Stop the LSASS helper session (Windows only; never raises).

        It holds references on the shared output files, so it must be released
        before this session's handlers close. No-op for the LSASS session itself.
        """
        output = getattr(getattr(self, "_config", None), "output", None)
        if output is None or getattr(output, "auxiliary_session", False):
            return
        from ..fritap_utility import are_we_running_on_windows
        if are_we_running_on_windows():
            _core()._release_lsass_keylog_writer(self.logger)

    def _run_cleanup_steps(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False):
        """The teardown steps; only called from cleanup(), which handles exit."""
        # Steps 1-3: instrumentation stop, graceful_detach, consumer drain.
        self._shutdown_agent_and_drain()
        # No more -pm modifications once the agent is shut down; an embedding
        # host (API/TUI) would otherwise keep the watcher thread alive.
        self._stop_payload_mod_watcher()
        # After the consumer drained, so every plaintext_api_learned report is in.
        self._save_learned_offsets()

        self._release_plugins_and_scan_engine()

        # Live passive analysis after plugins unload, before detaching; guarded.
        self._finalize_live_scan()

        # The Windows LSASS helper session shares our -p/-k/--json files; release
        # it first so its records are in before the last releaser completes them
        # (the JSON document, the full-capture finalize below).
        self._release_lsass_contributor()

        self.close_output_handlers()
        # Before finalize_full_capture below, which writes the manifest.
        self._close_request_context_sidecar()
        # -p: the plaintext pcap is closed now; switch synthetic streams to
        # their real tuples where safe and record the manifest summary.
        self._finalize_plaintext_pcap(full_capture)

        if self.pcap_obj is not None and full_capture:
            if self.pcap_obj.full_capture_thread.is_alive():
                self.pcap_obj.full_capture_thread.join()
                time.sleep(2)

        if not self._handlers_active:
            from .cleanup_compat import cleanup_legacy
            cleanup_legacy(self)

        self._report_traced_sockets(socket_trace)

        if full_capture:
            self._finish_full_capture_outputs(socket_trace, debug_output, debug)

        self.running = False
        self._done_event.set()
        if self.process:
            self._detach_with_cli_timeout()
        self._hint_if_no_library_detected()

    def _release_plugins_and_scan_engine(self) -> None:
        """Unload the script plugins, then close the memory-scan engine."""
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.unload_all(self._plugin_shim)

        # close() stops the poll loop, closes sidecars and unloads its scripts.
        if getattr(self, "_memory_scan_engine", None) is not None:
            try:
                self._memory_scan_engine.close()
            except Exception:  # noqa: BLE001 - cleanup must not break teardown
                self.logger.debug("memory-scan: engine close() failed", exc_info=True)

    def _report_traced_sockets(self, socket_trace) -> None:
        """Write the traced sockets (--socket_tracing FILE) and log the Wireshark display filter."""
        if isinstance(socket_trace, str):
            self.logger.info(f"Write traced sockets into {socket_trace}")
            self.write_socket_trace(socket_trace)
        if socket_trace:
            display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
            self.logger.info(f"Generated Display Filter for Wireshark:\n{display_filter}")

    def _finish_full_capture_outputs(self, socket_trace, debug_output, debug) -> None:
        """-f: finalize the full-capture pcap, then the SChannel relabel and the .tap build."""
        if debug_output or debug:
            display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
            self.logger.debug(f"Generated Display Filter for Wireshark:\n{display_filter}")

        formatted_keys = self._collected_full_capture_keys()

        pcap_name = self.pcap_obj.pcap_file_name

        self._write_full_capture_pcap(pcap_name, formatted_keys, socket_trace)

        # Relabel the SChannel keylog (TLS 1.3 label swaps, ??? client_randoms)
        # by trial decryption so Wireshark loads it without --repair-keylog.
        self._auto_relabel_schannel_keylog(pcap_name)

        # -f --tap: the plaintext hooks were off, so build the .tap from the
        # finalized pcap + keylog (after the relabel, so it sees fixed keys).
        self._auto_build_tap_from_full_capture(pcap_name)

    def _collected_full_capture_keys(self):
        """The formatted keys for the full-capture DSB: the key collector's, else the Wine keylog's."""
        from ..output import KeyCollectorHandler
        formatted_keys = ()
        for handler in getattr(self, "_output_handlers", []):
            if isinstance(handler, KeyCollectorHandler):
                formatted_keys = handler.get_collected_keys()
                break
        # The Wine GDB path bypasses the agent's key events, so its keys only
        # exist in the keylog file the extractor wrote.
        if not formatted_keys:
            formatted_keys = self._wine_keylog_lines()
        return formatted_keys

    def _write_full_capture_pcap(self, pcap_name, formatted_keys, socket_trace) -> None:
        """Write the app-scoped / socket-filtered pcap or finalize the device-wide one (logs, never raises)."""
        # AppTap must finish the app-scoped pcap first (idempotent).
        if getattr(self.pcap_obj, "apptap_session", None) is not None:
            self.pcap_obj.stop_owner_capture()
        owner_active = getattr(self.pcap_obj, "capture_tier", None) is not None
        try:
            if self.traced_scapy_socket_Set and not owner_active:
                self.pcap_obj.create_application_traffic_pcap(
                    self.traced_scapy_socket_Set, self.pcap_obj,
                    formatted_keys=formatted_keys,
                )
            else:
                if owner_active:
                    self.logger.info(
                        f"owner-capture: {pcap_name} is already app-scoped by AppTap "
                        f"(tier={self.pcap_obj.capture_tier}); skipping socket-trace post-filter.")
                else:
                    suffix = (
                        f"PCAP {pcap_name} will contain all captured traffic from "
                        f"the device (frida/adb infrastructure excluded by default)."
                    )
                    if socket_trace:
                        self.logger.warning(f"friTap observed no sockets during capture. The resulting {suffix}")
                    else:
                        self.logger.info(f"Socket tracing disabled. The resulting {suffix}")

                # Manifest ports come from the socket trace (--socket_trace only).
                self.pcap_obj.finalize_full_capture(
                    formatted_keys,
                    traced_Socket_Set=self.traced_Socket_Set,
                )
        except Exception as e:
            self.logger.error(f"Error: {e}")

    def _detach_with_cli_timeout(self) -> None:
        """Step 6: unload + session.detach, bounded by --timeout or the 30 s default."""
        _cli_timeout = getattr(self._config.device, 'timeout', None)
        if isinstance(_cli_timeout, int) and _cli_timeout > 0:
            self.detach_with_timeout(timeout=_cli_timeout)
        else:
            self.detach_with_timeout()

    def _hint_if_no_library_detected(self) -> None:
        """Exit hint when the capture attached but no library was detected and no key captured."""
        if (self.process is not None and not self._detected_libraries
                and not self._captured_any_secret
                and not self._config.hooking.library_scan):
            if self._config.protocol in ("tls", "auto", "all"):
                self.special_logger.info(
                    "\n[Hint] No TLS libraries were detected. Consider using "
                    "--library-scan (-ls) to discover renamed or statically linked libraries."
                )
            else:
                self.special_logger.info(
                    f"\n[Hint] No {self._config.protocol.upper()} libraries were detected. "
                    "If you believe this is incorrect, please open an issue at "
                    "https://github.com/fkie-cad/friTap/issues"
                )
