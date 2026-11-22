"""Process following for :class:`SSL_Logger`: child/spawn gating, exec hand-over,
the serial instrument worker, suspended-pid bookkeeping and child agents.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import functools
import queue
import threading
from typing import Optional

from ..backends.base import BackendTransportError
from ..events import DetachEvent
from ..exit_codes import EXIT_RUNTIME_ERROR
from .exec_follow import HeldExecWatchdog, ProcessTracker, ResumeWorker, agent_answers
from .ssl_logger_state import _ChildAgent, _InstrumentRequest


class ProcessFollowingMixin:
    """Gated children, spawn gating, exec following and the instrument worker."""

    def on_child_added(self, child):
        """Route a gated child; never block here.

        Runs on Frida's event thread: instrumentation goes to the worker, a
        resume to the resumer thread.
        """
        origin = getattr(child, "origin", None)
        if origin == "exec" and self._tracker.is_tracked(child.pid):
            path = getattr(child, "path", None) or getattr(child, "identifier", None)
            self._on_exec_image(child.pid, path)
        elif not self._gates_only_to_follow_exec:
            self._enqueue_instrumentation(child.pid, "child process",
                                          getattr(child, "identifier", None),
                                          watch_as_main=False)
        else:
            # Gating is on only to follow exec(); a fork/spawn child was not asked for.
            self._resume_untouched(child.pid, origin)

    # Exec following. _watch_process sets up every instrumented process before its
    # agent loads: child gating, a detach handler and the held-exec watchdog. On
    # exec() (e.g. Homebrew's python3 launcher) Frida ends the old session with
    # 'process-replaced' and reports the new image as a child of origin "exec"
    # with the SAME pid, held suspended. The worker instruments it and it replaces
    # the old session (for the target, the main one; outputs never close). The two
    # events can arrive in either order (the detach runs on its own thread), so
    # they are matched per pid by count.

    # How long a 'process-replaced' waits for its exec'd image before the process
    # counts as gone (e.g. an Apple platform binary Frida cannot gate).
    EXEC_HANDOVER_TIMEOUT = 5.0

    # How long a held-exec suspect's agent gets to answer before its image counts as replaced.
    HELD_EXEC_PROBE_TIMEOUT = 2.0

    def _init_process_following(self) -> None:
        """Create the exec-following and resume helpers (see __init__)."""
        self._tracker = ProcessTracker()
        self._held_exec_watchdog = HeldExecWatchdog(
            self._query_process_paths, self._on_held_exec_image)
        self._resumer = ResumeWorker(self._resume_and_untrack)

    @property
    def _gates_only_to_follow_exec(self) -> bool:
        """Sessions are gated only to follow exec(); reported fork/spawn children were not asked for.

        Decided by the options alone, whether or not the target's own gating succeeded.
        """
        return self.exec_following_requested and not self.enable_child_gating

    def follow_exec_of(self, process) -> bool:
        """Watch the target's session for exec() and, with --enable_child_gating, children.

        True when gated. With --enable_child_gating a gating failure propagates;
        otherwise a 'process-replaced' is followed by re-attaching (see
        _on_process_replaced). The detach handler is SessionManager's.
        """
        self._log_follow_exec_decision()
        pid = getattr(self, "pid", None)
        if pid is None:
            pid = getattr(process, "pid", None)
        return self._gate_and_track(process, pid, is_main=True,
                                    required=self.enable_child_gating)

    def _log_follow_exec_decision(self) -> None:
        """Log once what the follow-exec default did, or warn when child gating is on."""
        device = self._config.device
        if getattr(self, "_follow_exec_logged", False):
            return
        self._follow_exec_logged = True
        explicit_on = device.follow_exec is True or bool(self.enable_child_gating)
        if explicit_on:
            self.logger.warning(
                "child gating is on: Frida 17.24.3-17.27.x can crash or park a "
                "forked child of the target (known Frida fork-child crash); "
                "drop --follow-exec/--enable_child_gating if the target dies")
        elif device.follow_exec is None:
            self.logger.info(
                "exec-following (Frida child gating) is off by default: avoids a "
                "Frida fork-child crash; use --follow-exec to opt in")

    def _gate_and_track(self, session, pid, is_main, required=False) -> bool:
        """Gate *session*'s children if asked, track *pid* and watch it for held exec images."""
        gated = self._gate_children_of(session, required=required)
        self._tracker.track(pid, session=session, is_main=is_main, gated=gated)
        if gated:
            self._held_exec_watchdog.watch(pid)
        return gated

    def _gate_children_of(self, session, required=False) -> bool:
        """Turn child gating on for *session* if exec following or --enable_child_gating asks."""
        if not self.gates_children:
            return False
        try:
            self._backend.enable_child_gating(session)
        except Exception:
            if required:
                raise
            self.logger.debug("child gating unavailable for this session; an exec() "
                              "of it is followed by re-attaching", exc_info=True)
            return False
        return True

    def _watch_process(self, session, pid, is_main) -> None:
        """Watch a fresh process before its agent loads, so a death during load or an exec() is caught."""
        self._gate_and_track(session, pid, is_main=is_main)
        if is_main:
            self.process = session
            self._backend.on_detached(session, self.on_detach)
        else:
            self._watch_child_detach(session, pid)

    def _watch_child_detach(self, session, pid) -> None:
        handler = functools.partial(self._on_child_detached, pid, session)
        try:
            self._backend.on_detached(session, handler)
        except Exception:  # noqa: BLE001 - a child's detach is informational
            self.logger.debug("cannot watch child pid %s for detach", pid, exc_info=True)

    def _on_child_detached(self, pid, session, reason, crash=None) -> None:
        """A child's session ended: a hand-over if it exec()ed, else the child is gone."""
        if reason == "process-replaced" and self._on_process_replaced(pid):
            return
        if self._forget_process(pid, session):
            self.logger.debug("Instrumented child pid %s detached (%s)", pid, reason)

    def _forget_process(self, pid, session=None) -> bool:
        forgotten = self._tracker.forget(pid, session)
        if forgotten:
            self._held_exec_watchdog.forget(pid)
        return forgotten

    def _on_exec_image(self, pid, path) -> None:
        """Frida holds an exec'd image: instrument it (the worker resumes it), or let it run with --no-follow-exec."""
        self._tracker.note_image(pid)
        self._held_exec_watchdog.note_exec(pid)
        entry = self._tracker.get(pid)
        if entry is None or not self.exec_following_requested:
            self._resume_untouched(pid, "exec")
            return
        self.logger.info("%s pid %s exec()ed %s; following it",
                         "Target" if entry.is_main else "Child", pid, path)
        self._enqueue_instrumentation(pid, "exec'd image", path, exec_handover=True,
                                      watch_as_main=entry.is_main)

    def _on_process_replaced(self, pid) -> bool:
        """The old image's 'process-replaced' detach. True for a hand-over (no teardown)."""
        entry = self._tracker.get(pid)
        if entry is None or not self.exec_following_requested:
            return False
        if not entry.gated:
            # Nothing holds the new image, so attach at once; its first instants run
            # uninstrumented (gating avoids that).
            self.logger.info("pid %s exec()ed; re-attaching to its new image", pid)
            self._enqueue_instrumentation(pid, "exec'd image", None, resume=False,
                                          exec_handover=True, watch_as_main=entry.is_main)
            return True
        self.logger.debug("pid %s replaced by exec(); handing over", pid)
        if self._tracker.note_replaced(pid):
            timer = threading.Timer(self.EXEC_HANDOVER_TIMEOUT,
                                    self._on_exec_handover_timeout, args=(pid,))
            timer.name = "fritap-exec-handover"
            timer.daemon = True
            timer.start()
        return True

    def _on_exec_handover_timeout(self, pid) -> None:
        """No exec'd image arrived after 'process-replaced': the process is gone; for the target the capture ends."""
        if (not self._tracker.awaiting_image(pid) or not self.running
                or getattr(self, "_cleanup_done", False)):
            return
        entry = self._tracker.get(pid)
        if entry is None or not entry.is_main:
            self.logger.warning(
                "Child pid %s exec()ed an image friTap could not follow (no exec "
                "child within %.0fs).", pid, self.EXEC_HANDOVER_TIMEOUT)
            self._forget_process(pid)
            return
        self.logger.error(
            "Target pid %s exec()ed an image friTap could not follow (no exec "
            "child within %.0fs; e.g. an Apple platform binary).",
            pid, self.EXEC_HANDOVER_TIMEOUT)
        self._mark_unexpected_detach()
        self._event_bus.emit(DetachEvent(reason="process-replaced"))
        self._end_session("process-replaced")

    def _query_process_paths(self, pids):
        return self._backend.process_paths(self.device, pids)

    def _on_held_exec_image(self, pid, path) -> None:
        """The watchdog found an exec'd image Frida never announced (see HeldExecWatchdog); take it over."""
        if not self._tracker.is_tracked(pid):
            return
        if self._current_agent_alive(pid):
            # A path change alone is no exec: re-attaching would double every hook.
            self.logger.debug("pid %s now reports %s but its agent still answers; "
                              "not an exec()", pid, path)
            return
        self.logger.warning(
            "pid %s exec()ed %s but Frida never reported the new image (the process "
            "closed Frida's descriptors before exec(), e.g. Python's subprocess "
            "with close_fds=True); taking it over now.", pid, path)
        self._on_exec_image(pid, path)

    def _current_agent_alive(self, pid) -> bool:
        """Whether *pid*'s session and agent still serve the instrumented image (no exec())."""
        entry = self._tracker.get(pid)
        if entry is None or getattr(entry.session, "is_detached", None) is True:
            return False
        if entry.script is None:
            return False  # nothing to ask: trust the watchdog
        return agent_answers(entry.script, self.HELD_EXEC_PROBE_TIMEOUT)

    def _on_failed_handover(self, request, exc) -> None:
        if request.watch_as_main:
            self._end_after_failed_handover(request.pid, exc)
            return
        self.logger.warning("Could not instrument the exec'd image of child pid %s "
                            "(%s); it runs uninstrumented.", request.pid, exc)
        self._forget_process(request.pid)

    def _end_after_failed_handover(self, pid, exc) -> None:
        """The exec'd image runs without friTap, so the capture ends.

        The end runs on its own thread because the teardown joins the calling worker.
        """
        if isinstance(exc, BackendTransportError):
            # The new image died while its agent loaded.
            self._mark_unexpected_detach()
        else:
            self.logger.error(
                "Could not instrument the exec'd image of pid %s (%s); it keeps "
                "running uninstrumented and the capture ends here.", pid, exc)
            self.set_exit_status(EXIT_RUNTIME_ERROR)
        threading.Thread(target=self._end_session, args=("exec hand-over failed",),
                         name="fritap-session-end", daemon=True).start()

    def _resume_untouched(self, pid, origin) -> None:
        """Let a gated process run uninstrumented; tracked so a racing teardown still resumes it."""
        self.logger.debug("Resuming %s child pid %s uninstrumented", origin or "?", pid)
        self._track_suspended(pid)
        self._resume_off_event_thread(pid)

    def _handle_child_added(self, child):
        """Forward a child that reached friTap off the Frida event thread to the worker.

        Must not instrument inline: instrument() blocks in script.load() waiting
        for a handshake reply, and this runs on the queue-consumer thread.
        """
        self._enqueue_instrumentation(child.pid, "child process",
                                      getattr(child, "identifier", None),
                                      watch_as_main=False)

    def on_spawn_added(self, spawn):
        # Frida's device event thread: decide here, instrument on the worker.
        # spawn_gating_all instruments every spawn; otherwise filter by identifier.
        if self.spawn_gating_all or self._should_instrument_spawn(spawn.identifier):
            self.logger.info(f"Instrumenting spawned process with pid {spawn.pid}. Name: {spawn.identifier}")
            self._enqueue_instrumentation(spawn.pid, "spawned process", spawn.identifier,
                                          watch_as_main=False)
        else:
            # Resume unrelated spawns at once so they do not hang.
            self.logger.debug(f"Skipping unrelated spawn with pid {spawn.pid}. Name: {spawn.identifier}")
            self._resume_off_event_thread(spawn.pid)

    def _enqueue_instrumentation(self, pid, label, identifier=None, resume=True,
                                 exec_handover=False, watch_as_main=None):
        """Hand a gated process to the serial instrument worker.

        ``resume=False``: already running (not Frida-gated). ``exec_handover``: the
        exec'd image of an instrumented process. ``watch_as_main``: see _watch_process.
        """
        if resume:
            self._track_suspended(pid)
        if not self.running or self._instrument_stop.is_set():
            # Teardown started: instrumenting now would resurrect the joined worker,
            # so resume instead. ``running`` alone is not enough: teardown stops the
            # worker first and clears ``running`` near its end, and an exec'd image
            # is reported right after the 'process-replaced' detach that starts it.
            # Instrumenting then left the process parked at Frida's spawn breakpoint
            # when friTap os._exit()ed (macOS: EXC_BREAKPOINT in
            # dyld4::RuntimeState::notifyObjCInit).
            self._resume_rejected_gated(pid, label, resume)
            return

        request = _InstrumentRequest(pid=pid, label=label, identifier=identifier,
                                     resume=resume, exec_handover=exec_handover,
                                     watch_as_main=watch_as_main)
        queue_full = False
        with self._instrument_thread_lock:
            # Re-checked under the lock _stop_instrument_thread sets the stop under:
            # a request is queued before the stop (worker or drain resumes it) or
            # rejected, never queued after the drain or reviving a joined worker.
            accepted = self.running and not self._instrument_stop.is_set()
            if accepted:
                self._start_instrument_thread_locked()
                try:
                    self._instrument_queue.put_nowait(request)
                except queue.Full:
                    queue_full = True
        if not accepted:
            self._resume_rejected_gated(pid, label, resume)
        elif queue_full:
            # Never leave it suspended: a gated app never resumed is killed by the
            # OS watchdog (0x8badf00d on iOS) and looks like a friTap crash.
            self.logger.warning(
                "Instrumentation queue full — %s pid %s not instrumented", label, pid
            )
            if resume:
                self._resume_off_event_thread(pid)

    def _resume_rejected_gated(self, pid, label, resume):
        """Resume a gated process that arrived while the capture is stopping."""
        self.logger.debug("Capture stopping — resuming %s pid %s uninstrumented",
                          label, pid)
        if resume:
            self._resume_off_event_thread(pid)

    def _resume_off_event_thread(self, pid) -> None:
        """Resume *pid* on the resumer thread (see ResumeWorker).

        A synchronous ``device.resume()`` on Frida's event loop deadlocks it (a fork
        child resumed inline from 'child-added' hung the target and every later
        Frida call). The pid stays tracked until the resume returns, so a racing
        teardown still resumes it (a second resume is harmless).
        """
        self._resumer.submit(pid)

    def _resume_and_untrack(self, pid) -> None:
        self._resume_quietly(pid)
        self._untrack_suspended(pid)

    def _start_instrument_thread(self):
        """Start the serial worker that instruments gated processes.

        Serial, because instrument() writes ``self.script`` or the child-agent
        collection. Separate from the message-consumer thread so a slow agent load
        cannot stall or deadlock message processing.
        """
        with self._instrument_thread_lock:
            self._start_instrument_thread_locked()

    def _start_instrument_thread_locked(self):
        """Caller holds the lock."""
        if self._instrument_thread is not None:
            return
        self._instrument_stop.clear()
        self._instrument_thread = threading.Thread(
            target=self._process_instrument_requests, daemon=True,
            name="fritap-instrument",
        )
        self._instrument_thread.start()

    def _process_instrument_requests(self):
        """Drain the instrumentation queue one process at a time."""
        while not self._instrument_stop.is_set():
            try:
                request = self._instrument_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._instrument_gated_process(request)
            except Exception:
                # One unusable child must not end gating for every later one.
                self.logger.exception(
                    "Failed to instrument %s pid %s", request.label, request.pid
                )

    def _instrument_gated_process(self, request):
        """Instrument one gated process, then resume it no matter what.

        The resume is in a ``finally`` because failing attach or load would otherwise
        strand the app suspended, which the platform reports as a watchdog kill.
        """
        try:
            self.logger.info("Attached to %s with pid %s", request.label, request.pid)
            session = self._backend.attach(self.device, str(request.pid))
            if request.watch_as_main is not None:
                self._watch_process(session, request.pid, request.watch_as_main)
            self.instrument(session, self.own_message_handler)
        except Exception as exc:
            if not request.exec_handover:
                raise
            self._on_failed_handover(request, exc)
        finally:
            if request.resume:
                self._resume_suspended(request.pid)

    def _track_suspended(self, pid) -> None:
        """Record *pid* as suspended by friTap (spawned or gated, not yet resumed)."""
        with self._suspended_pids_lock:
            self._suspended_pids.add(pid)

    def _untrack_suspended(self, pid) -> None:
        """Forget *pid* after it was resumed by a path outside this bookkeeping."""
        with self._suspended_pids_lock:
            self._suspended_pids.discard(pid)

    def _resume_suspended(self, pid) -> None:
        """Resume *pid* (logging, never raising) and stop tracking it."""
        self._untrack_suspended(pid)
        self._resume_quietly(pid)

    def _resume_suspended_pids(self) -> None:
        """Teardown: resume every pid friTap still holds suspended.

        Covers the spawned target when Ctrl+C / SIGTERM lands before its resume
        (agent load, -t/--timeout wait): the handler os._exit()s, and a Frida-spawned
        macOS process left at the dyld breakpoint dies with EXC_BREAKPOINT/SIGTRAP,
        reported as the target's crash. Also covers a gated process a busy worker
        has not resumed: ``_stop_instrument_thread`` waits only 5 s, and an attach
        plus script load can take longer (or never finish on Frida's callback
        thread). A second resume from the worker's ``finally`` is harmless.
        """
        with self._suspended_pids_lock:
            pids = sorted(self._suspended_pids)
            self._suspended_pids.clear()
        for pid in pids:
            if pid == self.pid and self.spawn and not self._death_before_capture:
                self.logger.warning(
                    "Capture stopped before the spawned pid %s was resumed — resuming "
                    "it uninstrumented so it is not left suspended.", pid)
            else:
                self.logger.debug("Resuming gated pid %s still suspended at teardown", pid)
            self._resume_quietly(pid)

    def _resume_quietly(self, pid):
        """Resume a gated process, logging rather than raising on failure."""
        try:
            self._backend.resume(self.device, pid)
        except Exception as exc:
            # The process may have died already; never mask the error this runs beside.
            self.logger.warning("Failed to resume pid %s: %s", pid, exc)

    def _drain_instrument_queue(self):
        """Resume every gated process still waiting for the stopped worker.

        The worker checks the stop event only at the top of its loop and each
        iteration costs an attach plus a script load, so queued requests outlive it.
        Each names a still-suspended process, and an unresumed gated process is
        killed by the OS watchdog (``0x8badf00d`` on iOS) and reported as the app's
        crash.

        This resumes instead of instrumenting, like ``_enqueue_instrumentation``'s
        teardown branch, since the session it would need is going away. Runs during
        cleanup, so it must never raise.
        """
        resumed = 0
        while True:
            try:
                request = self._instrument_queue.get_nowait()
            except queue.Empty:
                break
            if not request.resume:
                continue
            try:
                self._resume_suspended(request.pid)
                resumed += 1
            except Exception:
                # Belt and braces: teardown must never raise.
                self.logger.exception("Failed to drain a queued instrument request")
        if resumed:
            self.logger.debug(
                "Resumed %d gated process(es) still queued at teardown", resumed
            )

    def _stop_instrument_thread(self):
        """Signal the instrument worker to stop, wait for it, then drain.

        The drain follows the join because a live worker competes for the same
        queue; what it wins is instrumented and resumed by ``_instrument_gated_process``.
        """
        self._held_exec_watchdog.stop()  # finds no more images to hand to the worker
        with self._instrument_thread_lock:
            # Set under the lock so _enqueue_instrumentation's check sees either
            # "not stopping" (queues before the drain) or "stopping".
            self._instrument_stop.set()
            thread = self._instrument_thread
            self._instrument_thread = None
        if thread is not None:
            thread.join(timeout=5)
        self._drain_instrument_queue()
        self._resume_suspended_pids()

    def _should_instrument_spawn(self, identifier):
        """Whether a spawned process's identifier matches the target app."""
        if not identifier:
            return False

        # Mobile: the identifier is a package name, e.g. "com.example.app:service".
        if self.mobile:
            return identifier.startswith(self.target_app)

        # Desktop: the identifier may be a path or executable name.
        target_name = self.target_app.split()[-1] if ' ' in self.target_app else self.target_app
        if '/' in target_name:
            target_name = target_name.split('/')[-1]
        if '\\' in target_name:
            target_name = target_name.split('\\')[-1]

        return target_name.lower() in identifier.lower()

    def _is_main_target(self, process) -> bool:
        """Whether *process* is the main target, whose agent is ``self.script``.

        That is ``self.process``: the spawned or attached session or its exec'd image
        (``_watch_process`` moves it before instrumenting). Every other session is a
        child. Without a main session (the Wine process watcher) the first
        instrumented process is the main one.
        """
        main_session = getattr(self, "process", None)
        if main_session is not None:
            return process is main_session
        return getattr(self, "script", None) is None

    @property
    def _child_agents_lock(self) -> threading.Lock:
        """Guards ``_child_agents``; created lazily so ``__new__``-built test instances have one."""
        return self.__dict__.setdefault("_child_agents_lock_obj", threading.Lock())

    @property
    def _child_agents(self) -> "list[_ChildAgent]":
        """Child agents in load order (see _ChildAgent); mutate only under ``_child_agents_lock``."""
        return self.__dict__.setdefault("_child_agents_list", [])

    def _register_child_agent(self, session, script) -> None:
        child = _ChildAgent(pid=self._tracked_pid_of(session), session=session, script=script)
        with self._child_agents_lock:
            self._child_agents.append(child)

    def _tracked_pid_of(self, session) -> Optional[int]:
        """The tracker's pid for *session* (frida's Session has no ``pid``), else None."""
        tracker = getattr(self, "_tracker", None)
        for pid in tracker.pids() if tracker is not None else ():
            entry = tracker.get(pid)
            if entry is not None and entry.session is session:
                return pid
        return None
