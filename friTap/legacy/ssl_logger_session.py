"""Session lifecycle for :class:`SSL_Logger`: capture phases, detach classification,
exit status, the once-only session end, stop requests, probe runs and signals.

The host class owns the state.
"""

import os
import threading
from typing import Optional

from ..backends.base import ScriptRuntime
from ..backends.frida_remote_limits import (
    is_connection_closed,
    remote_message_limit_hint,
    server_version_from_params,
)
from ..events import DetachEvent
from ..exit_codes import EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_TARGET_DETACHED
from .profile_capture import capture_continues_after_main_detach


class SessionLifecycleMixin:
    """Capture phases, exit status and the end-of-session paths."""

    def on_detach(self, reason, crash=None):
        # The main session's agent can no longer report readiness: end a resume wait now.
        self._release_agent_ready_for_session(getattr(self, "process", None))
        if not self.running:
            return

        if reason == "application-requested":
            return

        # After exec() the new image arrives as an exec child (or is re-attached).
        if reason == "process-replaced" and self._on_process_replaced(self.pid):
            return

        # A hook crash or startup abort arrives as 'process-terminated'; report
        # it explicitly, falling back to the Crash stashed by on_process_crashed.
        if reason == "process-terminated":
            self._report_target_crash(reason, crash or self._pending_crash)
            self._pending_crash = None  # a stale Crash must not leak into a later detach

        if self._defer_end_to_children(reason):
            return

        phase = self._claim_detach_classification(reason)
        if phase == self._PHASE_RESUMING:
            # The resume needs Frida's event loop, which this callback occupies,
            # so never wait here; the resuming thread finishes this detach.
            return
        self._finish_detach(reason, captured=phase == self._PHASE_CAPTURING)

    # Profile capture (--profile/--discover/--also-package): the target's helper
    # processes outlive it, so its detach ends the capture only with the last one.
    _profile_capture_active = False

    def keep_capture_while_children_alive(self) -> None:
        """Let the main target's detach wait for every instrumented child/spawn to go."""
        self._profile_capture_active = True

    def _defer_end_to_children(self, reason) -> bool:
        """True when the main detach leaves the capture running for live children."""
        children = self.tracked_child_pids()
        if not capture_continues_after_main_detach(
                self._profile_capture_active, self.capture_started(), children):
            return False
        self._main_detach_reason = reason
        self.logger.warning(
            "Target pid %s detached (%s); the capture continues while %d profile "
            "process(es) run.", self.pid, reason, len(children))
        self._end_if_last_child_gone()  # a child may have gone meanwhile
        return True

    def _end_if_last_child_gone(self) -> None:
        """After a deferred main detach: end the session once no child is left (once only)."""
        if getattr(self, "_main_detach_reason", None) is None or self.tracked_child_pids():
            return
        reason = self.__dict__.pop("_main_detach_reason", None)  # atomic: one caller wins
        if reason is not None:
            self.logger.info("Last profile process detached; ending the capture.")
            self._finish_detach(reason, captured=True)

    def _finish_detach(self, reason, captured: bool) -> None:
        """Classify a detach (exit 1 before the capture, else 3) and end the session."""
        if not captured:
            self._report_death_before_capture(f"detached: {reason}")
        else:
            self._warn_remote_message_limit(reason)
        self._mark_unexpected_detach()
        self._event_bus.emit(DetachEvent(reason=reason))
        self._end_session(reason)

    # Capture phases separate a startup failure (exit 1) from a target lost
    # during capture (exit 3). Only begin_startup() enters the startup phase;
    # other paths (API, Wine watcher, tests) count as capturing.
    _PHASE_STARTUP = "startup"
    _PHASE_RESUMING = "resuming"
    _PHASE_CAPTURING = "capturing"
    _capture_phase = _PHASE_CAPTURING
    _death_before_capture = False

    @property
    def _capture_start_lock(self) -> threading.Lock:
        """Lock for the capture phase fields only; never held across a Frida call.

        Created lazily (atomic ``dict.setdefault``) so ``__new__`` test instances have one."""
        return self.__dict__.setdefault("_capture_start_lock_obj", threading.Lock())

    def begin_startup(self) -> None:
        """Enter the startup phase: spawn/attach, agent load, hook install."""
        with self._capture_start_lock:
            self._capture_phase = self._PHASE_STARTUP
            self._deferred_detach_reason = None

    def start_capture(self, start=None) -> None:
        """Run *start* (the spawned target's resume) and mark the capture as started.

        The resume runs outside the lock because it needs Frida's event loop. A
        detach arriving meanwhile is only recorded and classified here: exit 3
        if the resume succeeded, exit 1 if it raised.
        """
        with self._capture_start_lock:
            self._capture_phase = self._PHASE_RESUMING
        succeeded = False
        try:
            if start is not None:
                start()
            succeeded = True
        finally:
            with self._capture_start_lock:
                self._capture_phase = (
                    self._PHASE_CAPTURING if succeeded else self._PHASE_STARTUP)
                deferred_reason = getattr(self, "_deferred_detach_reason", None)
                self._deferred_detach_reason = None
            if deferred_reason is not None:
                self._finish_deferred_detach(deferred_reason, succeeded)

    def _claim_detach_classification(self, reason) -> str:
        """The phase a detach arrived in; during a resume, record *reason* for start_capture."""
        with self._capture_start_lock:
            if self._capture_phase == self._PHASE_RESUMING:
                self._deferred_detach_reason = reason
            return self._capture_phase

    def _finish_deferred_detach(self, reason, captured: bool) -> None:
        """Finish a detach recorded during the resume.

        The exit status is set synchronously so no teardown exits before it;
        the teardown runs on its own thread."""
        if not captured:
            self._report_death_before_capture(f"detached: {reason}")
        self._mark_unexpected_detach()
        threading.Thread(
            target=self._finish_detach, args=(reason, True),
            name="fritap-deferred-detach",
        ).start()

    def capture_started(self) -> bool:
        with self._capture_start_lock:
            return self._capture_phase == self._PHASE_CAPTURING

    # Remote frida-server 17.24.0-17.24.3 closes the link on messages > 128 KiB.

    def _is_remote_device(self) -> bool:
        """True for a remote (``-H`` / remote device id) frida-server session."""
        if getattr(self, "host", None):
            return True
        return getattr(getattr(self, "device", None), "type", None) == "remote"

    def note_remote_frida_server_version(self) -> None:
        """Record the remote frida-server's version while the link is up; never raises.

        frida 17.24 reports no version, so this usually stays None (neutral hint).
        """
        if not self._is_remote_device():
            return
        try:
            params = self.device.query_system_parameters()
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            self.logger.debug("Could not query the remote frida-server: %s", exc)
            return
        self._remote_frida_server_version = server_version_from_params(params)

    def remote_message_limit_hint_for(self, error) -> Optional[str]:
        """The frida-server 17.24.0-17.24.3 hint for *error*, or None.

        Only for a remote device whose connection closed, unless the server
        reported a version outside the affected range.
        """
        if not self._is_remote_device() or not is_connection_closed(error):
            return None
        try:
            import frida
            host_version = getattr(frida, "__version__", None)
        except Exception:  # noqa: BLE001
            host_version = None
        return remote_message_limit_hint(
            getattr(self, "_remote_frida_server_version", None), host_version)

    def _warn_remote_message_limit(self, error) -> None:
        """Log the remote frida-server message-limit hint once, if it applies."""
        if getattr(self, "_remote_limit_hint_reported", False):
            return
        hint = self.remote_message_limit_hint_for(error)
        if hint:
            self._remote_limit_hint_reported = True
            self.logger.warning(hint)

    def _report_death_before_capture(self, cause) -> None:
        """Report a target lost before the capture started: a startup failure (exit 1, not 3)."""
        if not self.set_exit_status(EXIT_RUNTIME_ERROR):
            return  # an earlier failure was already reported
        self._death_before_capture = True
        what = "spawned" if self.spawn else "attached"
        headline = getattr(self, "_termination_headline", None)
        if headline:
            cause = f"{cause}; {headline}"
        message = (
            f"The {what} target {self.target_app} (pid {self.pid}) went away before "
            f"the capture started ({cause}), while friTap was still preparing it "
            "(agent load, hook install or the -t/--timeout wait, before the resume). "
            "Nothing was captured.")
        hint = ("Usual causes: the app was killed or force-stopped by the system "
                "(Android kills an app that does not finish starting within ~10 s), "
                "it exited on its own, or it crashed while being instrumented.")
        remote_hint = self.remote_message_limit_hint_for(cause)
        if remote_hint:
            hint = f"{remote_hint} {hint}"
            self._remote_limit_hint_reported = True
        self.logger.error("%s %s", message, hint)
        try:
            from ..output.stdout_stream import note_runtime_error
            note_runtime_error("TargetDetachedBeforeCapture", message, hint)
        except Exception:  # noqa: BLE001 - reporting must not break the detach path
            pass

    def _mark_unexpected_detach(self) -> None:
        """Propose EXIT_TARGET_DETACHED when the target went away on its own.

        No-op once a teardown or stop signal is under way: that detach is expected."""
        if getattr(self, "_cleanup_done", False):
            return
        session_manager = getattr(self, "_session_manager", None)
        if getattr(session_manager, "_exit_signal_received", False):
            return
        self.set_exit_status(EXIT_TARGET_DETACHED)

    # Bound for a scanner-driven session end to reach the flushed state before
    # the main thread exits anyway. Generous: the final pcap/DSB/manifest pass
    # of a long capture is slow, and this only fires on a wedge.
    SESSION_END_WEDGE_TIMEOUT = 120.0

    # Guards the once-flag claim; class-level so ``__new__`` test instances have it.
    _SESSION_END_CLAIM_LOCK = threading.Lock()

    # Exit status for cleanup()'s os._exit; written only via set_exit_status().
    _exit_status = 0
    # Writers: main thread, signal handler, Frida's detach callback, --duration timer.
    _EXIT_STATUS_LOCK = threading.Lock()

    def set_exit_status(self, code: int) -> bool:
        """Propose the process exit status (see ``friTap/exit_codes.py``).

        The first non-zero status wins: detach (3), runtime error (1) or a
        non-SIGINT signal (128+signum). EXIT_OK (Ctrl+C, --duration) never
        overrides. Returns True when *code* became the exit status.
        """
        if code == EXIT_OK:
            return False
        with self._EXIT_STATUS_LOCK:
            if self._exit_status != EXIT_OK:
                return False
            self._exit_status = code
            return True

    def _claim_session_end(self) -> bool:
        """Atomically claim the end-of-session teardown; True for the first caller only."""
        with self._SESSION_END_CLAIM_LOCK:
            if getattr(self, "_session_end_claimed", False):
                return False
            self._session_end_claimed = True
            return True

    def _end_session(self, reason) -> bool:
        """The idempotent end-of-session teardown for a target that is gone.

        on_detach and the memory scanner may both fire on different threads;
        later callers get False. cleanup() writes the final pcap, DSB and
        manifest and sets ``_done_event`` before the wedge-prone frida detach.
        """
        if not self._claim_session_end():
            self.logger.debug(
                "session end (%s) already in progress; skipping", reason)
            return False
        # A gone target cannot answer graceful_detach, so the RPC is skipped.
        self._target_gone = True
        self._notify_session_detach()
        self.logger.info(f"Target process stopped: {reason}")
        self._log_session_end(reason)
        self.pcap_cleanup(self.full_capture,self.mobile,self.pcap_name)
        self.cleanup(self.live,self.socket_trace,self.full_capture,self.debug_output)
        return True

    def _end_session_bounded(self, reason) -> None:
        """Run :meth:`_end_session` on a worker bounded by ``SESSION_END_WEDGE_TIMEOUT``.

        If it wedges before flushing (a frida unload on the dead session), set
        ``_done_event`` anyway so the main thread exits with the raw capture.
        """
        worker = threading.Thread(
            target=self._end_session, args=(reason,),
            name="fritap-session-end", daemon=True,
        )
        worker.start()
        worker.join(self.SESSION_END_WEDGE_TIMEOUT)
        if worker.is_alive() and not self._done_event.is_set():
            self.logger.warning(
                "session teardown did not finish within %.0fs; exiting without "
                "the final capture pass", self.SESSION_END_WEDGE_TIMEOUT)
            self._done_event.set()

    def _notify_session_detach(self) -> None:
        """Tell the script plugins and the memory-scan engine the target is gone."""
        # One detach ScriptContext, shared by plugins and the memory-scan engine.
        detach_ctx = None
        if hasattr(self, '_plugin_loader') and self.process and self.device:
            detach_ctx = self._build_script_context(
                self.process, self.device,
                getattr(self, '_last_runtime', ScriptRuntime.QJS),
            )
            self._plugin_loader.detach_all(detach_ctx)

        if getattr(self, "_memory_scan_engine", None) is not None:
            try:
                if detach_ctx is None:
                    detach_ctx = self._build_script_context(
                        self.process, self.device,
                        getattr(self, '_last_runtime', ScriptRuntime.QJS),
                    )
                self._memory_scan_engine.stop(detach_ctx)
            except Exception:  # noqa: BLE001 - teardown must not break detach
                self.logger.debug("memory-scan: engine stop() failed", exc_info=True)

    def _on_memory_scan_ended(self) -> None:
        """Handle the memory-scan agent ending unexpectedly (scanner poll thread).

        In a memory-scan-only run this ends the run; with hooks too, only log it.
        """
        if not self._is_memory_scan_only():
            self.logger.warning(
                "memory-scan: heap scanner ended early; main capture continues")
            return
        self.logger.info(
            "memory-scan: scanner ended (target gone) — stopping capture")
        # The TUI worker loops on `running`; clearing it drives the normal teardown.
        if self._tui_mode:
            self.request_stop()
            return
        # CLI/API: the main thread waits on _done_event then os._exit()s, and a
        # force-stopped / ANR'd target sends no frida detach. Run on_detach's
        # once-guarded teardown so the pcap, DSB and manifest are written first;
        # bounded because frida unload on a dead session can wedge. No
        # request_stop() first: clearing `running` makes a concurrent on_detach
        # bail out instead of deferring to the shared guard.
        self._end_session_bounded("memory-scan-ended")

    def stop_capture_gracefully(self) -> bool:
        """Stop the capture like Ctrl+C (flush, detach, exit 0); safe from any thread.

        Returns False when a teardown is already running, so an earlier
        EXIT_TARGET_DETACHED is kept."""
        if getattr(self, "_cleanup_done", False) or getattr(self, "_session_end_claimed", False):
            return False
        self._session_manager.request_graceful_stop()
        return True

    def request_stop(self):
        """Signal the capture to stop. Non-blocking, safe to call from any thread."""
        self.running = False
        self._consumer_stop.set()
        self._instrument_stop.set()

    def finish_fritap(self):
        # Shutdown steps 1-3; idempotent, so a later cleanup() (TUI) skips them.
        self._shutdown_agent_and_drain()
        if self._proxy_redirector is not None:
            try:
                self._proxy_redirector.stop()
            except Exception:
                pass
            self._proxy_redirector = None
        self._session_manager.finish()

    # Class-level so ``__new__`` test instances have it.
    _fritap_session_stopped = False

    def stop_fritap_session(self) -> None:
        """Full idempotent teardown for an embedding caller (``FriTapSession.stop``); never exits.

        finish_fritap() alone closes no output. This runs the CLI order
        (full-capture stop, cleanup(exit_process=False)) and then finish_fritap()
        for host-only resources (payload-mod observer, proxy redirector,
        process-crashed handler, LSASS hook).
        """
        if self._fritap_session_stopped:
            return
        self._fritap_session_stopped = True
        try:
            self.pcap_cleanup(self.full_capture, self.mobile, self.pcap_name)
        except Exception as exc:  # noqa: BLE001 - cleanup() below must run regardless
            self.logger.error(f"Error stopping the full capture: {exc}")
        self.cleanup(self.live, self.socket_trace, self.full_capture,
                     self.debug_output, self.debug, exit_process=False)
        self.finish_fritap()
        # An opted-in API signal handler must not outlive the session.
        session_manager = getattr(self, "_session_manager", None)
        if session_manager is not None:
            session_manager.restore_signal_handlers()

    # Class-level default so bare ``SSL_Logger.__new__`` test instances have it.
    _embedded = False

    def set_embedded(self, embedded: bool = True) -> None:
        """Mark the session as hosted in a long-lived program (API, TUI).

        A target death still finalizes every output but skips ``os._exit``.
        """
        self._embedded = bool(embedded)

    def _owns_process_exit(self) -> bool:
        """True only for the CLI, which ends the process once the session ends."""
        return not (self._embedded or getattr(self, "_tui_mode", False))

    def _mark_session_stopped(self) -> None:
        """Tell ``running`` pollers and ``_done_event`` waiters the session is over."""
        self.running = False
        done_event = getattr(self, "_done_event", None)
        if done_event is not None:
            done_event.set()

    # Wait for the agent's platform report before declaring probe mode
    # unsupported. It is sent at agent load, so 3 s only covers consumer routing.
    PROBE_REPORT_TIMEOUT = 3.0
    # Non-zero exit used when the loaded bundle never acknowledged probe mode.
    PROBE_EXIT_BUNDLE_UNSUPPORTED = 2

    def wait_for_completion(self):
        """Block until the session ends. Responds to KeyboardInterrupt."""
        # A probe run installs no hooks, so nothing will arrive. It ends here
        # because this method already owns the final exit, and start_fritap_session()
        # has other callers (the LSASS helper) whose return contract must not change.
        if self.probe:
            self._finish_probe_run()
            return
        while not self._done_event.wait(timeout=0.5):
            pass
        # _done_event is set after the flush. On the on_detach path cleanup()
        # runs on a Frida callback thread that can wedge in the post-flush
        # detach of a destroyed script, never reaching its os._exit. The main
        # thread is awake and the data is flushed, so it owns the exit (CLI only).
        if self._owns_process_exit():
            self._let_running_teardown_finish()
            self._finish_json_stream()
            os._exit(self._exit_status)

    # How long the main thread lets a teardown running on another thread
    # (--duration timer, on_detach) finish after _done_event: the detach and
    # the post-detach crash check follow it. Bounded, as that detach can wedge.
    TEARDOWN_FINISH_GRACE_SECONDS = 10.0
    # Further wait, only while the post-detach crash check is still running:
    # its device enrichment (tombstone, logcat, minidumps) decides exit 3.
    CRASH_CHECK_GRACE_SECONDS = 30.0

    @property
    def _teardown_finished(self) -> threading.Event:
        """Set when a cleanup() that ran the teardown steps returns (see SSL_Logger.cleanup).

        Created lazily (atomic ``dict.setdefault``) so ``__new__`` test instances have one."""
        return self.__dict__.setdefault("_teardown_finished_event", threading.Event())

    def _let_running_teardown_finish(self) -> None:
        """Wait (bounded) for a teardown another thread is running.

        Without this the main thread exited right after _done_event, cutting
        off the detach and the check that the target survived it."""
        if not getattr(self, "_cleanup_done", False):
            return
        if self._teardown_finished.wait(self.TEARDOWN_FINISH_GRACE_SECONDS):
            return
        if getattr(self, "_post_detach_check_running", False) is True:
            self._teardown_finished.wait(self.CRASH_CHECK_GRACE_SECONDS)

    def _finish_probe_run(self) -> None:
        """Complete a --probe dry run: verdict, teardown, exit.

        Exits 0 if the agent acknowledged probe mode, else ``PROBE_EXIT_BUNDLE_UNSUPPORTED``.
        """
        acknowledged = (
            self.wait_for_platform_report(self.PROBE_REPORT_TIMEOUT)
            and self._platform_report is not None
            # The echoed `probe` flag tells a probe-aware bundle from an old one.
            and self._platform_report.probe
        )
        if acknowledged:
            # _on_platform_report already logged the platform summary.
            self.special_logger.info(
                "Probe complete — no hooks were installed and no data was captured."
            )
            exit_code = 0
        else:
            for line in self._probe_unsupported_bundle_lines():
                self.logger.error(line)
            exit_code = self.PROBE_EXIT_BUNDLE_UNSUPPORTED
        self._shutdown_after_probe(exit_code)

    def _probe_unsupported_bundle_lines(self) -> "list[str]":
        """Error lines for a bundle that never acknowledged --probe (logs nothing).

        A hard failure: an old bundle ignores ``probe`` and installs every hook,
        so a pass would mislead. The loaded bundle is named because a stale one
        is the likeliest cause.
        """
        try:
            bundle = self._resolve_agent_bundle_path()
        except Exception:
            bundle = getattr(self, "agent_script", "<unknown>")
        lines = [
            "--probe failed: the loaded agent bundle does not implement probe mode."
        ]
        if self._platform_report is None:
            lines.append("  The agent never sent a platform report.")
        else:
            lines.append(
                "  The agent reported platform '%s' but did not acknowledge probe "
                "mode, so it installed its hooks as usual."
                % (self._platform_report.platform or "unknown",)
            )
        lines.append(f"  Loaded bundle: {bundle}")
        lines.append(
            "  -> Rebuild the agent bundle with ./dev/compile_agent.sh, then re-run --probe."
        )
        lines.append(
            "  Treat this run as a NORMAL instrumented run: hooks may well have "
            "been installed, so it proves nothing about probe mode."
        )
        return lines

    def _shutdown_after_probe(self, exit_code: int) -> None:
        """Tear the probe session down and exit with *exit_code* (CLI only).

        Probe writes no outputs, so finish_fritap() is the whole teardown;
        guarded so a wedged detach cannot swallow the verdict.
        """
        try:
            self.request_stop()
            self.finish_fritap()
        except Exception as err:
            self.logger.debug("Probe teardown error (ignored): %s", err)
        self._done_event.set()
        if self._owns_process_exit():
            self.set_exit_status(exit_code)
            self._finish_json_stream()
            os._exit(exit_code)

    def install_signal_handler(self) -> bool:
        """Route SIGINT/SIGTERM to friTap's teardown (main thread only); True if installed.

        Embedded (API) sessions run :meth:`stop_fritap_session` instead of exiting.
        """
        return self._session_manager.install_signal_handler()
