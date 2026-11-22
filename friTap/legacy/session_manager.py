#!/usr/bin/env python3

"""SessionManager: capture session start/stop, signal handling and cleanup."""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING

from .._fs_util import is_non_empty_file
from ..backends.base import BackendName
from ..exit_codes import forced_exit_code
from ..pcap_utility import PCAP_FORMAT_PCAPNG
from ..spawn_target import resolve_spawn_target

if TYPE_CHECKING:
    from .ssl_logger_core import SSL_Logger


def full_capture_decryption_hint(pcap_file_name, pcap_container, keylog_name):
    """How the user decrypts the finished full capture, per output container.

    A pcapng output embeds the captured TLS keys in a Decryption Secrets Block,
    so Wireshark decrypts it as-is; a classic pcap holds only ciphertext and
    needs the keylog file. ``pcap_container`` is the resolved container.
    """
    if pcap_container == PCAP_FORMAT_PCAPNG:
        return (f"the full capture {pcap_file_name} keeps TLS traffic encrypted but embeds "
                "the captured keys (pcapng DSB), so Wireshark decrypts it directly.")
    if keylog_name:
        return (f"the full capture {pcap_file_name} contains only encrypted TLS traffic; "
                f"to decrypt it in Wireshark, load the keylog file {keylog_name}.")
    return (f"the full capture {pcap_file_name} contains only encrypted TLS traffic and no "
            "keylog file was written; use -k <keylog> or a .pcapng output to keep the keys.")


class SessionManager:
    """Manages the lifecycle of a friTap capture session."""

    # Android's ActivityManager kills a spawned app that has not attached within
    # its process-start timeout (10 s, scaled by ro.hw_timeout_multiplier;
    # logcat "Killing <pid>: start timeout"). On a busy device Frida's attach
    # alone can exceed it and fail with ProcessNotFoundError although the spawn
    # worked. A fresh spawn usually succeeds, so remote spawn+attach gets one retry.
    SPAWN_ATTACH_ATTEMPTS = 2

    # ScriptErrorHandler ends the run with SIGTERM on an agent error: same
    # graceful teardown as Ctrl+C, but a failure exit status.
    TERMINATION_SIGNALS = ("SIGINT", "SIGTERM")
    # How long a signal waits for a teardown another thread owns before forcing the exit.
    TEARDOWN_WAIT_SECONDS = 60.0
    # A 2nd signal during teardown only warns; a 3rd one, or this long after the
    # 2nd, forces the exit. Users press Ctrl+C twice, and GNU timeout signals
    # both the child and its process group.
    FORCE_EXIT_AFTER_SECONDS = 60.0
    # While the device-capture pull still progresses, the timer waits this long
    # again instead of forcing (the pull has its own timeout, up to 600 s).
    PULL_PROGRESS_RECHECK_SECONDS = 15.0
    # Bound of the must-do steps of a forced exit (kill device tcpdump, close outputs).
    FORCE_EXIT_STEPS_SECONDS = 10.0

    def __init__(self, logger_instance: "SSL_Logger") -> None:
        self._logger_instance = logger_instance
        self._logger = logging.getLogger("friTap.session")
        self._pcap_cleanup_lock = threading.RLock()
        self._pcap_cleanup_done = False
        self._exit_signal_received = False
        # Signals received after the first one (see _on_repeated_termination_signal).
        self._repeated_signal_count = 0
        self._force_exit_lock = threading.Lock()
        # Pull bytes at the last force-exit timer check (None: not checked yet).
        self._last_pull_progress = None
        self._last_pull_progress_reading = None  # the latest check's reading
        self._waited_for_pull = False  # the timer was suspended for a pull
        # Handlers install_signal_handler() replaced, for restore_signal_handlers().
        self._prior_signal_handlers: dict = {}

    @property
    def _l(self) -> "SSL_Logger":
        """Shorthand access to the SSL_Logger instance."""
        return self._logger_instance

    def _spawn_and_attach_remote(self, logger) -> int:
        """Spawn ``logger.target_app`` remotely and attach; sets ``logger.pid``/``process``, returns the pid.

        Respawns when the process vanished before the attach (``SPAWN_ATTACH_ATTEMPTS``).
        """
        from ..backends import BackendProcessNotFoundError

        for attempt in range(1, self.SPAWN_ATTACH_ATTEMPTS + 1):
            pid = logger._backend.spawn_raw(logger.device, logger.target_app)
            logger.pid = pid
            try:
                logger.process = logger._backend.attach(logger.device, str(pid))
                return pid
            except BackendProcessNotFoundError:
                # The pid is gone: nothing left to resume on the failure path.
                logger.pid = None
                if attempt == self.SPAWN_ATTACH_ATTEMPTS:
                    self._log_spawned_process_vanished(pid, final=True)
                    raise
                self._log_spawned_process_vanished(pid, final=False)

    def _register_child_handler(self, logger) -> None:
        """Listen for gated children (--enable_child_gating and exec'd images, see follow_exec_of).

        Without child events only an explicit --enable_child_gating fails."""
        if not logger.gates_children:
            return
        try:
            logger._backend.on_child_added(logger.device, logger.on_child_added)
        except NotImplementedError:
            if logger.enable_child_gating:
                raise
            self._logger.debug("%s backend has no child events; exec() will "
                               "not be followed", logger._backend.name)

    def _log_spawned_process_vanished(self, pid, final: bool) -> None:
        cause = (
            f"spawned process {pid} was gone before friTap could attach to it. On "
            "Android the system kills an app that has not finished starting within "
            "~10 s, which a slow attach on a busy device or emulator can exceed")
        if not final:
            self._logger.warning("The %s; spawning it again.", cause)
            return
        self._logger.error(
            "The %s (%d attempts). Retry when the device is less busy, or start the "
            "app first and attach to it without -s.", cause, self.SPAWN_ATTACH_ATTEMPTS)

    def _get_device_or_abort(self, logger, wanted_id, **lookup):
        """``backend.get_device(**lookup)``, or a startup abort (see :meth:`_abort_startup`)."""
        from ..backends import BackendInvalidArgumentError, BackendNotRunningError

        backend_name = logger._backend.name
        try:
            return logger._backend.get_device(**lookup)
        except BackendNotRunningError as e:
            self._abort_startup(
                logger, e,
                f"{backend_name} backend: server is not running. Please ensure it "
                "is started on the device.")
        except BackendInvalidArgumentError as e:
            if "device not found" in str(e).lower():
                what = f"Device with ID '{wanted_id}' not found." if wanted_id \
                    else "No mobile device found."
                self._abort_startup(
                    logger, e, what,
                    hint="Pass the device ID with -m <device-id> "
                         "(see `adb devices` or `fritap devices`).")
            self._abort_startup(logger, e, f"Backend error ({backend_name}): {e}")
        except Exception as e:  # noqa: BLE001 - reported, then exit 1
            self._abort_startup(
                logger, e, f"Unexpected error while attaching to the device: {e}")

    def _abort_startup(self, logger, error, message, hint=None):
        """Log *message*, note it as the run's cause, and exit 1.

        The first noted cause fills the ``-j -`` stream's closing ``error`` record,
        so consumers get the specific reason instead of "see stderr".
        """
        from ..exit_codes import EXIT_RUNTIME_ERROR
        from ..output.stdout_stream import note_runtime_error

        self._logger.error(message)
        error_type = type(getattr(error, "original_exception", None) or error).__name__
        note_runtime_error(error_type, message, hint)
        logger.set_exit_status(EXIT_RUNTIME_ERROR)
        sys.exit(EXIT_RUNTIME_ERROR)

    def _resolve_attached_process_name(self, logger) -> None:
        """After a numeric-PID attach, look up the process name once for the flow collectors.

        Name targets make no device call. A failed lookup never breaks the attach.
        """
        target = str(logger.target_app or "")
        if not target.isnumeric():
            return
        try:
            name = logger._backend.process_name(logger.device, int(target))
            if name:
                self._logger.debug("Resolved pid %s to process %s", target, name)
                logger.apply_resolved_process_name(name)
        except Exception as exc:  # noqa: BLE001 - must never break the attach
            self._logger.debug("Could not resolve process name for pid %s: %s",
                               target, exc)

    def start_session(self, own_message_handler=None):
        """Start a capture session; returns ``(process, script)``."""
        logger = self._l
        logger.begin_startup()

        if logger.device_id:
            logger.device = self._get_device_or_abort(logger, logger.device_id,
                                                      device_id=logger.device_id)
            self._logger.info("Successfully attached to device (ID: %s).", logger.device_id)
        elif logger.mobile:
            if logger.mobile is True:
                logger.device = self._get_device_or_abort(logger, None, mobile=True)
            else:
                logger.device = self._get_device_or_abort(logger, logger.mobile,
                                                          mobile=logger.mobile)
            self._logger.info("Successfully attached to the mobile device.")
        elif logger.host:
            logger.device = logger._backend.get_device(host=logger.host)
        else:
            logger.device = logger._backend.get_device()
        # Remote only: the frida-server version feeds the 17.24.0-17.24.3
        # "> 128 KiB message closes the link" hint.
        logger.note_remote_frida_server_version()

        self._register_child_handler(logger)
        if logger.enable_spawn_gating or logger.spawn_gating_all:
            logger._backend.enable_spawn_gating(logger.device)
            logger._backend.on_spawn_added(logger.device, logger.on_spawn_added)
        if logger.spawn:
            self._logger.info(f"spawning {logger.target_app}")
            # device_id counts as remote too: otherwise resolve_spawn_target would
            # probe the host's filesystem for a target that only exists on the device.
            if logger.mobile or logger.host or logger.device_id:
                pid = self._spawn_and_attach_remote(logger)
                logger._track_suspended(pid)
            else:
                used_env = {}
                if logger.environment_file:
                    with open(logger.environment_file) as json_env_file:
                        used_env = json.load(json_env_file)
                # A single argv token with whitespace is either one executable path
                # with spaces or a collapsed command line. resolve_spawn_target
                # decides by a local filesystem probe, valid only for a local device.
                spawn_target = resolve_spawn_target(
                    logger.target_argv, logger.target_app, self._logger
                )
                pid = logger._backend.spawn_raw(logger.device, spawn_target, env=used_env)
                # Record the pid before the settle sleep: a Ctrl+C in any pre-resume
                # wait must find it (see SSL_Logger._resume_suspended_pids).
                logger.pid = pid
                logger._track_suspended(pid)
                time.sleep(1)
                logger.process = logger._backend.attach(logger.device, str(pid))
        else:
            logger.process = logger._backend.attach(logger.device, logger.target_app)
            # 'process-crashed' is device-wide and on_process_crashed filters by pid;
            # without logger.pid an unrelated app's crash would be reported as ours.
            logger.pid = getattr(logger.process, "pid", None)
            self._resolve_attached_process_name(logger)
            if logger.timeout:
                logger.target_threads = logger._backend.enumerate_threads(logger.process)
                if logger.target_threads:
                    try:
                        main_thread = next(t for t in logger.target_threads if t.entrypoint is not None)
                    except StopIteration:
                        main_thread = logger.target_threads[0]
                    self._logger.info(f"Suspending main thread {main_thread.id} for {logger.timeout} seconds...")
                    logger._backend.suspend_thread(logger.process, main_thread.id)

        # Watch the session before the agent loads: frida does not replay a
        # 'detached' from before the handler connected, so a target killed during
        # the load (e.g. Android force-stop) would hang friTap forever.
        # on_detach classifies such a death as a startup failure (exit 1).
        logger._backend.on_detached(logger.process, logger.on_detach)

        logger.follow_exec_of(logger.process)

        if logger._config.backend != BackendName.FRIDA and logger._agent_script_path is not None:
            self._logger.info(
                "Loading %s agent script: %s",
                logger._config.backend, logger._agent_script_path,
            )
            with open(logger._agent_script_path, 'r') as f:
                script_source = f.read()
            script = logger._backend.create_script(logger.process, script_source)
            logger.script = script  # reply target for a handshake arriving during load
            logger._backend.on_message(script, logger._internal_callback_wrapper(script))
            logger._load_script_bounded(script)
            logger.script = script
        else:
            script = logger.instrument(logger.process, own_message_handler)
        if not logger.spawn:
            # Attach mode: the hooks are in, the capture has started.
            logger.start_capture()

        from ..events import SessionEvent
        logger._event_bus.emit(SessionEvent(
            event_type="started",
            session_id=str(id(logger.process)),
        ))

        if logger.pcap_name and logger.full_capture:
            self._logger.info(f'Logging pcap to {logger.pcap_name}')
        if logger.pcap_name and not logger.full_capture:
            self._logger.info(f'Logging TLS plaintext as pcap to {logger.pcap_name}')
        if logger.keylog:
            self._logger.info(f'Logging keylog file to {logger.keylog}')

        # Native crash report (frida's Crash carries the backtrace). Needed in attach
        # mode too: a hook can kill an attached target, and on_detach would get no
        # Crash object. Registered after logger.pid is set so the pid filter works.
        try:
            logger._backend.on_process_crashed(logger.device, logger.on_process_crashed)
        except Exception:
            self._logger.debug("on_process_crashed registration failed", exc_info=True)
        if logger.timeout:
            self._logger.info(f"Waiting {logger.timeout} seconds before resuming...")
            time.sleep(logger.timeout)
            self._logger.info("Timeout reached. Resuming execution...")

        if logger.spawn:
            # A target lost before or by this resume is a startup failure (exit 1),
            # after it a detach (exit 3).
            logger.start_capture(lambda: logger._backend.resume(logger.device, pid))
            logger._untrack_suspended(pid)
        else:
            if logger.timeout and logger.target_threads:
                logger._backend.resume_thread(logger.process, main_thread.id)

        return logger.process, script

    def finish(self):
        """Stop the session and clean up resources."""
        logger = self._l
        logger._stop_payload_mod_watcher()

        if logger.script:
            logger._backend.unload_script(logger.script)
            # Our own unload, not a dead target: detach_with_timeout must still
            # detach the main session (the TUI unloads first).
            logger._main_script_unloaded = True
        # Child agents go after the main one; no-op if detach_with_timeout released them.
        logger._release_child_agents()

        try:
            # Also removed in attach mode, or the callback outlives the session.
            if logger.device is not None:
                logger._backend.off_process_crashed(logger.device, logger.on_process_crashed)
        except Exception:
            pass

        if hasattr(logger, 'install_lsass_hook') and logger.install_lsass_hook:
            try:
                from ..friTap import cleanup_lsass_hook
                cleanup_lsass_hook()
            except ImportError:
                pass

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        """Stop the full capture and stage its temp file for the finalize step.

        Idempotent: signals, target death, script errors and normal exit all call
        this. The work runs once; a concurrent caller waits for it, because the
        finalize step must not read a half-pulled capture. ``pcap_name`` is unused.
        """
        logger = self._l
        if not is_full_capture or logger.pcap_obj is None:
            return
        with self._pcap_cleanup_lock:
            if self._pcap_cleanup_done:
                return
            self._pcap_cleanup_done = True
            temp_path = self._stop_full_capture(logger.pcap_obj, is_mobile)
        self._log_full_capture_staged(temp_path, is_mobile)

    @staticmethod
    def _stop_full_capture(pcap_obj, is_mobile):
        """Stop the capture source; return the temp capture path (None if nothing)."""
        thread = pcap_obj.full_capture_thread
        thread.join(2.0)
        if is_mobile:
            # Pulls the pcap to where PCAP._temp_pcap_path expects it.
            return pcap_obj.stop_device_capture()
        if thread.is_alive() and getattr(thread, "socket", None) is not None:
            thread.socket.close()
        return pcap_obj._temp_pcap_path()

    def _log_full_capture_staged(self, temp_path, is_mobile):
        capture_type = "mobile" if is_mobile else "local"
        if not temp_path or not os.path.exists(temp_path):
            self._logger.info(f"full {capture_type} capture: no capture data was recorded.")
            return
        # Only the staging copy exists; the finalize step logs the user-facing
        # "Full capture written to" line.
        self._logger.debug(f"full {capture_type} capture staged at {temp_path}")
        pcap_obj = self._l.pcap_obj
        self._logger.info(full_capture_decryption_hint(
            pcap_obj.pcap_file_name,
            pcap_obj.pcap_container,
            self._written_keylog_name(pcap_obj),
        ))

    def _written_keylog_name(self, pcap_obj):
        """The keylog the user can load, or ``None``.

        Same rule as ``PCAP.written_keylog_path``. The keylog handler opens its file
        lazily, so the setup-time ``keylog_file`` handle is only a last resort.
        """
        resolve_written = getattr(pcap_obj, "written_keylog_path", None)
        written_path = resolve_written() if callable(resolve_written) else None
        if written_path:
            return written_path
        live_path = self._live_keylog_path()
        if is_non_empty_file(live_path):
            return live_path
        return getattr(getattr(self._l, "keylog_file", None), "name", None)

    def _live_keylog_path(self):
        resolve = getattr(self._l, "_live_keylog_path", None)
        if callable(resolve):
            return resolve()
        return getattr(self._l, "keylog", None)

    def install_signal_handler(self) -> bool:
        """Route Ctrl+C (SIGINT) and SIGTERM to the graceful teardown.

        ``signal.signal`` only works on the main thread: elsewhere this installs
        nothing and returns False instead of raising ValueError.
        """
        if threading.current_thread() is not threading.main_thread():
            self._logger.debug(
                "signal handlers not installed: not on the main thread")
            return False
        for name in self.TERMINATION_SIGNALS:
            signum = getattr(signal, name, None)
            if signum is not None:
                previous = signal.signal(signum, self._on_termination_signal)
                self.__dict__.setdefault("_prior_signal_handlers", {}).setdefault(
                    signum, previous)
        return True

    def restore_signal_handlers(self) -> None:
        """Restore the handlers install_signal_handler() replaced, where ours is still installed.

        Main thread only; otherwise a no-op."""
        if not getattr(self, "_prior_signal_handlers", None):
            return
        if threading.current_thread() is not threading.main_thread():
            return
        for signum, previous in list(self._prior_signal_handlers.items()):
            try:
                if signal.getsignal(signum) == self._on_termination_signal:
                    signal.signal(signum, previous if previous is not None else signal.SIG_DFL)
            except (ValueError, OSError, TypeError):
                self._logger.debug("restoring the handler of signal %s failed",
                                   signum, exc_info=True)
        self._prior_signal_handlers.clear()

    def request_graceful_stop(self):
        """Run the Ctrl+C teardown programmatically (exit status 0), e.g. for ``--duration``."""
        self._on_termination_signal(signal.SIGINT, None)

    def _is_embedded_api_session(self) -> bool:
        """An API-embedded session: the host owns the process, so a stop must never exit it."""
        logger = self._l
        # Identity checks: a mock attribute must never leave the CLI path.
        return (getattr(logger, "_embedded", False) is True
                and getattr(logger, "_tui_mode", False) is not True)

    def _on_embedded_termination_signal(self, signum) -> None:
        """Embedded stop: the API's teardown, never an exit. Idempotent."""
        if self._exit_signal_received:
            self._logger.debug("signal %s: embedded stop already in progress", signum)
            return
        self._exit_signal_received = True
        self._logger.info(self._termination_message(signum))
        self._l.stop_fritap_session()

    def _on_termination_signal(self, signum, frame):
        logger = self._l
        if self._is_embedded_api_session():
            self._on_embedded_termination_signal(signum)
            return
        exit_status = 0 if signum == signal.SIGINT else 128 + int(signum)
        if self._exit_signal_received:
            self._on_repeated_termination_signal(signum)
            return
        self._exit_signal_received = True
        logger.set_exit_status(exit_status)  # first non-zero status wins
        self._logger.info(self._termination_message(signum))
        if hasattr(logger, 'install_lsass_hook') and logger.install_lsass_hook:
            try:
                from ..friTap import cleanup_lsass_hook
                cleanup_lsass_hook()
            except ImportError:
                pass
        try:
            self.pcap_cleanup(logger.full_capture, logger.mobile, logger.pcap_name)
        except Exception as exc:  # cleanup() below must run regardless
            self._logger.error(f"Error stopping the full capture: {exc}")
        logger.cleanup(logger.live, logger.socket_trace, logger.full_capture, logger.debug_output, logger.debug)

        # Safety net: cleanup() normally ends in os._exit itself. Reaching here means
        # it returned early via _cleanup_done because another thread (e.g. on_detach)
        # is mid-teardown. Wait a bounded time for it to flush (it sets _done_event),
        # then force the exit. os._exit, not sys.exit: the Frida session is half
        # torn down and a non-daemon Frida thread would block interpreter shutdown.
        done_event = getattr(logger, "_done_event", None)
        if done_event is not None:
            done_event.wait(self.TEARDOWN_WAIT_SECONDS)
        self._exit_now(exit_status)

    def _on_repeated_termination_signal(self, signum):
        """A signal during teardown: the 2nd lets it finish, the 3rd forces the exit.

        Runs nested in the main thread's teardown; returning resumes it, so the
        capture pull, manifest and keylog flush still happen.
        """
        self._repeated_signal_count = getattr(self, "_repeated_signal_count", 0) + 1
        forced_status = forced_exit_code(signum)
        if self._repeated_signal_count == 1:
            # A status notice: INFO ("[*]"); WARNING would print the error prefix.
            self._logger.info(
                "Teardown in progress (stopping the capture, writing the outputs). "
                "Press Ctrl+C again to force quit.")
            self._start_force_exit_timer(forced_status)
            return
        self._force_exit(forced_status, "forced by the user")

    def _start_force_exit_timer(self, exit_status, delay=None):
        """Force the exit if the teardown is still running FORCE_EXIT_AFTER_SECONDS from now."""
        timer = threading.Timer(
            self.FORCE_EXIT_AFTER_SECONDS if delay is None else delay,
            self._on_force_exit_timer, args=(exit_status,))
        timer.daemon = True  # the normal teardown ends in os._exit anyway
        timer.start()

    def _on_force_exit_timer(self, exit_status):
        """Force the exit, unless the device-capture pull is still making progress.

        The pull's time does not count: once a pull the timer waited for has
        ended, the rest of the teardown (finalize, detach) gets a fresh budget, once."""
        if self._device_pull_progressing():
            self._waited_for_pull = True
            self._logger.info(
                "Still pulling the full capture from the device "
                f"({self._last_pull_progress} bytes so far); waiting for it. "
                "Press Ctrl+C again to force quit.")
            self._start_force_exit_timer(exit_status, self.PULL_PROGRESS_RECHECK_SECONDS)
            return
        pull_ended = self._last_pull_progress_reading is None
        if pull_ended and getattr(self, "_waited_for_pull", False):
            self._waited_for_pull = False  # only once
            self._start_force_exit_timer(exit_status)
            return
        self._force_exit(
            exit_status, f"teardown still running after {self.FORCE_EXIT_AFTER_SECONDS:.0f} s")

    def _device_pull_progressing(self):
        """True while a pull runs and its local file grew since the last check.

        The first check only needs a running pull: it may not have written yet."""
        progress = getattr(getattr(self._l, "pcap_obj", None), "device_pull_progress", None)
        current = progress() if callable(progress) else None
        if not isinstance(current, int):
            current = None
        # None: no pull runs (never started, or ended).
        self._last_pull_progress_reading = current
        if current is None:
            return False
        previous = getattr(self, "_last_pull_progress", None)
        self._last_pull_progress = current
        return previous is None or current > previous

    def _final_exit_status(self, forced_status):
        """First non-zero wins: an earlier recorded status (e.g. 3) beats the forced code."""
        recorded = getattr(self._l, "_exit_status", 0)
        if isinstance(recorded, int) and not isinstance(recorded, bool) and recorded != 0:
            return recorded
        return forced_status

    def _force_exit(self, exit_status, reason):
        """Exit now, after the bounded must-do steps; a further signal meanwhile exits at once."""
        exit_status = self._final_exit_status(exit_status)
        lock = self.__dict__.setdefault("_force_exit_lock", threading.Lock())
        if not lock.acquire(blocking=False):
            os._exit(exit_status)
        self._logger.warning(f"Forcing exit ({reason}); the outputs may be incomplete.")
        worker = threading.Thread(target=self._force_exit_steps, daemon=True,
                                  name="fritap-force-exit")
        worker.start()
        worker.join(self.FORCE_EXIT_STEPS_SECONDS)
        os._exit(exit_status)

    def _force_exit_steps(self):
        """Best effort, local steps first: stop the pull and log how to recover the device
        capture, flush the outputs, then no orphaned device tcpdump, AppTap session or
        adb child (os._exit skips atexit, and adb children ignore the terminal's Ctrl+C)."""
        logger = self._l
        pcap_obj = getattr(logger, "pcap_obj", None)
        steps = (
            getattr(pcap_obj, "abort_device_capture_pull", None),
            getattr(logger, "_close_output_handlers_safely", None),
            getattr(pcap_obj, "kill_device_capture", None),
            getattr(pcap_obj, "abort_owner_capture", None),
            getattr(pcap_obj, "kill_adb_children", None),
        )
        for step in steps:
            if not callable(step):
                continue
            try:
                step()
            except Exception:  # noqa: BLE001 - the exit must happen regardless
                self._logger.debug("forced-exit step failed", exc_info=True)

    def _exit_now(self, exit_status):
        """Force the process exit; '-j -' still gets its closing records."""
        finish = getattr(self._l, "_finish_json_stream", None)
        if finish is not None:
            finish()
        os._exit(exit_status)

    @staticmethod
    def _termination_message(signum):
        if signum == signal.SIGINT:
            return "Ctrl+C detected. Cleaning up..."
        return f"{signal.Signals(signum).name} received. Cleaning up..."
