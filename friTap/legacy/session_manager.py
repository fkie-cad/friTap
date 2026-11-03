#!/usr/bin/env python3

"""
Session lifecycle management for friTap.

SessionManager handles the session start/stop lifecycle,
signal handling, and cleanup.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING

from ..backends.base import BackendName
from ..spawn_target import resolve_spawn_target

if TYPE_CHECKING:
    from .ssl_logger_core import SSL_Logger


class SessionManager:
    """Manages the lifecycle of a friTap capture session."""

    # A spawned app stays suspended until friTap resumes it after attaching
    # and loading the agent. Android's ActivityManager kills an app process
    # that has not attached to it within its process-start timeout (10 s,
    # scaled by ro.hw_timeout_multiplier; logcat: "failed to attach" ...
    # "Killing <pid>: start timeout"). On a busy device or emulator Frida's
    # attach alone can exceed that window, and the attach then fails with
    # ProcessNotFoundError although the spawn itself worked. A fresh spawn
    # usually succeeds, so the remote spawn+attach gets one retry.
    SPAWN_ATTACH_ATTEMPTS = 2

    # SIGTERM is how ScriptErrorHandler ends the run on an agent error; it gets
    # the same graceful teardown as Ctrl+C, but keeps a failure exit status.
    TERMINATION_SIGNALS = ("SIGINT", "SIGTERM")
    # How long a signal waits for a teardown another thread already owns
    # (e.g. the target just died) before forcing the exit anyway.
    TEARDOWN_WAIT_SECONDS = 60.0

    def __init__(self, logger_instance: "SSL_Logger") -> None:
        self._logger_instance = logger_instance
        self._logger = logging.getLogger("friTap.session")
        self._pcap_cleanup_lock = threading.RLock()
        self._pcap_cleanup_done = False
        self._exit_signal_received = False

    @property
    def _l(self) -> "SSL_Logger":
        """Shorthand access to the SSL_Logger instance."""
        return self._logger_instance

    def _spawn_and_attach_remote(self, logger) -> int:
        """Spawn ``logger.target_app`` on the remote device and attach to it.

        Sets ``logger.pid`` / ``logger.process`` and returns the pid. Retries
        the whole spawn when the spawned process vanished before the attach
        completed (see ``SPAWN_ATTACH_ATTEMPTS``).
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

    def start_session(self, own_message_handler=None):
        """Start a friTap capture session. Delegates to SSL_Logger internals."""
        from ..backends import BackendInvalidArgumentError, BackendNotRunningError

        logger = self._l

        if logger.device_id:
            try:
                logger.device = logger._backend.get_device(device_id=logger.device_id)
                self._logger.info("Successfully attached to device (ID: %s).", logger.device_id)
            except BackendNotRunningError:
                self._logger.error("%s backend: server is not running. Please ensure it is started on the device.", logger._backend.name)
                sys.exit(1)
            except BackendInvalidArgumentError as e:
                if 'device not found' in e.args:
                    self._logger.error("Device with ID '%s' not found.", logger.device_id)
                else:
                    self._logger.error("Backend error (%s): %s", logger._backend.name, e)
                sys.exit(1)
            except Exception as e:
                self._logger.error("Unexpected error while attaching to the device: %s", e)
                sys.exit(1)
        elif logger.mobile:
            try:
                if logger.mobile is True:
                    logger.device = logger._backend.get_device(mobile=True)
                else:
                    logger.device = logger._backend.get_device(mobile=logger.mobile)
                self._logger.info("Successfully attached to the mobile device.")
            except BackendNotRunningError:
                self._logger.error("%s backend: server is not running. Please ensure it is started on the device.", logger._backend.name)
                sys.exit(1)
            except BackendInvalidArgumentError as e:
                if 'device not found' in e.args:
                    self._logger.error("Device with ID '%s' not found.", logger.mobile)
                else:
                    self._logger.error("Backend error (%s): %s", logger._backend.name, e)
                sys.exit(1)
            except Exception as e:
                self._logger.error("Unexpected error while attaching to the device: %s", e)
                sys.exit(1)
        elif logger.host:
            logger.device = logger._backend.get_device(host=logger.host)
        else:
            logger.device = logger._backend.get_device()

        if logger.enable_child_gating:
            logger._backend.on_child_added(logger.device, logger.on_child_added)
        if logger.enable_spawn_gating or logger.spawn_gating_all:
            logger._backend.enable_spawn_gating(logger.device)
            logger._backend.on_spawn_added(logger.device, logger.on_spawn_added)
        if logger.spawn:
            self._logger.info(f"spawning {logger.target_app}")
            # device_id belongs here too: a session picked by device ID (TUI
            # device enumeration, see above) is a REMOTE device, and the local
            # filesystem probe in resolve_spawn_target would otherwise test the
            # host's paths for a target that only exists on that device.
            if logger.mobile or logger.host or logger.device_id:
                pid = self._spawn_and_attach_remote(logger)
            else:
                used_env = {}
                if logger.environment_file:
                    with open(logger.environment_file) as json_env_file:
                        used_env = json.load(json_env_file)
                # A single argv token containing whitespace is ambiguous: it is
                # either one executable whose path has spaces or a command with
                # arguments that the shell collapsed. resolve_spawn_target picks
                # via a local filesystem probe and logs which reading it chose
                # -- valid only here, where the device is genuinely local
                # (mobile, host and device_id all take the branch above).
                # spawn_raw passes the list straight to device.spawn().
                spawn_target = resolve_spawn_target(
                    logger.target_argv, logger.target_app, self._logger
                )
                pid = logger._backend.spawn_raw(logger.device, spawn_target, env=used_env)
                time.sleep(1)
                logger.pid = pid
                logger.process = logger._backend.attach(logger.device, str(pid))
        else:
            logger.process = logger._backend.attach(logger.device, logger.target_app)
            # Record the attached pid: 'process-crashed' is a device-WIDE signal
            # and on_process_crashed only filters it by comparing pids, so
            # without logger.pid the filter degrades to accept-anything and an
            # unrelated app's crash would be reported as our target's.
            logger.pid = getattr(logger.process, "pid", None)
            if logger.timeout:
                logger.target_threads = logger._backend.enumerate_threads(logger.process)
                if logger.target_threads:
                    try:
                        main_thread = next(t for t in logger.target_threads if t.entrypoint is not None)
                    except StopIteration:
                        main_thread = logger.target_threads[0]
                    self._logger.info(f"Suspending main thread {main_thread.id} for {logger.timeout} seconds...")
                    logger._backend.suspend_thread(logger.process, main_thread.id)

        if logger.enable_child_gating:
            logger._backend.enable_child_gating(logger.process)

        if logger._config.backend != BackendName.FRIDA and logger._agent_script_path is not None:
            # Non-Frida backend: load backend-specific hook script
            self._logger.info(
                "Loading %s agent script: %s",
                logger._config.backend, logger._agent_script_path,
            )
            with open(logger._agent_script_path, 'r') as f:
                script_source = f.read()
            script = logger._backend.create_script(logger.process, script_source)
            logger.script = script  # so a handshake arriving during load has a reply target
            logger._backend.on_message(script, logger._internal_callback_wrapper(script))
            logger._load_script_bounded(script)
            logger.script = script
        else:
            script = logger.instrument(logger.process, own_message_handler)

        # Emit session started event
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

        logger._backend.on_detached(logger.process, logger.on_detach)
        # Capture a full native crash report for a target that dies while
        # instrumented (frida's Crash carries the backtrace). Registered for
        # ATTACH mode too, not just spawn: an attached target can equally be
        # killed by a hook (fkie-cad/friTap#65 was attaching), and without this
        # handler such a crash reaches on_detach with no Crash object at all.
        # Registered after logger.pid is set in both branches above, so the pid
        # filter in on_process_crashed can do its job.
        try:
            logger._backend.on_process_crashed(logger.device, logger.on_process_crashed)
        except Exception:
            self._logger.debug("on_process_crashed registration failed", exc_info=True)
        if logger.timeout:
            self._logger.info(f"Waiting {logger.timeout} seconds before resuming...")
            time.sleep(logger.timeout)
            self._logger.info("Timeout reached. Resuming execution...")

        if logger.spawn:
            logger._backend.resume(logger.device, pid)
        else:
            if logger.timeout and logger.target_threads:
                logger._backend.resume_thread(logger.process, main_thread.id)

        return logger.process, script

    def finish(self):
        """Stop the session and clean up resources."""
        logger = self._l
        if logger._observer is not None:
            logger._observer.stop()
            logger._observer.join(timeout=5)
            logger._observer = None

        if logger.script:
            logger._backend.unload_script(logger.script)

        try:
            # Un-gated from spawn to match the registration above: the attach-mode
            # handler must be removed as well, or the callback outlives the session.
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

        Idempotent: Ctrl+C/SIGTERM, target death, script errors, normal exit and
        uncaught exceptions all call this. The work runs exactly once; a
        concurrent caller waits for it to finish instead of racing it (the
        finalize step must not read a half-pulled capture). ``pcap_name`` is
        kept for API compatibility; the temp path comes from the pcap object.
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
            # Stops tcpdump, pulls the pcap next to the output file (where
            # PCAP._temp_pcap_path expects it) and deletes the device copy.
            return pcap_obj.stop_device_capture()
        if thread.is_alive() and getattr(thread, "socket", None) is not None:
            thread.socket.close()
        return pcap_obj._temp_pcap_path()

    def _log_full_capture_staged(self, temp_path, is_mobile):
        capture_type = "mobile" if is_mobile else "local"
        if not temp_path or not os.path.exists(temp_path):
            self._logger.info(f"full {capture_type} capture: no capture data was recorded.")
            return
        # Only the staging copy exists yet: the user-facing "Full capture
        # written to <output>" line comes from the finalize step, which turns
        # it into the requested output file (and removes the temp copy).
        self._logger.debug(f"full {capture_type} capture staged at {temp_path}")
        keylog_file = getattr(self._l, "keylog_file", None)
        if keylog_file is None:
            self._logger.info("remember that the full capture won't contain any decrypted TLS traffic.")
        else:
            self._logger.info(f"remember that the full capture won't contain any decrypted TLS traffic. In order to decrypt it use the logged keys from {keylog_file.name}")

    def install_signal_handler(self):
        """Route Ctrl+C (SIGINT) and SIGTERM to the graceful teardown."""
        for name in self.TERMINATION_SIGNALS:
            signum = getattr(signal, name, None)
            if signum is not None:
                signal.signal(signum, self._on_termination_signal)

    def _on_termination_signal(self, signum, frame):
        logger = self._l
        exit_status = 0 if signum == signal.SIGINT else 128 + int(signum)
        if self._exit_signal_received:
            # A second signal while the teardown is still running: the user
            # insists, so stop waiting for it.
            os._exit(exit_status)
        self._exit_signal_received = True
        logger._exit_status = exit_status
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

        # Safety net. cleanup() normally force-exits the process itself (it
        # finalizes the pcap/keylog, prints the goodbye banner, then calls
        # os._exit). We only reach this line if cleanup() returned early via
        # its _cleanup_done guard — i.e. another thread (e.g. on_detach) is
        # already mid-teardown. Give that teardown a bounded chance to flush
        # the capture (it sets _done_event once the pcap/keylog are written),
        # then force the exit so the user never has to signal a second time.
        # os._exit (not sys.exit) because the Frida session/script is left
        # half-torn-down and a non-daemon Frida thread would otherwise block
        # interpreter shutdown.
        done_event = getattr(logger, "_done_event", None)
        if done_event is not None:
            done_event.wait(self.TEARDOWN_WAIT_SECONDS)
        os._exit(exit_status)

    @staticmethod
    def _termination_message(signum):
        if signum == signal.SIGINT:
            return "Ctrl+C detected. Cleaning up..."
        return f"{signal.Signals(signum).name} received. Cleaning up..."
