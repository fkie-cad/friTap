#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Session lifecycle management for friTap.

SessionManager handles the session start/stop lifecycle,
signal handling, and cleanup.
"""

from __future__ import annotations
import json
import signal
import sys
import time
import logging
from typing import TYPE_CHECKING

from ..backends.base import BackendName

if TYPE_CHECKING:
    from .ssl_logger_core import SSL_Logger


class SessionManager:
    """Manages the lifecycle of a friTap capture session."""

    def __init__(self, logger_instance: "SSL_Logger") -> None:
        self._logger_instance = logger_instance
        self._logger = logging.getLogger("friTap.session")

    @property
    def _l(self) -> "SSL_Logger":
        """Shorthand access to the SSL_Logger instance."""
        return self._logger_instance

    def start_session(self, own_message_handler=None):
        """Start a friTap capture session. Delegates to SSL_Logger internals."""
        from ..backends import BackendNotRunningError, BackendInvalidArgumentError

        logger = self._l

        if logger.mobile:
            try:
                if logger.mobile is True:
                    logger.device = logger._backend.get_device(mobile=True)
                else:
                    logger.device = logger._backend.get_device(mobile=logger.mobile)
                self._logger.info("Successfully attached to the mobile device.")
            except BackendNotRunningError:
                self._logger.error(f"{logger._backend.name} backend: server is not running. Please ensure it is started on the device.")
                sys.exit(1)
            except BackendInvalidArgumentError as e:
                if 'device not found' in e.args:
                    self._logger.error(f"Device with ID '{logger.mobile}' not found.")
                else:
                    self._logger.error(f"Backend error ({logger._backend.name}): {e}")
                sys.exit(1)
            except Exception as e:
                self._logger.error(f"Unexpected error while attaching to the device: {e}")
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
            if logger.mobile or logger.host:
                pid = logger._backend.spawn_raw(logger.device, logger.target_app)
            else:
                used_env = {}
                if logger.environment_file:
                    with open(logger.environment_file) as json_env_file:
                        used_env = json.load(json_env_file)
                pid = logger._backend.spawn_raw(logger.device, logger.target_app.split(" "), env=used_env)
                time.sleep(1)
            logger.process = logger._backend.attach(logger.device, str(pid))
        else:
            logger.process = logger._backend.attach(logger.device, logger.target_app)
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
            logger._backend.on_message(script, logger._internal_callback_wrapper())
            logger._backend.load_script(script)
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

        if hasattr(logger, 'install_lsass_hook') and logger.install_lsass_hook:
            try:
                from ..friTap import cleanup_lsass_hook
                cleanup_lsass_hook()
            except ImportError:
                pass

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        """Finalize PCAP capture."""
        logger = self._l
        if is_full_capture and logger.pcap_obj is not None:
            capture_type = "local"
            logger.pcap_obj.full_capture_thread.join(2.0)
            if logger.pcap_obj.full_capture_thread.is_alive() and not is_mobile:
                logger.pcap_obj.full_capture_thread.socket.close()
            if logger.pcap_obj.full_capture_thread.mobile_subprocess != -1:
                capture_type = "mobile"
                logger.pcap_obj.android_Instance.send_ctrlC_over_adb()
                time.sleep(1)
                logger.pcap_obj.full_capture_thread.mobile_subprocess.terminate()
                logger.pcap_obj.full_capture_thread.mobile_subprocess.wait()
                if not logger.pcap_obj.android_Instance.is_tcpdump_available:
                    self._logger.error("tcpdump is not available on the device.")
                    return
                logger.pcap_obj.android_Instance.pull_pcap_from_device()
            self._logger.info(f"full {capture_type} capture saved to _{pcap_name}")
            if logger.keylog_file is None:
                self._logger.info("remember that the full capture won't contain any decrypted TLS traffic.")
            else:
                self._logger.info(f"remember that the full capture won't contain any decrypted TLS traffic. In order to decrypt it use the logged keys from {logger.keylog_file.name}")

    def install_signal_handler(self):
        """Install Ctrl+C signal handler."""
        logger = self._l

        def signal_handler(signum, frame):
            self._logger.info("Ctrl+C detected. Cleaning up...")
            if hasattr(logger, 'install_lsass_hook') and logger.install_lsass_hook:
                try:
                    from ..friTap import cleanup_lsass_hook
                    cleanup_lsass_hook()
                except ImportError:
                    pass
            self.pcap_cleanup(logger.full_capture, logger.mobile, logger.pcap_name)
            logger.cleanup(logger.live, logger.socket_trace, logger.full_capture, logger.debug_output, logger.debug)

        signal.signal(signal.SIGINT, signal_handler)
