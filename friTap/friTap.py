#!/usr/bin/env python3

import argparse
import atexit
import logging
import sys
import threading
import time
import traceback

from .backends import (
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
    BackendNotRunningError,
    BackendPermissionDeniedError,
    BackendProcessNotFoundError,
    BackendProcessNotRespondingError,
    BackendScriptLoadTimeout,
    BackendTimedOutError,
    BackendTransportError,
)

try:
    import colorama
    colorama.init()
except Exception:
    pass

try:
    from AndroidFridaManager import FridaBasedException
except ImportError:
    # Create a dummy exception for testing environments
    class FridaBasedException(Exception):
        pass
from .about import __author__, __version__
from .backends.base import BackendName
from .cli_config import _make_inspection_config, build_capture_config
from .cli_dispatch import (  # noqa: F401 - re-exported for callers and tests
    _AGENT_API_COMMANDS,
    _SUBCOMMAND_HELP_FLAGS,
    _SUBCOMMAND_RUNNERS,
    _agent_api_mode,
    _dispatch_special_mode,
    _looks_like_pcap_input,
    _looks_like_tap_input,
    _selects_tap_subcommand,
)
from .cli_duration import (  # noqa: F401 - re-exported for callers and tests
    _capture_already_stopping,
    _start_duration_timer,
    _stop_capture_after_duration,
)
from .cli_errors import (  # noqa: F401 - re-exported for callers and tests
    _DEVICE_NOT_FOUND_HINT,
    _REMOTE_SERVER_DOWN_HINT,
    _format_seconds,
    _process_not_responding_hints,
    _report_invalid_argument,
    _report_transport_error,
    _report_unexpected_error,
    _script_load_timeout_hints,
    _unexpected_error_line,
)
from .cli_options import (  # noqa: F401 - re-exported for callers and tests
    _CONSOLE_LOGGER_NAMES,
    _PROBE_IGNORED_CAPTURE_FLAGS,
    _WINE_MODES,
    _apply_decoder_isolation_flag,
    _apply_non_interactive_flag,
    _apply_quiet_console,
    _auto_enable_sshd_child_gating,
    _confirm_protocol_all,
    _hex_text_or_none,
    _is_console_handler,
    _maybe_prepend_wine,
    _normalize_bare_wine_flag,
    _normalize_protocol_selection,
    _probe_conflict_warnings,
    _resolve_backend_choice,
    _resolve_ms_rc4_ciphertext,
    _resolve_protocols,
    _split_exec_argv,
    _validate_duration,
    _validate_protocol_cli_intent,
)
from .cli_stream import (  # noqa: F401 - re-exported for callers and tests
    _claim_stdout_for_json_stream,
    _emit_json_stream_usage_error,
    _error_type_name,
    _finish_json_stream_on_exit,
    _note_stream_runtime_error,
    _register_stream_end_reason,
    _register_stream_exit_status,
    _split_exit_info,
    _stop_signal_received,
    _stream_hint,
)
from .config import FriTapConfig, UnsupportedProtocolBackendError
from .exit_codes import (
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    EXIT_TARGET_DETACHED,
    EXIT_USAGE_ERROR,
)
from .fritap_utility import (
    Failure,
    FriTapExit,
    Success,
    are_we_running_on_windows,
    get_pid_of_lsass,
    setup_fritap_logging,
)
from .inspector import LibraryInspector
from .pcap_utility import PCAP_FORMAT_AUTO, PCAP_FORMAT_CHOICES
from .ssl_logger import SSL_Logger


def _repair_shadowed_package_path():
    """Heal ``friTap.__path__`` when a stale install shadows the real source.

    A leftover ``site-packages/friTap`` directory (e.g. from a previous
    non-editable ``pip install .``) has no ``__init__.py``, so Python resolves
    ``friTap`` as a *namespace package* whose ``__path__`` points only at that
    stale directory. Subpackages such as ``friTap.tui`` then resolve into the
    empty stale tree, breaking the TUI with ``No module named 'friTap.tui.app'``.

    This module always loads from the real source tree, so ``__file__`` gives
    the correct package directory. Forces ``friTap.__path__`` to it and drops
    submodules already cached from the wrong location. No-op when already correct.
    """
    import os
    real_dir = os.path.dirname(os.path.abspath(__file__))
    package = sys.modules.get("friTap")
    if package is None or list(getattr(package, "__path__", []) or []) == [real_dir]:
        return
    package.__path__ = [real_dir]
    for name in list(sys.modules):
        if name == "friTap.tui" or name.startswith("friTap.tui."):
            module_file = getattr(sys.modules[name], "__file__", None)
            if not module_file or not os.path.abspath(module_file).startswith(real_dir):
                del sys.modules[name]


_repair_shadowed_package_path()


# Targets with no native modern implementation yet: under --modern the agent runs
# the proven legacy hooks for these, so both paths behave the same there.
_MODERN_LEGACY_DELEGATED = "iOS/macOS Cronet, Windows LSASS"


def _build_lsass_config(pid_of_lsass, *, pcap_name, verbose, keylog, live, debug_mode,
                        host, debug_output, enable_default_fd, patterns,
                        custom_hook_script, json_output, full_capture, json_keys=False,
                        pcap_format=PCAP_FORMAT_AUTO):
    """Config for the LSASS helper session, which contributes to the target's outputs.

    It is marked ``auxiliary_session`` and shares the target session's -p, -k
    and --json paths through the process-wide shared writers
    (friTap/output/shared_output_file.py, shared_keylog_writer.py). When the
    target session runs a full capture (-f) it alone owns the -p file (sniffer,
    finalize, manifest), so the LSASS session gets no pcap and contributes keys.
    """
    config = FriTapConfig.from_legacy_params(
        app=str(pid_of_lsass),
        pcap_name=None if full_capture else pcap_name,
        verbose=verbose,
        spawn=False,  # Always attach, never spawn LSASS
        keylog=keylog,
        enable_spawn_gating=False,
        mobile=False,
        live=live,
        environment_file=None,
        debug_mode=debug_mode,
        full_capture=False,
        socket_trace=False,
        host=host,
        offsets=None,
        debug_output=debug_output,
        experimental=False,
        anti_root=False,
        payload_modification=False,
        enable_default_fd=enable_default_fd,
        patterns=patterns,
        custom_hook_script=custom_hook_script,
        json_output=json_output,
        # Same JSON key-material policy as the target session sharing the file.
        json_keys=json_keys,
        install_lsass_hook=True
    )
    config.output.auxiliary_session = True
    # Same -p container as the target session sharing the file. Resolved after
    # marking the session auxiliary, so only the target session warns about an
    # extension that contradicts --pcap-format.
    config.output.output_format = pcap_format
    config.output.resolve_pcap_container()
    # -f: like the target session (which drops its plaintext hooks in full-capture
    # mode, tcpdump records the raw packets), the helper installs no plaintext
    # hooks either, even though a shared -j output would consume them otherwise.
    # Read by SSL_Logger._plaintext_hooks_needed (OutputConfig has no field yet).
    config.output.plaintext_hooks_disabled = bool(full_capture)
    return config


class LsassHookManager:
    """
    Manager for LSASS hooking that runs in a background thread.
    Provides proper cleanup when friTap detaches from the target process.
    """
    
    def __init__(self):
        self.lsass_logger = None
        self.lsass_thread = None
        self.lsass_process = None
        self.lsass_script = None
        self.lsass_device = None
        self.running = False
        self.logger = logging.getLogger('friTap.lsass')
        
    def start_lsass_hook(self, pcap_name=None, verbose=False, keylog=False, live=False, 
                        debug_mode=False, host=False, debug_output=False, 
                        enable_default_fd=False, patterns=None, custom_hook_script=None, 
                        json_output=None, full_capture=False, json_keys=False,
                        pcap_format=PCAP_FORMAT_AUTO):
        """Start LSASS hooking in a background thread.

        ``full_capture`` is the TARGET session's -f mode: that session alone owns
        the -p file (sniffer, finalize, manifest), so the LSASS session then gets
        no pcap at all and only contributes keys.
        """

        # LSASS is a Windows service. Guard here as well as at the call sites
        # so a direct call is a clear no-op.
        if sys.platform != "win32":
            self.logger.info(
                "LSASS hooking is a Windows-only feature; skipping on %s.",
                sys.platform)
            return None

        pid_of_lsass = get_pid_of_lsass()
        if pid_of_lsass is None:
            self.logger.warning("LSASS process not found. Skipping LSASS hook.")
            return None
            
        self.logger.info(f"Starting LSASS hook with PID: {pid_of_lsass}")
        
        def lsass_hook_worker():
            """Worker function that runs in the background thread."""
            try:
                config = _build_lsass_config(
                    pid_of_lsass, pcap_name=pcap_name, verbose=verbose, keylog=keylog,
                    live=live, debug_mode=debug_mode, host=host, debug_output=debug_output,
                    enable_default_fd=enable_default_fd, patterns=patterns,
                    custom_hook_script=custom_hook_script, json_output=json_output,
                    full_capture=full_capture, json_keys=json_keys,
                    pcap_format=pcap_format)
                self.lsass_logger = SSL_Logger(config=config)
                
                self.lsass_process, self.lsass_script = self.lsass_logger.start_fritap_session()
                self.lsass_device = self.lsass_logger.device
                self.running = True
                
                self.logger.info("LSASS hook started successfully")
                
                while self.running and self.lsass_logger.running:
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"LSASS hook failed: {e}")
                traceback.print_exc()
            finally:
                self.running = False
                
        self.lsass_thread = threading.Thread(
            target=lsass_hook_worker,
            name="LsassHookWorker",
            daemon=True
        )
        self.lsass_thread.start()
        
        time.sleep(2)
        
        return pid_of_lsass
        
    def stop_lsass_hook(self):
        """Stop the LSASS hook and cleanup resources."""
        if not self.running:
            # The worker may have ended on its own (lsass session detached);
            # its output handlers are still open and must be released too.
            self._close_lsass_output_handlers()
            return

        self.logger.info("Stopping LSASS hook...")
        self.running = False
        
        try:
            if self.lsass_logger:
                self.lsass_logger.running = False
                self.lsass_logger.finish_fritap()
                
            if self.lsass_process and self.lsass_logger:
                try:
                    self.lsass_logger._backend.detach(self.lsass_process)
                except Exception as e:
                    self.logger.debug(f"LSASS process detach error (expected): {e}")
                    
        except Exception as e:
            self.logger.error(f"Error during LSASS cleanup: {e}")

        # Release the shared -k keylog handle (and any other outputs): nothing
        # else closes them before the process os._exit()s, and the SChannel
        # auto-relabel cannot rename a keylog that is still open on Windows.
        self._close_lsass_output_handlers()

        if self.lsass_thread and self.lsass_thread.is_alive():
            self.lsass_thread.join(timeout=5.0)
            if self.lsass_thread.is_alive():
                self.logger.warning("LSASS thread did not terminate within timeout")
                
        self.logger.info("LSASS hook stopped")
        
    def _close_lsass_output_handlers(self):
        """Flush and close the LSASS logger's output handlers (idempotent, never raises)."""
        if self.lsass_logger is None:
            return
        try:
            self.lsass_logger.close_output_handlers()
        except Exception as e:
            self.logger.debug(f"LSASS output handler close error: {e}")

    def is_running(self):
        """Check if LSASS hook is currently running."""
        return self.running and (self.lsass_thread and self.lsass_thread.is_alive())

_lsass_hook_manager = LsassHookManager()

def hook_lsass(pcap_name=None, verbose=False, keylog=False, live=False, debug_mode=False, 
               host=False, debug_output=False, enable_default_fd=False, patterns=None, 
               custom_hook_script=None, json_output=None, full_capture=False,
               json_keys=False, pcap_format=PCAP_FORMAT_AUTO):
    """
    Hook the Local Security Authority Subsystem Service (LSASS) process.
    This runs in a background thread and doesn't block the main friTap session.
    """
    return _lsass_hook_manager.start_lsass_hook(
        pcap_name=pcap_name,
        verbose=verbose,
        keylog=keylog,
        live=live,
        debug_mode=debug_mode,
        host=host,
        debug_output=debug_output,
        enable_default_fd=enable_default_fd,
        patterns=patterns,
        custom_hook_script=custom_hook_script,
        json_output=json_output,
        full_capture=full_capture,
        json_keys=json_keys,
        pcap_format=pcap_format,
    )

def cleanup_lsass_hook():
    """Cleanup the LSASS hook when friTap is shutting down."""
    _lsass_hook_manager.stop_lsass_hook()

def is_lsass_hook_running():
    """Check if LSASS hook is currently running."""
    return _lsass_hook_manager.is_running()

# Debug aid: dump the generated final Frida script when its template
# replacements misbehave.
def write_debug_frida_file(debug_script_version):
    debug_script_file = "fritap_agent_debug.js"
    with open(debug_script_file, 'wt', encoding='utf-8') as f:
        f.write(debug_script_version)
    logger = logging.getLogger('friTap')
    logger.info(f"written debug version of the frida script: {debug_script_file}")


def _confirm_full_capture_without_keylog(parsed, logger):
    """Handle ``-f`` without ``-k``: ask before capturing with no key material.

    With ``-ms`` the heap scanner records the keys into its own keylog, so the
    capture is decryptable and the blocking prompt is skipped.
    """
    if getattr(parsed, "memory_scan", False):
        logger.info("Full capture without -k: key material will be recorded by the memory scanner (-ms).")
        return
    if _is_non_interactive(parsed):
        logger.warning(
            "Full capture without -k: no key material will be recorded, so the TLS "
            "traffic in the pcap cannot be decrypted. Continuing (non-interactive).")
        return
    logger.warning("Are you sure you want to proceed without recording the key material (-k <keys.log>)?")
    logger.warning("Without the key material, you have a complete network record, but no way to view the contents of the TLS traffic.")
    logger.info("Do you want to proceed without recording keys? : <press any key to proceed or Ctrl+C to abort>")
    input()


def _stdin_is_interactive():
    """True when stdin is a terminal a human could answer a prompt on."""
    try:
        return bool(sys.stdin) and sys.stdin.isatty()
    except (AttributeError, ValueError):  # closed/replaced stdin
        return False


def _is_non_interactive(parsed):
    """True when an ``input()`` prompt must not block: --non-interactive was
    passed, or stdin is not a TTY (scripts, CI, AI agents)."""
    return bool(getattr(parsed, "non_interactive", False)) or not _stdin_is_interactive()


def _record_capture_exit_status(ssl_log, exit_code):
    """Hand the capture's outcome to the logger, whose cleanup() owns the final
    os._exit (see SSL_Logger.set_exit_status for the first-non-zero-wins rule)."""
    if exit_code is None or not isinstance(ssl_log, SSL_Logger):
        return
    ssl_log.set_exit_status(exit_code)


def _run_early_exit_command(label, action_fn, logger, special_logger):
    """Run a "print something and exit" command, then leave ``cli()`` for good.

    Every path out of this function raises a :class:`FriTapExit` (``Success``
    on a clean listing, ``Failure`` otherwise). It must never ``return``: a
    return would fall through into a full capture session that blocks forever
    in ``wait_for_completion()``.
    """
    logger.info(label)
    try:
        result = action_fn()
    except FriTapExit:
        # A controlled exit is not an error; keep `except Exception` from rewriting it.
        raise
    except BackendTransportError as fe:
        logger.error(f"Backend transport error: {fe}")
        _note_stream_runtime_error(fe)
    except FridaBasedException as e:
        logger.error(f"Backend error: {e}")
        _note_stream_runtime_error(e)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        _note_stream_runtime_error(e)
    else:
        # Must stay in the else: clause. Success/Failure subclass Exception, so
        # raising them in the try: body would be caught by `except Exception`
        # above and re-reported as "An error occurred".
        special_logger.info(result)
        # The inspectors report failure in their return value rather than by
        # raising, so a scan that failed still has to exit non-zero.
        if LibraryInspector.is_error(result):
            raise Failure
        # Keyword on purpose: FriTapExit takes *info* first, so a positional
        # logger would print the Logger's repr instead of the goodbye banner.
        raise Success(logger=special_logger)
    # Only reached after one of the except clauses above logged the cause.
    raise Failure


def _reject_invalid_headless_filter(filter_expression, logger):
    """Exit with :class:`Failure` (code 2) when ``--filter`` cannot be used headless.

    ``cli()`` calls this after the ``-ll``/``--extract-libraries`` early-exit
    commands (which ignore ``--filter``) and before the capture banners, the
    LSASS hook, device lookup or spawning. A bare ``return`` would exit 0 and
    look like a successful empty run to wrapper scripts.

    Only the headless CLI reaches this: the TUI builds flows and accepts the
    full filter engine (``telegram``, ``http.host`` ...).
    """
    if not filter_expression:
        return
    from friTap.filter.pipeline_filter import headless_filter_error
    err = headless_filter_error(filter_expression)
    if err:
        raise Failure(info=err, logger=logger)


class ArgParser(argparse.ArgumentParser):
    """Argument parser that prints the full help on a usage error.

    Help stays on stdout (tooling greps it); the exit code is 2, documented in
    docs/api/cli.md for invalid arguments. ``fritap --help`` is served by the
    explicit ``-h/--help`` action registered in :func:`cli`, not by this method.
    """

    def error(self, message):
        _emit_json_stream_usage_error(message)
        print("friTap v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(EXIT_USAGE_ERROR)


_CAPTURE_DESCRIPTION = "Decrypts and logs an executables or mobile applications encrypted traffic."

_CAPTURE_EPILOG = r"""
Examples:
  %(prog)s -m -p ssl.pcap com.example.app
  %(prog)s -m --pcap log.pcap --verbose com.example.app
  %(prog)s -m -k keys.log -v -s com.example.app
  %(prog)s -m -k keys.log -v -c <path to custom hook script> -s com.example.app
  %(prog)s -m --patterns pattern.json -k keys.log -s com.google.android.youtube
  %(prog)s --pcap log.pcap "$(which curl) https://www.google.com"
  %(prog)s -H 192.168.0.1:1234 --pcap log.pcap com.example.app
  %(prog)s -m -p log.pcap --enable_spawn_gating -v -do -sot --full_capture -k keys.log com.example.app
  %(prog)s -m -p log.pcap --enable_spawn_gating -v -do --anti_root --full_capture -k keys.log com.example.app
  %(prog)s -m -p log.pcap --enable_default_fd com.example.app

Offline (pcap -> .tap):
  %(prog)s --from-pcap capture.pcapng --keylog keys.log --tap out.tap --scan
  %(prog)s --from-pcap cleartext.pcap --tap out.tap        # already-plaintext capture
  (full offline options: %(prog)s --from-pcap <file> --help)

Offline (read / analyze .tap):
  %(prog)s -r capture.tap                       # browse flows interactively in the TUI
  %(prog)s --analyze capture.tap                # passive analysis + findings report
  %(prog)s --analyze capture.tap --report md
"""


def _add_session_arguments(args):
    """Target selection, debugging and the core capture outputs (-k, -p, -f, -l)."""
    args.add_argument("-m", "--mobile",  metavar="<device_id>", default=False, required=False, nargs='?', const=True, help="Attach to a process on Android or iOS. If you have multpile device you specify with the device id.")
    args.add_argument("-H", "--host", metavar="<ip:port>", required=False,
                      help="Attach to a process on a remote device")
    args.add_argument("-c", "--custom_script", metavar="<path>", required=False,
                      help="Path to a custom hook script that will be executed prior to applying the friTap hooks.")
    args.add_argument("-d", "--debug", required=False, action="store_const", const=True,
                      help="Set friTap into debug mode this include debug output as well as a listening Chrome Inspector server for remote debugging.")
    args.add_argument("--debug-log", metavar="<path>", required=False, default=None, dest="debug_log",
                      help="Write the friTap debug log to <path> (default: ./fritap_debug_<ts>_<pid>.log). "
                           "Capture session-level errors, warnings, and uncaught exceptions even in non-TUI mode.")
    args.add_argument("-do", "--debug-output", required=False, action="store_const", const=True,
                      help="Activate the debug output only.")
    args.add_argument("-ar", "--anti_root", required=False, action="store_const", const=True, default=False, help="Activate anti root hooks for Android")
    args.add_argument("-ed", "--enable_default_fd", required=False, action="store_const", const=True, default=False, help="Activate the fallback socket information (127.0.0.1:1234-127.0.0.1:2345) whenever the file descriptor (FD) of the socket cannot be determined. The fallback tuple is oriented: writes go 1234->2345, reads 2345->1234. Records whose TLS client_random is known are instead emitted without addresses, so the host assigns each connection its own synthetic tuple")
    args.add_argument("-f", "--full_capture", required=False, action="store_const", const=True, default=False,
                      help="Do a full packet capture instead of logging only the decrypted TLS payload. Set pcap name with -p <PCAP name>")
    args.add_argument("-k", "--keylog", metavar="<path>", required=False,
                      help="Log key material in the Wireshark-loadable format for the "
                           "active protocol (NSS SSLKEYLOGFILE for TLS, SHARED_SECRET "
                           "for SSH). With --protocol all/auto and multiple protocols "
                           "emitting keys, the file is split per protocol as "
                           "<stem>.<proto><ext> (e.g. keys.tls.log, keys.ssh.log).")
    args.add_argument("-l", "--live", required=False, action="store_const", const=True,
                      help="Create a named pipe <tempdir>/fritap_sharkfin.pcapng that Wireshark "
                           "can read during the capture. The exact path is printed at "
                           "start; open it with 'wireshark -k -i <path>'. Not supported "
                           "on Windows.")
    args.add_argument("-p", "--pcap", metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("--pcap-format", dest="pcap_format", choices=PCAP_FORMAT_CHOICES,
                      default=PCAP_FORMAT_AUTO,
                      help="Container of the -p file (plaintext and -f full capture): "
                           "'pcapng' embeds the keys as a Decryption Secrets Block. "
                           "Default 'auto': .pcapng extension -> pcapng, anything "
                           "else -> classic pcap. An explicit format wins over the "
                           "extension (a contradicting extension is warned about).")
    args.add_argument("-s", "--spawn", required=False, action="store_const", const=True,
                      help="Spawn the executable/app instead of attaching to a running process")
    args.add_argument("-sot", "--socket_tracing", metavar="<path>", required=False, nargs='?', const=True,
                      help="Traces all socket of the target application and provide a prepared wireshark display filter. If pathname is set, it will write the socket trace into a file-")
    args.add_argument("-env","--environment", metavar="<env.json>", required=False,
                      help="Provide the environment necessary for spawning as an JSON file. For instance: {\"ENV_VAR_NAME\": \"ENV_VAR_VALUE\" }")
    args.add_argument("-v", "--verbose", required=False, action="store_const",
                      const=True, help="Show verbose output")


def _add_passive_analysis_arguments(args):
    """Flow view and the live passive analysis (--scan*)."""
    args.add_argument("--hide-control-frames", required=False, action="store_true",
                      default=False, help="Hide HTTP/2 control frames (PING, SETTINGS, WINDOW_UPDATE, GOAWAY) in flow view")
    args.add_argument("--scan", required=False, nargs="?", const="all", default=None,
                      metavar="<analyzers>",
                      help="Run passive analysis of observed traffic during capture. "
                           "Optionally pass a comma-separated analyzer list (e.g. "
                           "credentials,ioc); with no value, runs all built-in analyzers. "
                           "This analyzes already-decrypted traffic only — it does not "
                           "perform any active scanning of the target.")
    args.add_argument("--scan-report", required=False,
                      choices=["json", "csv", "md", "table"], default="table",
                      dest="scan_report",
                      help="Format for the passive-analysis report printed at the end of capture (default: table).")
    args.add_argument("--scan-report-out", required=False, metavar="<path>",
                      default=None, dest="scan_report_out",
                      help="Write the passive-analysis report to this path instead of stdout.")
    args.add_argument("--scan-min-severity", required=False,
                      choices=["critical", "high", "medium", "low", "info"], default="info",
                      dest="scan_min_severity",
                      help="Only report passive-analysis findings at or above this severity (default: info).")
    args.add_argument("--scan-min-confidence", required=False, type=float, default=0.0,
                      dest="scan_min_confidence",
                      help="Only report passive-analysis findings with confidence at or above this value (default: 0.0).")
    args.add_argument("--scan-source", required=False, default=None, metavar="<names>",
                      dest="scan_source",
                      help="Comma-separated analyzer source names to include in the passive-analysis report (default: all).")
    args.add_argument("--scan-category", required=False, default=None, metavar="<categories>",
                      dest="scan_category",
                      help="Comma-separated finding categories to include (secret,pii,network,protocol; default: all).")
    args.add_argument("--scan-show-pii", required=False, action="store_true", default=False,
                      dest="scan_show_pii",
                      help="Reveal PII/secret values in the passive-analysis report instead of redacting them (default: redacted).")
    args.add_argument("--analyzer-path", required=False, action="append", default=None,
                      dest="scan_analyzer_path", metavar="MODULE[:CLASS]",
                      help="Load an external analyzer for the live --scan ('module' or "
                           "'module:Class'). Repeatable to load several analyzers.")
    args.add_argument("--list-analyzers", required=False, action="store_true", default=False,
                      help="List available analyzers (built-in + discovered externals) and exit.")


def _add_info_arguments(args):
    """--version and -h/--help."""
    args.add_argument('--version', action='version',version=f'friTap v{__version__}')
    # The parser is built with add_help=False, so the help action has to be
    # registered explicitly. Without it, `fritap --help` would only "work" as a
    # side effect of error() printing the help text -- and error() must exit 2
    # so that wrappers and CI can detect a bad command line.
    args.add_argument("-h", "--help", action="help",
                      help="Show this help message and exit.")


def _add_gating_and_target_arguments(args):
    """Spawn/child gating, exec() following and the target positional."""
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes matching the target app (useful for Android multi-process apps)")
    args.add_argument("--spawn_gating_all", required=False, action="store_const", const=True,
                      help="Catch ALL newly spawned processes without filtering (use with caution)")
    args.add_argument("--enable_child_gating", required=False, action="store_const", const=True,
                      help="Intercept child processes (fork/posix_spawn) of the target and "
                           "of every instrumented child, and follow each across exec() "
                           "(e.g. git -> git-remote-https)")
    args.add_argument("--follow-exec", required=False, action="store_true",
                      dest="follow_exec", default=None,
                      help="Follow instrumented processes across exec() (spawn and "
                           "attach mode). Default: OFF on every platform: child "
                           "gating triggers a Frida fork-child crash (Frida "
                           "17.24.3-17.27.x).")
    args.add_argument("--no-follow-exec", required=False, action="store_false",
                      dest="follow_exec", default=None,
                      help="Do not follow instrumented processes across exec() (spawn "
                           "and attach mode; e.g. a launcher exec()ing the real binary). "
                           "Skips child gating, which costs ~40-50 ms per fork. "
                           "This is already the default.")
    args.add_argument("exec", metavar="<executable/app name/pid>", nargs="+",
                      help="executable/app whose SSL calls to log. Accepts a "
                           "command with arguments for spawn mode, e.g. "
                           "'wine /path/to/application.exe' (issue #66). If the "
                           "target's own arguments start with '-', put the target "
                           "after '--', e.g. 'fritap -s -k keys.log -- wine app.exe "
                           "-sk https://example.com'.")


def _add_hooking_arguments(args):
    """Offsets, patterns and the agent code path."""
    args.add_argument("--offsets", required=False, metavar="<offsets.json>",
                      help="Provide custom offsets for all hooked functions inside a JSON file or a json string containing all offsets. For more details see our example json (offsets_example.json)")
    args.add_argument("--patterns", required=False, metavar="<pattern.json>",
                  help="Path to a JSON file with custom byte patterns for module hooking "
                           "(merged on top of the shipped defaults). Inline JSON strings "
                           "are not accepted. For the format see the example pattern.json.")
    args.add_argument("--payload_modification", required=False, action="store_const", const=True, default=False,
                      help="Capability to alter the decrypted payload. Be careful here, because this can crash the application.")                  
    args.add_argument("-exp","--experimental", required=False, action="store_const", const=True, default=False,
                      help="Activates all existing experimental feature (see documentation for more information)")
    args.add_argument("--modern", required=False, action="store_const", const=True, default=False,
                      dest="use_modern",
                      help="EXPERIMENTAL: opt into the modern (refactored) friTap agent code path. "
                           "Unlocks the three-tier BoringSSL keylog chain (callback / "
                           "ssl_log_secret symbol / byte pattern) on every platform, and improved "
                           "Cronet hooks on Android/Windows. On Apple the callback tier resolves "
                           "SSL_CTX_set_keylog_callback from the symbol table, since Apple does not "
                           "export it. Every protocol works on both paths; for "
                           f"{_MODERN_LEGACY_DELEGATED} --modern uses the legacy hooks. "
                           "Default: legacy.")
    args.add_argument("--quic-capture-mode", required=False,
                      choices=["stream", "app-api"], default="stream",
                      dest="quic_capture_mode",
                      help="Select the QUIC plaintext capture boundary. "
                           "'stream' (default) uses the current lower-boundary "
                           "stream-level hooks (QuicStream/QuicStreamSequencer "
                           "Readv). 'app-api' captures at the application-API "
                           "Boundary-4 with decoded HTTP/3 headers "
                           "(Chrome/Android Google QUICHE only).")


def _add_memory_scan_arguments(args):
    """The key-region scan and the -ms memory-scan agent."""
    args.add_argument("--scan-keys-region", required=False, default=None,
                      metavar="<module|base,size|heap>", dest="scan_keys_region",
                      help="Scan a memory region for cryptographic key material "
                           "with the generic key-scan engine and emit ranked, "
                           "anonymous candidates to the keylog (requires -k). "
                           "Value is a module name, an explicit '0xADDR,SIZE' "
                           "region, or 'heap' (all writable ranges).")
    args.add_argument("-ms", "--memory-scan", required=False, nargs='?',
                      const=True, default=False, dest="memory_scan",
                      metavar="<pattern.json|engine>",
                      help="Recover TLS secrets by scanning the target's heap memory "
                           "instead of hooking the TLS library — a complementary, "
                           "independently-injected agent. Passed ALONE it is the only "
                           "thing loaded (the normal TLS-hooking agent is skipped) and "
                           "keys are written to '<target>_memscan.keylog' in the current "
                           "directory; combined with -k it writes its own keylog beside "
                           "it as '<stem>.memscan<ext>' (e.g. keys.log -> "
                           "keys.memscan.log), and with -p/-c it runs alongside them. "
                           "Protocol sidecars (.schannel.unpaired, .rc4.keylog, "
                           ".mtproto.keylog, .tls_midstream.secrets.jsonl) are written "
                           "next to that memory-scan keylog. Which scan engine(s) run is derived from --protocol "
                           "and the target platform. The optional value overrides that: "
                           "a pattern FILE overrides/extends the shipped patterns, or an "
                           "ENGINE name (boringssl | schannel | rc4 | mtproto) or "
                           "profile id targets just that engine ('mtproto' and its "
                           "alias 'telegram' recover Telegram MTProto cloud + E2E "
                           "keys on Android). NOTE: because the value is "
                           "optional, put the target after it or use '--' (e.g. "
                           "'fritap -ms -- com.app', 'fritap -ms my_patterns.json com.app', "
                           "'fritap -ms schannel -- app.exe').")
    args.add_argument("--memory-scan-interval", required=False, type=float,
                      default=2.0, dest="memory_scan_interval", metavar="<seconds>",
                      help="Poll cadence (seconds) at which the memory-scan agent "
                           "re-scans the heap (default: 2.0). Only effective with -ms.")
    args.add_argument("--ms-emit-unconfirmed", required=False, action="store_const",
                      const=True, default=False, dest="ms_emit_unconfirmed",
                      help="Also write memory-scan key candidates the confirmation "
                           "oracle could NOT verify (currently MTProto auth/E2E keys) "
                           "to the keylog. OFF by default. Safe offline: a wrong "
                           "candidate matches no record (harmless), a real one recovers "
                           "messages — at the cost of extra keylog noise. Only with -ms.")
    args.add_argument("--ms-rc4-known-plaintext", required=False, default=None,
                      dest="ms_rc4_known_plaintext", metavar="<HEX_OR_TEXT>",
                      help="Known-plaintext oracle for the RC4 memory scanner: a "
                           "candidate key is accepted only when its keystream "
                           "reproduces this prefix. Accepts lowercase hex "
                           "(e.g. '474554202f') or plain text (e.g. 'GET /'), which "
                           "is utf-8-encoded to hex automatically. Turns the heap "
                           "sweep into an exact, zero-false-accept test. Only with "
                           "-ms and the rc4 engine.")
    args.add_argument("--ms-rc4-ciphertext", required=False, default=None,
                      dest="ms_rc4_ciphertext", metavar="<HEX_OR_@FILE>",
                      help="Ciphertext sample for the RC4 memory scanner's trial-"
                           "decrypt scoring (there is no SSPI oracle on Android). "
                           "Accepts lowercase hex, plain text (utf-8-encoded to hex), "
                           "or '@<path>' to read the sample from a file (its contents "
                           "used as hex if valid, else raw->hex). Only with -ms and "
                           "the rc4 engine.")


def _add_hook_tuning_arguments(args):
    """QUIC, loader-hook, PairIP, probe and attribution switches."""
    args.add_argument("--quic-egress-headers-layer", required=False,
                      choices=["auto", "quiche-internal", "chrome-shim", "session-level"],
                      default="auto",
                      dest="quic_egress_headers_layer",
                      help="Override which layer of the HTTP/3 egress-headers chain "
                           "(QuicSpdyStream::WriteHeaders / "
                           "net::QuicChromiumClientStream::WriteHeaders / "
                           "QuicSpdySession::WriteHeadersOnHeadersStream) the agent "
                           "actually attaches to. Default 'auto' keeps the winner-"
                           "takes-all fallback chain (quiche-internal preferred, "
                           "chrome-shim as fallback, session-level as last resort). "
                           "Set to 'chrome-shim' or 'session-level' to force the "
                           "fallback path for testing — useful for validating chain "
                           "behavior on builds where the quiche-internal path still "
                           "resolves. Only effective with --quic-capture-mode app-api.")
    args.add_argument("--quic-only", required=False, action="store_const",
                      const=True, default=False, dest="quic_only",
                      help="Install ONLY QUIC hooks; skip TLS-library hooks (BoringSSL, "
                           "NSS, GnuTLS, ...), OHTTP, the keylog scan-results pass, and "
                           "(Android) the Java hooks. Dramatically lighter attach (no "
                           "multi-MB pattern scans; on Android, no Java VM safepoint sync) "
                           "— helps friTap attach to a target already in active QUIC "
                           "traffic. Supported on Android and Linux (arm64 + x86_64). "
                           "Filter scope: Android = Google QUICHE (Cronet) only; "
                           "Linux = Cloudflare quiche, Google QUICHE (Cronet), Mozilla "
                           "Neqo (Firefox).")
    args.add_argument("--no-loader-hook", "-nlh", required=False, action="store_const",
                      const=True, default=False, dest="no_loader_hook",
                      help="Android: do not install the android_dlopen_ext loader hook. "
                           "Avoids PairIP / anti-tamper SIGSEGV crashes (fkie-cad/friTap#64); "
                           "only already-loaded / explicitly-selected (--offsets) TLS libraries "
                           "are hooked. Recommended together with attach mode (no -s). friTap "
                           "also auto-skips this hook in spawn mode when it detects a known "
                           "anti-tamper library such as Google PairIP (libpairipcore.so).")
    args.add_argument("--experimental-stealth-loader", required=False, action="store_const",
                      const=True, default=False, dest="stealth_loader",
                      help="EXPERIMENTAL (Android, arm64). Watch android_dlopen_ext via a "
                           "hardware breakpoint (CPU debug registers — no linker code patch) "
                           "instead of the inline trampoline, so late-loaded TLS libraries can "
                           "be hooked on PairIP-protected apps without tripping the anti-tamper "
                           "scan (fkie-cad/friTap#64). UNVALIDATED on-device; needs root "
                           "frida-server and may not catch loads on threads created after attach.")
    args.add_argument("--pairip-safe", required=False, action="store_const",
                      const=True, default=False, dest="pairip_safe",
                      help="Android: minimal capture mode for Google PairIP-protected apps "
                           "(fkie-cad/friTap#64). Hooks ONLY a curated, scan-free TLS-library "
                           "allowlist (libssl.so, libhttpengine.so, libcommerce_http_client.so, "
                           "libjavacrypto.so, libconscrypt*, and offset-based libwebviewchromium.so; "
                           "libunity.so is opt-in via --offsets), resolved without any Memory.scan "
                           "(exports -> symbols -> offsets); skips the loader hook, the WebView/Cronet "
                           "pattern scan, Java hooks, OHTTP and library-scan — the broad footprint "
                           "that trips PairIP's periodic integrity check and SIGSEGVs the app. Keys "
                           "persist via 'blink' (hooks toggled so .text stays pristine between scans). "
                           "Works with BOTH attach and spawn (-s); spawn is best-effort (hooks are "
                           "deferred past PairIP's startup window, so the earliest handshakes may be "
                           "missed — attach is the proven path). Trigger fresh TLS handshakes after "
                           "attach (e.g. toggle wifi). See docs/advanced/pairip-safe.md.")
    args.add_argument("--probe", required=False, action="store_const",
                      const=True, default=False, dest="probe",
                      help="Dry run. Load the friTap agent, report which platform friTap "
                           "detected and which platform code path it selected, then exit "
                           "without installing any TLS hooks. Use it to diagnose targets "
                           "that die during instrumentation (fkie-cad/friTap#65): if the "
                           "target survives --probe, the agent loaded fine and the crash "
                           "is in hook installation. No keys, pcap or plaintext are "
                           "produced in probe mode.")
    args.add_argument("--boringssl-anchor-only", required=False, action="store_const",
                      const=True, default=False, dest="force_anchor_locator",
                      help="DEBUGGING AID (Android, arm64). Force friTap's last-resort BoringSSL "
                           "keylog tier (the 'anchor locator') by SKIPPING the byte-pattern tier, so "
                           "a fully-stripped BoringSSL library (Chrome libchrome.so, libhttpengine.so) "
                           "routes straight to the anchor locator that finds ssl_log_secret from the "
                           "keylog label strings and derives the ctx offsets from its prologue. Use it "
                           "to verify tier 4 on modules a pattern would otherwise cover. Still honours "
                           "--pairip-safe (tier 4 is a memory scan). No effect on non-arm64 targets.")
    args.add_argument("--attribute-sdk", required=False, action="store_const",
                      const=True, default=False, dest="attribute_sdk",
                      help="OPT-IN (off by default). Capture the calling thread's backtrace once per "
                           "connection at the first TLS plaintext hook and emit it as an additive "
                           "'caller_stack' message, so decrypted traffic can be attributed to the SDK / "
                           "app code that produced it. Adds per-connection attribution metadata only; it "
                           "never changes, delays or drops captured traffic. Both native and (on Android) "
                           "Java frames are recorded.")


def _add_owner_capture_arguments(args):
    """--owner-capture: scope -f to the target app's UID (AppTap)."""
    args.add_argument("--owner-capture", "-oc", required=False, action="store_const",
                      const=True, default=False, dest="owner_capture",
                      help="Android/Linux: scope the full packet capture (-f) to ONLY the target "
                           "app's traffic using its Linux UID, via the AppTap library. Picks an "
                           "in-kernel NFLOG pre-filter where the kernel supports it, otherwise a "
                           "kernel socket-table (SOCK_DIAG) filter — both app-precise and independent "
                           "of the Frida socket trace. Requires -f and a rooted device; falls back to "
                           "the legacy whole-device capture if AppTap or kernel support is unavailable.")
    args.add_argument("--owner-strict", required=False, action="store_const",
                      const=True, default=False, dest="owner_strict",
                      help="With --owner-capture: scope to the app's base UID only (exclude isolated/"
                           "WebView child UIDs and the DNS resolver UID).")
    args.add_argument("--owner-no-dns", required=False, action="store_const",
                      const=True, default=False, dest="owner_no_dns",
                      help="With --owner-capture: include isolated/WebView child UIDs but not the DNS "
                           "resolver UID.")
    args.add_argument("--nflog-group", required=False, type=int, default=30, dest="owner_nflog_group",
                      metavar="N", help="With --owner-capture: NFLOG group for the Tier-2 in-kernel "
                           "capture (default: 30).")


def _add_library_scan_arguments(args):
    """tlsLibHunter pre-scan and forced BoringSSL pattern scans."""
    args.add_argument("--library-scan", "-ls", required=False, action="store_const",
                      const=True, default=False,
                      help="Pre-scan for TLS libraries using tlsLibHunter before hooking. "
                           "Discovers renamed or statically linked libraries.",
                      dest="library_scan")
    args.add_argument("--force-scan", required=False, metavar="<module>",
                      action="append", default=[], dest="force_scan_modules",
                      help="Force the BoringSSL pattern scan to run on the given module even "
                           "if friTap detects it is covered by a sibling library (Cronet "
                           "APEX split). Repeatable. Example: "
                           "--force-scan libmainlinecronet.141.0.7340.3.so. Accepts a regex "
                           "when prefixed with 're:' or a trailing '*' for prefix matching. "
                           "Also honored via the FRITAP_FORCE_SCAN env var (comma-separated).")


def _add_structured_output_arguments(args):
    """JSON/JSONL and .tap outputs."""
    args.add_argument("-j", "--json", metavar="<path>", required=False,
                      help="Save session metadata and analysis results in JSON format "
                           "(a *.jsonl path writes one event per line). Use '-j -' to "
                           "stream JSONL events to stdout for scripts/AI agents: stdout "
                           "then carries only JSONL and all logging goes to stderr. Key "
                           "material is redacted in every JSON output unless -k or "
                           "--json-keys is also given.")
    args.add_argument("--json-keys", required=False, action="store_true", default=False,
                      dest="json_keys",
                      help="Include raw key material (key_data) in the -j JSON/JSONL "
                           "output even without -k. Without -k or --json-keys keylog "
                           "records are redacted to their label (and public "
                           "client_random) with \"redacted\": true.")
    args.add_argument("--tap", metavar="<file.tap>", required=False, default=None,
                      dest="tap",
                      help="Write the decrypted flows of this capture to a .tap file "
                           "(the TUI's capture format; open with --analyze or the TUI). "
                           "Finalized on Ctrl+C, --duration and target exit.")


def _add_inspection_and_platform_arguments(args):
    """Library listing/extraction, LSASS, resume timeout, backend, Wine and macOS."""
    args.add_argument("-ll", "--list-libraries", required=False, action="store_const", const=True,
                      help="List loaded libraries in order to help debugging the hooking process. This will not start the logging process, but only list the libraries and exit.", dest="list_libraries")
    args.add_argument("--extract-libraries", required=False, metavar="<dir>",
                      help="Extract detected TLS libraries to the specified directory and exit.", dest="extract_libraries")
    args.add_argument("-nl", "--no-lsass", required=False, action="store_const", const=True,default=False,
                      help="Only applied on windows systems. By default friTap is hooking the Local Security Authority Subsystem Service (LSASS) process as well as its the default TLS provider on Windows systems. With this parameter we are not hooking LSASS", dest="no_lsass")
    args.add_argument("-t", "--timeout", metavar="<seconds>", type=int, required=False, default=None,
                      help="Set a timeout in seconds for the process. After the timeout, the process will be resumed automatically. If not set, the process will resume immediately.")
    # default=None (not FRIDA) so we can tell whether the user explicitly chose a
    # backend; resolved to FRIDA right after parse_args (see cli()).
    args.add_argument("--backend", choices=[b.value for b in BackendName], default=None,
                      help="Instrumentation backend to use (default: frida)")
    args.add_argument("--wine", choices=_WINE_MODES, nargs="?", const="auto", default="auto",
                      help="Wine key extraction on Linux (default: auto; '--wine' alone "
                           "also means auto). 'auto' detects a "
                           "Wine target (a `wine ...` command, or a Windows .exe/PE given "
                           "directly) and uses the GDB-based key extractor; 'on' forces it; "
                           "'off' disables it (use the normal Frida flow, e.g. the "
                           "experimental Wine agent).")
    args.add_argument("--macos-unsign-copy", action="store_true", default=False,
                      help="macOS, with -s: spawn an ad-hoc signed temp copy of an Apple platform "
                           "binary (e.g. /usr/bin/curl) so it can be instrumented without root/boot-args.")


def _add_protocol_arguments(args):
    """The multi-select --protocol and -y/--yes."""
    from friTap.protocols.registry import (
        CUSTOM_GROUP,
        available_protocol_names,
        custom_cipher_names,
    )
    # --protocol is multi-select: repeatable and/or comma-separated, so
    # `--protocol tls,rc4` and `--protocol tls --protocol rc4` are equivalent.
    # Normalized and validated after parsing in _normalize_protocol_selection();
    # the default collapses to ["tls"].
    args.add_argument("--protocol", action="append", default=None,
                      metavar="<proto[,proto...]>", dest="protocol",
                      help="Protocol(s) to intercept (default: tls). Repeatable and "
                           "comma-separated for multi-select, e.g. --protocol tls,rc4 or "
                           "--protocol tls --protocol rc4 (both protocols active, independent). "
                           "'tls' covers the TLS family — TLS, QUIC, and OHTTP. "
                           "'ssh', 'ipsec' and 'mtproto' (Telegram) are EXCLUSIVE — each installs "
                           "only its own hooks and cannot be combined with another protocol "
                           "(custom ciphers excepted). "
                           "'telegram' extracts MTProto cloud-chat keys AND Secret-Chat E2E keys into one keylog. "
                           "Some protocols are TLS-wrapped and additionally extract TLS keys; their -k "
                           "keylog is then split into <stem>.<proto><ext> + <stem>.tls<ext>. "
                           "'all' hooks every supported protocol and asks for confirmation "
                           "(skip with -y/--yes). 'auto' is a script-friendly alias for 'all' "
                           "that does NOT prompt. 'all'/'auto' are standalone and cannot be combined. "
                           f"'{CUSTOM_GROUP}' = all custom ciphers (currently: "
                           f"{', '.join(custom_cipher_names()) or 'none'}); combinable with any protocol "
                           "except 'all'/'auto'. "
                           f"Available: {', '.join(available_protocol_names() + ['all', 'auto', CUSTOM_GROUP])}.")
    args.add_argument("-y", "--yes", required=False, action="store_true", default=False,
                      help="Auto-confirm interactive prompts (e.g. --protocol all warning).")


def _add_automation_arguments(args):
    """Unattended runs: --non-interactive, --duration, -q/--quiet."""
    # Unattended / automation flags (scripts, CI, AI agents). See the
    # "Unattended / automation" section of docs/api/cli.md.
    args.add_argument("--non-interactive", required=False, action="store_true",
                      default=False, dest="non_interactive",
                      help="Never prompt: implies -y/--yes, and the -f-without--k "
                           "confirmation only logs a warning and continues. That "
                           "prompt is also skipped automatically when stdin is not a TTY.")
    args.add_argument("--duration", metavar="<seconds>", type=float, required=False,
                      default=None, dest="duration",
                      help="Stop the capture cleanly after <seconds> (same teardown as "
                           "Ctrl+C: pcap/keylog/JSON are flushed, exit code 0). Unrelated "
                           "to -t/--timeout, which delays resuming a spawned process.")
    args.add_argument("-q", "--quiet", required=False, action="store_true",
                      default=False, dest="quiet",
                      help="Suppress the banner and info messages on the console; "
                           "warnings and errors are still printed to stderr.")


def _add_capture_pipeline_arguments(args):
    """Proxy, filters, loopback, keylog relabel, agent load bound, decoder isolation."""
    args.add_argument("--proxy", metavar="<host:port>", required=False, default=None,
                      help="Redirect connections to a proxy (e.g., mitmproxy) and bypass cert pinning. Requires fritap-proxy package.")
    args.add_argument("--filter", metavar="<expression>", required=False, default=None,
                      help='Display filter (Wireshark-like syntax). '
                           'Example: --filter "http.response.code >= 400 and ip.dst == 10.0.0.1"')
    args.add_argument("--no-filter-infrastructure", required=False, action="store_false",
                      default=True, dest="filter_infrastructure",
                      help="Include frida/adb control traffic in captures (by default, ports "
                           "5037/5555/27042/27043 are dropped).")
    # Loopback capture/inclusion is OFF by default and opt-in via --loopback: a full
    # capture (-f) then also sniffs the loopback adapter and the pipeline keeps loopback
    # traffic, so a client talking to a local server (e.g. 127.0.0.1) is captured.
    args.add_argument("--loopback", required=False, action="store_true",
                      default=False, dest="include_loopback",
                      help="Also capture loopback (localhost, 127.0.0.1/::1) traffic. "
                           "Off by default. Only relevant for a full capture (-f) of a "
                           "client talking to a local server. On Windows this needs "
                           "Npcap with loopback support. Note: Frida's own agent link "
                           "uses ephemeral loopback ports, so it will also appear.")
    # Deprecated spelling kept so existing scripts keep working (allow_abbrev is
    # off, so the old flag would otherwise be rejected). Hidden from --help.
    args.add_argument("--include-loopback", required=False, action="store_true",
                      default=False, dest="include_loopback",
                      help=argparse.SUPPRESS)
    # Windows SChannel/lsass keylogs come out with swapped TLS 1.3 labels and ???
    # client_randoms (lsass is system-wide; correlation is per-thread). By default a
    # full capture (-f) auto-relabels the keylog by trial decryption at teardown so it
    # loads directly in Wireshark (the raw agent output is kept as <stem>.raw.keylog).
    args.add_argument("--no-auto-relabel", required=False, action="store_false",
                      default=True, dest="auto_relabel",
                      help="Do NOT auto-relabel the Windows SChannel keylog after a full "
                           "capture. By default friTap trial-decrypts the capture to fix "
                           "TLS 1.3 label swaps / ??? client_randoms and overwrites the "
                           "keylog with the corrected version (raw kept as <stem>.raw.keylog); "
                           "pass this to keep the raw keylog untouched.")
    args.add_argument("--script-load-timeout", metavar="<seconds>", type=float,
                      required=False, default=20.0, dest="script_load_timeout",
                      help="Upper bound in seconds for loading the friTap agent into the "
                           "target (Frida's script.load(), which blocks until the agent "
                           "finished its startup). Exceeding it aborts with a diagnostic "
                           "instead of hanging forever. Use 0 to disable the bound. The "
                           "value is automatically tripled when a pattern scan (--patterns), "
                           "a library scan (--library-scan) or a key-region "
                           "scan (--scan-keys-region) is requested, since those scan inside "
                           "the agent's startup.")
    args.add_argument("--isolate-decoders", required=False, action="store_true",
                      default=False, dest="isolate_decoders",
                      help="Run the native body decompressors (gzip/deflate, brotli, zstd) "
                           "in a separate, restricted worker process, so a decoder exploit "
                           "triggered by captured (attacker-controlled) traffic cannot reach "
                           "the friTap process. Same as FRITAP_ISOLATE_DECODERS=1.")


# Called in this order: argparse lists the options in --help as they are added.
_CAPTURE_ARGUMENT_BUILDERS = (
    _add_session_arguments,
    _add_passive_analysis_arguments,
    _add_info_arguments,
    _add_gating_and_target_arguments,
    _add_hooking_arguments,
    _add_memory_scan_arguments,
    _add_hook_tuning_arguments,
    _add_owner_capture_arguments,
    _add_library_scan_arguments,
    _add_structured_output_arguments,
    _add_inspection_and_platform_arguments,
    _add_protocol_arguments,
    _add_automation_arguments,
    _add_capture_pipeline_arguments,
)


def build_capture_parser():
    """The argparse parser of the main capture CLI (``fritap [options] <target>``)."""
    parser = ArgParser(
        add_help=False,
        description=_CAPTURE_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=_CAPTURE_EPILOG)
    args = parser.add_argument_group("Arguments")
    for add_arguments in _CAPTURE_ARGUMENT_BUILDERS:
        add_arguments(args)
    return parser


def cli():
    # Replaced by setup_fritap_logging() once the flags are parsed.
    logger = logging.getLogger('friTap')

    parser, parsed = _parse_capture_args()
    logger, special_logger = _configure_logging_and_target(parsed)
    _run_library_inspection_commands(parsed, logger, special_logger)

    # A rejected --filter is an invalid-argument error: fail with exit 2 before
    # the capture starts (no banners, no LSASS hook, no attach/spawn). It runs
    # after -ll/--extract-libraries on purpose: those commands never use the
    # filter, so `fritap -ll app --filter telegram` must not be rejected by it.
    _reject_invalid_headless_filter(getattr(parsed, 'filter', None), logger)

    _maybe_hook_lsass(parsed, logger)

    install_lsass_hook = False

    _confirm_protocol_all(parsed, parser, logger)
    _auto_enable_sshd_child_gating(parsed, logger)
    _validate_protocol_cli_intent(parsed, parser, logger)
    _validate_capture_options(parsed, parser, logger)
    _warn_chrome_network_service(parsed, logger)
    _run_capture_session(parsed, logger, special_logger, install_lsass_hook)


def _parse_capture_args():
    """Parse ``sys.argv`` and normalise the result. Returns ``(parser, parsed)``."""
    parser = build_capture_parser()
    parsed = parser.parse_args(_normalize_bare_wine_flag(sys.argv[1:]))
    _claim_stdout_for_json_stream(parsed)
    _apply_decoder_isolation_flag(parsed)
    _apply_non_interactive_flag(parsed)
    _validate_duration(parsed, parser)
    _resolve_backend_choice(parsed)
    _split_exec_argv(parsed)
    _resolve_protocols(parsed, parser)
    return parser, parsed


def _configure_logging_and_target(parsed):
    """Set up console logging, then adjust the target (Wine, macOS) and the debug log.

    Returns ``(logger, special_logger)``.
    """
    # Configure logging after parsing arguments to respect debug flags
    logger, special_logger = setup_fritap_logging(
        debug=parsed.debug, debug_output=parsed.debug_output
    )
    _apply_quiet_console(parsed.quiet)

    # Wine synthesis: turn a bare Windows target (a .exe/PE given without an
    # explicit `wine` launcher) into a `wine <exe>` command so the normal Wine
    # detection/route applies. Linux + spawn only; respects --wine.
    _maybe_prepend_wine(parsed, logger)
    # Apple platform binaries (arm64e): fail fast with options, or --macos-unsign-copy.
    from friTap.platform_support.macos_targets import prepare_macos_spawn_target
    prepare_macos_spawn_target(parsed, logger)
    _prime_debug_log_if_requested(parsed, logger)
    return logger, special_logger


def _prime_debug_log_if_requested(parsed, logger):
    """Open the debug-log file for --debug-log or --debug-output."""
    # Bring up the debug-log file subsystem when the user asked for one,
    # either explicitly via --debug-log or implicitly via --debug-output.
    # Done immediately after console-logging is configured so init-time
    # errors below this line land in the file. The TUI entry point
    # (run_tui) calls prime_debug_log too; both call sites are idempotent.
    debug_log_path_override = getattr(parsed, "debug_log", None)
    if debug_log_path_override or parsed.debug_output:
        from .fritap_utility import prime_debug_log
        opened = prime_debug_log(debug_log_path_override)
        if opened:
            logger.info(f"Debug log: {opened}")
        else:
            logger.warning("Failed to initialise friTap debug log file")


def _run_library_inspection_commands(parsed, logger, special_logger):
    """-ll / --extract-libraries: print and exit via FriTapExit; no-op otherwise."""
    # Handled before the LSASS hook: these flags promise not to start
    # logging, so `fritap -ll app.exe` on Windows must not install a full LSASS
    # instrumentation session just to print a library listing.
    #
    # The SSL_Logger is built inside the lambda so a config or protocol-registry
    # error becomes the helper's "An error occurred" + exit 2 instead of a raw
    # traceback.
    # The label is the only progress feedback: tlsLibHunter pattern-scans every
    # candidate module silently, and the scan grows with module count and
    # pattern set (--scan-all-modules, a few hundred modules on Android).
    if parsed.list_libraries:
        _run_early_exit_command(
            "Listing loaded libraries (scanning loaded modules for TLS patterns)...",
            lambda: SSL_Logger(config=_make_inspection_config(parsed)).inspect_libraries(),
            logger, special_logger)

    if parsed.extract_libraries:
        _run_early_exit_command(
            f"Extracting TLS libraries to {parsed.extract_libraries} "
            "(scanning loaded modules for TLS patterns)...",
            lambda: SSL_Logger(config=_make_inspection_config(parsed)).extract_libraries(
                parsed.extract_libraries),
            logger, special_logger)


def _maybe_hook_lsass(parsed, logger):
    """Start the background LSASS hook for a local Windows target, unless -nl."""
    # LSASS is a Windows service: hooking it only makes sense when friTap runs on
    # a local Windows host analysing a local Windows process. A mobile target
    # (--mobile, Android/iOS) or a remote frida-server (--host) is never Windows
    # LSASS on THIS machine, so LSASS must stay off for those even when the
    # analyst's own OS is Windows.
    if are_we_running_on_windows() and not parsed.mobile and not parsed.host:
        if parsed.no_lsass:
            logger.info("LSASS hooking is disabled. Proceeding without LSASS.")
        else:
            logger.info("Hooking LSASS process for SSL/TLS traffic decryption.")
            # --owner-capture implies -f (enabled further below), so it counts here.
            hook_lsass(parsed.pcap, parsed.verbose, parsed.keylog, parsed.live, parsed.debug, parsed.host, parsed.debug_output, parsed.enable_default_fd, parsed.patterns, parsed.custom_script, parsed.json,
                       full_capture=bool(parsed.full_capture or getattr(parsed, 'owner_capture', False)),
                       json_keys=parsed.json_keys,
                       pcap_format=parsed.pcap_format)
            atexit.register(cleanup_lsass_hook)
    elif (parsed.mobile or parsed.host) and not parsed.no_lsass:
        logger.debug("LSASS hooking is a local-Windows-only feature; skipping for the mobile/remote target.")


def _validate_capture_options(parsed, parser, logger):
    """Warnings and checks on the output flags, before the capture starts."""
    if parsed.use_modern:
        # A status notice, not a problem: INFO gives it the "[*]" prefix, while
        # WARNING would print "[-]", the same prefix as errors.
        logger.info(
            f"friTap modern hooks active (experimental; {_MODERN_LEGACY_DELEGATED} "
            "use the legacy hooks). Omit --modern to use the stable legacy path."
        )

    # Surfaced before the output-flag validations below so the user learns that
    # probe mode ignores those flags at all, rather than being sent to fix a
    # combination that would have been ignored anyway.
    for line in _probe_conflict_warnings(parsed):
        logger.warning(line)

    if parsed.full_capture and parsed.pcap is None:
        parser.error("--full_capture requires -p to set the pcap name")
    if parsed.pcap_format != PCAP_FORMAT_AUTO and parsed.pcap is None:
        parser.error("--pcap-format requires -p to set the pcap name")

    # Resolve '@file' up front so a missing/unreadable sample is a clean CLI
    # error instead of a traceback from inside config construction.
    try:
        parsed.ms_rc4_ciphertext = _resolve_ms_rc4_ciphertext(
            getattr(parsed, 'ms_rc4_ciphertext', None))
    except ValueError as exc:
        parser.error(str(exc))

    if parsed.full_capture and parsed.keylog is None:
        _confirm_full_capture_without_keylog(parsed, logger)


def _warn_chrome_network_service(parsed, logger):
    """Hint at child gating when a QUIC capture targets Chrome's browser process."""
    # Chrome's network service runs in a child process on modern Android builds.
    # Attaching to the browser process sees only its own infra UDP (DoH/sync/
    # Safe-Browsing); QuicSpdyStream::WriteHeaders never fires because the
    # streams live in the subprocess. Hint at the right flags before the user
    # produces an empty pcap. Heuristic: Chrome-family target, mobile mode, and
    # no --enable_child_gating.
    _CHROME_FAMILY_TARGETS = {
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "org.chromium.chrome",
        "Chrome",  # the friendly name Frida resolves on Android
    }
    target = (parsed.exec or "").strip()
    # Only hint when the user opted into QUIC capture (--quic-capture-mode
    # app-api). Keylog-only Chrome captures work fine against the browser
    # process, and the warning would just be noise.
    _explicit_quic_capture = (
        getattr(parsed, 'quic_capture_mode', 'stream') == 'app-api'
        or getattr(parsed, 'quic_only', False)
    )
    if (parsed.mobile and target in _CHROME_FAMILY_TARGETS and _explicit_quic_capture
            and not parsed.enable_child_gating and not parsed.spawn_gating_all):
        logger.warning(
            "[hint] Chrome on Android runs its network service (where HTTP/3 streams "
            "live) in a child process. Attaching only to '%s' typically captures the "
            "browser process's infra UDP (DoH/sync/Safe-Browsing) but NOT the "
            "user-visible HTTP/3 page traffic. If your pcap ends up empty, try one "
            "of:", target)
        logger.warning(
            "  a)  fritap -m %s -s --enable_child_gating <other-flags> %s "
            "(spawn fresh + child-gating)",
            getattr(parsed, "mobile", "<serial>") if isinstance(parsed.mobile, str) else "<serial>",
            target)
        logger.warning(
            "  b)  fritap -m <serial> --enable_child_gating <other-flags> %s "
            "(attach to running Chrome + child-gating)", target)
        logger.warning(
            "  c)  attach directly to the network service subprocess by PID: "
            "adb shell pidof %s:privileged_process0", target)
        logger.warning(
            "Run  adb shell \"ps -A | grep %s\"  to see which child processes "
            "actually exist for your Chrome build.", target)


def _run_capture_session(parsed, logger, special_logger, install_lsass_hook):
    """Run the capture to completion. Returns on success, otherwise raises.

    The ``finally`` records the exit status and runs SSL_Logger's cleanup,
    which owns the final os._exit.
    """
    # Runtime-error unless the capture returns normally (see the else/except
    # branches); handed to SSL_Logger.cleanup()'s os._exit in the finally.
    capture_exit_code = EXIT_RUNTIME_ERROR
    try:
        special_logger.info("Start logging")
        special_logger.info("Press Ctrl+C to stop logging")

        # --owner-capture produces an app-scoped full pcap; it implies -f.
        if getattr(parsed, 'owner_capture', False) and not parsed.full_capture:
            logger.info("--owner-capture implies a full capture; enabling -f/--full_capture.")
            parsed.full_capture = True

        config = build_capture_config(parsed, install_lsass_hook)

        # --filter was already validated by _reject_invalid_headless_filter()
        # right after argument parsing, before the banners above.

        config.output.tap_output = parsed.tap

        ssl_log = SSL_Logger(config=config)
        _register_stream_exit_status(ssl_log)

        # Read by legacy/ssl_logger_core.py via getattr(self, 'use_modern', False)
        # when it builds the agent config_batch.
        if getattr(parsed, "use_modern", False):
            ssl_log.use_modern = True

        ssl_log.install_signal_handler()
        ssl_log.start_fritap_session()

        # --duration: a probe run exits on its own, so only arm it for captures.
        if not parsed.probe:
            _start_duration_timer(ssl_log, parsed.duration, logger)
        
        # Wait for user input or interrupt
        ssl_log.wait_for_completion()
            
    except KeyboardInterrupt:
        capture_exit_code = None  # unchanged: the Ctrl+C teardown decides
        from .output.stdout_stream import ENDED_BY_STOPPED, note_end_reason
        note_end_reason(ENDED_BY_STOPPED)
        logger.info("Keyboard interrupt received. Cleaning up...")
        cleanup_lsass_hook()
        raise
    except SystemExit as se:
        capture_exit_code = se.code if isinstance(se.code, int) else None
        cleanup_lsass_hook()
        raise
    except BackendTransportError as fe:
        capture_exit_code = EXIT_TARGET_DETACHED
        _note_stream_runtime_error(fe)
        # A transport error mid-session almost always means the target died
        # (often a native crash inside a hook). If on_detach already attributed
        # it, don't repeat the cryptic line; otherwise add a hint.
        _report_transport_error(fe, locals().get("ssl_log"), logger)
    except BackendScriptLoadTimeout as se:
        # Prefer the breadcrumb the exception carries over the one on SSL_Logger.
        _ssl_log = locals().get("ssl_log")
        crumb = se.breadcrumb or getattr(_ssl_log, "_last_hook_breadcrumb", "")
        # se.bound_seconds is the EFFECTIVE bound (tripled for scan-heavy runs);
        # parsed.script_load_timeout is only what the user typed, so it would
        # under-report for --patterns / --library-scan / --scan-keys-region.
        bound = se.bound_seconds or parsed.script_load_timeout
        hint_lines = _script_load_timeout_hints(se.elapsed_seconds, crumb, bound)
        for line in hint_lines:
            logger.error(line)
        _note_stream_runtime_error(se, hint_lines[1:])
    except BackendProcessNotRespondingError as pe:
        hint_lines = _process_not_responding_hints(str(pe), parsed.spawn)
        for line in hint_lines:
            logger.error(line)
        _note_stream_runtime_error(pe, hint_lines[1:])
    except FridaBasedException as e:
        logger.error(f"Backend error: {e}")
        _note_stream_runtime_error(e)
    except BackendTimedOutError as te:
        logger.error(f"TimeOutError: {te}")
        _note_stream_runtime_error(te)
    except BackendProcessNotFoundError as pe:
        logger.error(f"ProcessNotFoundError: {pe}")
        _note_stream_runtime_error(pe)
    except BackendPermissionDeniedError as e:
        logger.error(f"Permission denied: {e}")
        from friTap.platform_support.macos_targets import hardened_process_hint_lines
        hint_lines = hardened_process_hint_lines(str(e), parsed.exec or "")
        for line in hint_lines:
            logger.error(line)
        _note_stream_runtime_error(e, hint_lines)
    except BackendNotRunningError as e:
        logger.error(f"Backend server is not running: {e}")
        _note_stream_runtime_error(e)
    except BackendInvalidArgumentError as e:
        _report_invalid_argument(e, logger)
    except BackendInvalidOperationError as e:
        logger.error(f"Invalid operation: {e}")
        _note_stream_runtime_error(e)
    except UnsupportedProtocolBackendError as e:
        logger.error(f"Unsupported protocol-backend combination: {e}")
        _note_stream_runtime_error(e)
    except Exception as ar:
        _report_unexpected_error(ar, parsed, logger, special_logger)

    else:
        capture_exit_code = EXIT_OK
        return
    finally:
        _record_capture_exit_status(locals().get("ssl_log"), capture_exit_code)
        if 'ssl_log' in locals() and isinstance(ssl_log, SSL_Logger):
            ssl_log.pcap_cleanup(parsed.full_capture,parsed.mobile,parsed.pcap)
            ssl_log.cleanup(live=parsed.live, socket_trace=parsed.socket_tracing, full_capture=parsed.full_capture, debug_output=parsed.debug_output, debug=parsed.debug)
    
    # Reached only when an error handler above did not raise.
    raise Failure(code=capture_exit_code if capture_exit_code is not None else EXIT_RUNTIME_ERROR)


_BROTLI_WARNING_EMITTED = False


def _warn_if_vulnerable_brotli():
    """Log the brotli CVE-2026-111497 warning once per process (if it applies)."""
    global _BROTLI_WARNING_EMITTED
    if _BROTLI_WARNING_EMITTED:
        return
    _BROTLI_WARNING_EMITTED = True
    from .parsers.decompress import brotli_security_warning
    warning = brotli_security_warning()
    if warning:
        logging.getLogger('friTap').warning(warning)


def main():
    _warn_if_vulnerable_brotli()
    # Handle sub-commands before argparse via the centralized dispatcher.
    mode = _dispatch_special_mode(sys.argv)

    if mode is not None:
        kind, payload = mode

        runner = _SUBCOMMAND_RUNNERS.get(kind)
        if runner is not None:
            return runner(kind, payload)

        if kind == "replay" and payload is None:
            print("Usage: fritap -r <capture.tap>")
            return

        # pcap-wizard mode: fritap -r capture.pcap  or  fritap capture.pcapng
        # Launch the guided pcap-to-tap wizard inside the TUI, which converts
        # the pcap to a .tap (with optional TLS + per-protocol keylogs) and
        # then opens the result in the replay view.
        if kind == "pcap-wizard":
            try:
                from .tui.app import run_tui
            except ImportError as e:
                logging.getLogger('friTap').error(
                    f"Could not load the interactive TUI: {e}. "
                    "Ensure friTap's TUI dependencies are installed (pip install -e . / pip install textual)."
                )
            else:
                run_tui(pcap_to_tap_file=payload)
            return

    # Replay mode: fritap -r capture.tap  or  fritap capture.tap
    replay_file = mode[1] if (mode is not None and mode[0] == "replay") else None

    if replay_file is not None:
        try:
            from .tui.app import run_tui
        except ImportError as e:
            logging.getLogger('friTap').error(
                f"Could not load the interactive TUI: {e}. "
                "Ensure friTap's TUI dependencies are installed (pip install -e . / pip install textual)."
            )
        else:
            run_tui(replay_file=replay_file)
        return

    # When invoked with no arguments, launch the interactive TUI
    if len(sys.argv) == 1:
        try:
            from .tui.app import run_tui
        except ImportError as e:
            logging.getLogger('friTap').error(
                f"Could not load the interactive TUI: {e}. "
                "Ensure friTap's TUI dependencies are installed (pip install -e . / pip install textual). "
                "Falling back to the command-line interface."
            )
            # fall through to CLI help
        else:
            run_tui()
            return

    try:
        cli()
    except FriTapExit as e:
        _finish_json_stream_on_exit(e.code, e.info)
        e.exit()
    except SystemExit as se:
        code = se.code if isinstance(se.code, int) else (0 if se.code is None else EXIT_RUNTIME_ERROR)
        _finish_json_stream_on_exit(code, se.code if isinstance(se.code, str) else None)
        raise
    except BaseException as unexpected:  # noqa: BLE001 - re-raised below
        if not isinstance(unexpected, KeyboardInterrupt):
            _finish_json_stream_on_exit(
                EXIT_RUNTIME_ERROR, f"{type(unexpected).__name__}: {unexpected}",
                error_type=type(unexpected).__name__)
        raise


if __name__ == "__main__":
    # Like the console-script wrapper: a subcommand's return code is the exit code.
    sys.exit(main())
