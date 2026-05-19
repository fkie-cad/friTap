#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import sys
from .backends import (
    BackendTransportError,
    BackendTimedOutError,
    BackendProcessNotFoundError,
    BackendPermissionDeniedError,
    BackendNotRunningError,
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
)
import logging
import time
import traceback
import threading
import atexit

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
from .about import __version__
from .about import __author__
from .ssl_logger import SSL_Logger
from .config import FriTapConfig, UnsupportedProtocolBackendError
from .backends.base import BackendName
from .fritap_utility import get_pid_of_lsass, are_we_running_on_windows, setup_fritap_logging, Success, Failure, FriTapExit


# Libraries the modern agent path does not yet cover; users opting into --modern
# (or --protocol ssh, which auto-enables it) fall back to legacy behavior for these.
_MODERN_REGRESSIONS = "iOS/macOS Cronet, Windows LSASS, IPsec"


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
                        json_output=None):
        """Start LSASS hooking in a background thread."""
        
        pid_of_lsass = get_pid_of_lsass()
        if pid_of_lsass is None:
            self.logger.warning("LSASS process not found. Skipping LSASS hook.")
            return None
            
        self.logger.info(f"Starting LSASS hook with PID: {pid_of_lsass}")
        
        def lsass_hook_worker():
            """Worker function that runs in the background thread."""
            try:
                # Create SSL_Logger instance for LSASS
                self.lsass_logger = SSL_Logger(
                    app=str(pid_of_lsass),
                    pcap_name=pcap_name,
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
                    install_lsass_hook=True
                )
                
                # Start the LSASS session
                self.lsass_process, self.lsass_script = self.lsass_logger.start_fritap_session()
                self.lsass_device = self.lsass_logger.device
                self.running = True
                
                self.logger.info("LSASS hook started successfully")
                
                # Keep the thread alive while the hook is running
                while self.running and self.lsass_logger.running:
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"LSASS hook failed: {e}")
                traceback.print_exc()
            finally:
                self.running = False
                
        # Start the worker thread
        self.lsass_thread = threading.Thread(
            target=lsass_hook_worker,
            name="LsassHookWorker",
            daemon=True  # Daemon thread will be terminated when main program exits
        )
        self.lsass_thread.start()
        
        time.sleep(2)
        
        return pid_of_lsass
        
    def stop_lsass_hook(self):
        """Stop the LSASS hook and cleanup resources."""
        if not self.running:
            return
            
        self.logger.info("Stopping LSASS hook...")
        self.running = False
        
        try:
            # Cleanup LSASS logger
            if self.lsass_logger:
                self.lsass_logger.running = False
                self.lsass_logger.finish_fritap()
                
            # Detach from LSASS process
            if self.lsass_process and self.lsass_logger:
                try:
                    self.lsass_logger._backend.detach(self.lsass_process)
                except Exception as e:
                    self.logger.debug(f"LSASS process detach error (expected): {e}")
                    
        except Exception as e:
            self.logger.error(f"Error during LSASS cleanup: {e}")
            
        # Wait for thread to finish (with timeout)
        if self.lsass_thread and self.lsass_thread.is_alive():
            self.lsass_thread.join(timeout=5.0)
            if self.lsass_thread.is_alive():
                self.logger.warning("LSASS thread did not terminate within timeout")
                
        self.logger.info("LSASS hook stopped")
        
    def is_running(self):
        """Check if LSASS hook is currently running."""
        return self.running and (self.lsass_thread and self.lsass_thread.is_alive())

# Global LSASS hook manager instance
_lsass_hook_manager = LsassHookManager()

def hook_lsass(pcap_name=None, verbose=False, keylog=False, live=False, debug_mode=False, 
               host=False, debug_output=False, enable_default_fd=False, patterns=None, 
               custom_hook_script=None, json_output=None):
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
        json_output=json_output
    )

def cleanup_lsass_hook():
    """Cleanup the LSASS hook when friTap is shutting down."""
    _lsass_hook_manager.stop_lsass_hook()

def is_lsass_hook_running():
    """Check if LSASS hook is currently running."""
    return _lsass_hook_manager.is_running()

# usually not needed - but sometimes the replacements of the script result into minor issues
# than we have to look into the generated final frida script we supply
def write_debug_frida_file(debug_script_version):
    debug_script_file = "fritap_agent_debug.js"
    with open(debug_script_file, 'wt', encoding='utf-8') as f:
        f.write(debug_script_version)
    logger = logging.getLogger('friTap')
    logger.info(f"written debug version of the frida script: {debug_script_file}")



class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("friTap v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)

def cli():
    # Initial setup - will be reconfigured after parsing arguments
    logger = logging.getLogger('friTap')
    
    parser = ArgParser(
        add_help=False,
        description="Decrypts and logs an executables or mobile applications SSL/TLS traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=r"""
Examples:
  %(prog)s -m -p ssl.pcap com.example.app
  %(prog)s -m --pcap log.pcap --verbose com.example.app
  %(prog)s -m -k keys.log -v -s com.example.app
  %(prog)s -m -k keys.log -v -c <path to custom hook script> -s com.example.app
  %(prog)s -m --patterns pattern.json -k keys.log -s com.google.android.youtube
  %(prog)s --pcap log.pcap "$(which curl) https://www.google.com"
  %(prog)s -H --pcap log.pcap 192.168.0.1:1234 com.example.app
  %(prog)s -m -p log.pcap --enable_spawn_gating -v -do -sot --full_capture -k keys.log com.example.app
  %(prog)s -m -p log.pcap --enable_spawn_gating -v -do --anti_root --full_capture -k keys.log com.example.app
  %(prog)s -m -p log.pcap --enable_default_fd com.example.app
""")

    args = parser.add_argument_group("Arguments")
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
    args.add_argument("-do", "--debugoutput", required=False, action="store_const", const=True,
                      help="Activate the debug output only.")
    args.add_argument("-ar", "--anti_root", required=False, action="store_const", const=True, default=False, help="Activate anti root hooks for Android")
    args.add_argument("-ed", "--enable_default_fd", required=False, action="store_const", const=True, default=False, help="Activate the fallback socket information (127.0.0.1:1234-127.0.0.1:2345) whenever the file descriptor (FD) of the socket cannot be determined")
    args.add_argument("-f", "--full_capture", required=False, action="store_const", const=True, default=False,
                      help="Do a full packet capture instead of logging only the decrypted TLS payload. Set pcap name with -p <PCAP name>")
    args.add_argument("-k", "--keylog", metavar="<path>", required=False,
                      help="Log key material in the Wireshark-loadable format for the "
                           "active protocol (NSS SSLKEYLOGFILE for TLS, SHARED_SECRET "
                           "for SSH). With --protocol all/auto and multiple protocols "
                           "emitting keys, the file is split per protocol as "
                           "<stem>.<proto><ext> (e.g. keys.tls.log, keys.ssh.log).")
    args.add_argument("-l", "--live", required=False, action="store_const", const=True,
                      help="Creates a named pipe /tmp/sharkfin which can be read by Wireshark during the capturing process")
    args.add_argument("-p", "--pcap", metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("-s", "--spawn", required=False, action="store_const", const=True,
                      help="Spawn the executable/app instead of attaching to a running process")
    args.add_argument("-sot", "--socket_tracing", metavar="<path>", required=False, nargs='?', const=True,
                      help="Traces all socket of the target application and provide a prepared wireshark display filter. If pathname is set, it will write the socket trace into a file-")
    args.add_argument("-env","--environment", metavar="<env.json>", required=False,
                      help="Provide the environment necessary for spawning as an JSON file. For instance: {\"ENV_VAR_NAME\": \"ENV_VAR_VALUE\" }")
    args.add_argument("-v", "--verbose", required=False, action="store_const",
                      const=True, help="Show verbose output")
    args.add_argument("--hide-control-frames", required=False, action="store_true",
                      default=False, help="Hide HTTP/2 control frames (PING, SETTINGS, WINDOW_UPDATE, GOAWAY) in flow view")
    args.add_argument('--version', action='version',version='friTap v{version}'.format(version=__version__))
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes matching the target app (useful for Android multi-process apps)")
    args.add_argument("--spawn_gating_all", required=False, action="store_const", const=True,
                      help="Catch ALL newly spawned processes without filtering (use with caution)")
    args.add_argument("--enable_child_gating", required=False, action="store_const", const=True,
                      help="Intercept child processes spawned by the target application")
    args.add_argument("exec", metavar="<executable/app name/pid>",
                      help="executable/app whose SSL calls to log")
    args.add_argument("--offsets", required=False, metavar="<offsets.json>",
                      help="Provide custom offsets for all hooked functions inside a JSON file or a json string containing all offsets. For more details see our example json (offsets_example.json)")
    args.add_argument("--patterns", required=False, metavar="<pattern.json>",
                  help="Provide custom patterns for module hooking inside a JSON file or a JSON string containing platform-specific patterns. For more details see our provided JSON (pattern.json)")
    args.add_argument("--payload_modification", required=False, action="store_const", const=True, default=False,
                      help="Capability to alter the decrypted payload. Be careful here, because this can crash the application.")                  
    args.add_argument("-exp","--experimental", required=False, action="store_const", const=True, default=False,
                      help="Activates all existing experimental feature (see documentation for more information)")
    args.add_argument("--modern", required=False, action="store_const", const=True, default=False,
                      dest="use_modern",
                      help="EXPERIMENTAL: opt into the modern (refactored) friTap agent code path. "
                           "Unlocks the three-tier BoringSSL keylog chain and improved Cronet hooks "
                           "on Android/Windows. Known regressions vs the legacy default: "
                           f"{_MODERN_REGRESSIONS}. Default: legacy.")
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
    args.add_argument("-j", "--json", metavar="<path>", required=False,
                      help="Save session metadata and analysis results in JSON format")
    args.add_argument("-ll", "--list-libraries", required=False, action="store_const", const=True,
                      help="List loaded libraries in order to help debugging the hooking process. This will not start the logging process, but only list the libraries and exit.", dest="list_libraries")
    args.add_argument("--extract-libraries", required=False, metavar="<dir>",
                      help="Extract detected TLS libraries to the specified directory and exit.", dest="extract_libraries")
    args.add_argument("-nl", "--no-lsass", required=False, action="store_const", const=True,default=False,
                      help="Only applied on windows systems. By default friTap is hooking the Local Security Authority Subsystem Service (LSASS) process as well as its the default TLS provider on Windows systems. With this parameter we are not hooking LSASS", dest="no_lsass")
    args.add_argument("-t", "--timeout", metavar="<seconds>", type=int, required=False, default=None,
                      help="Set a timeout in seconds for the process. After the timeout, the process will be resumed automatically. If not set, the process will resume immediately.")
    args.add_argument("--backend", choices=[b.value for b in BackendName], default=BackendName.FRIDA,
                      help="Instrumentation backend to use (default: frida)")
    args.add_argument("--protocol", type=str, default="tls",
                      choices=["tls", "ipsec", "ssh", "all", "auto"],
                      help="Protocol to intercept (default: tls). "
                           "'tls' covers the TLS family — TLS, QUIC, and OHTTP. "
                           "'ssh' and 'ipsec' are exclusive (only their hooks install). "
                           "'all' hooks every supported protocol and asks for confirmation "
                           "(skip with -y/--yes). 'auto' is a script-friendly alias for 'all' "
                           "that does NOT prompt.")
    args.add_argument("-y", "--yes", required=False, action="store_true", default=False,
                      help="Auto-confirm interactive prompts (e.g. --protocol all warning).")
    args.add_argument("--proxy", metavar="<host:port>", required=False, default=None,
                      help="Redirect connections to a proxy (e.g., mitmproxy) and bypass cert pinning. Requires fritap-proxy package.")
    args.add_argument("--filter", metavar="<expression>", required=False, default=None,
                      help='Display filter (Wireshark-like syntax). '
                           'Example: --filter "http.response.code >= 400 and ip.dst == 10.0.0.1"')
    args.add_argument("--no-filter-infrastructure", required=False, action="store_false",
                      default=True, dest="filter_infrastructure",
                      help="Include frida/adb control traffic in captures (by default, ports "
                           "5037/5555/27042/27043 are dropped).")
    args.add_argument("--include-loopback", required=False, action="store_true",
                      default=False, dest="include_loopback",
                      help="Include loopback/localhost traffic (e.g. Firefox internal NSS IPC). "
                           "By default loopback traffic is filtered out to reduce noise.")
    parsed = parser.parse_args()

    # Configure logging after parsing arguments to respect debug flags
    logger, special_logger = setup_fritap_logging(
        debug=parsed.debug, debug_output=parsed.debugoutput
    )

    # Bring up the debug-log file subsystem when the user asked for one,
    # either explicitly via --debug-log or implicitly via --debugoutput.
    # Done immediately after console-logging is configured so init-time
    # errors below this line land in the file. The TUI entry point
    # (run_tui) calls prime_debug_log too — both call sites are idempotent.
    debug_log_path_override = getattr(parsed, "debug_log", None)
    if debug_log_path_override or parsed.debugoutput:
        from .fritap_utility import prime_debug_log
        opened = prime_debug_log(debug_log_path_override)
        if opened:
            logger.info(f"Debug log: {opened}")
        else:
            logger.warning("Failed to initialise friTap debug log file")

    if are_we_running_on_windows() and not parsed.mobile:
        if parsed.no_lsass:
            logger.info("LSASS hooking is disabled. Proceeding without LSASS.")
        else:
            logger.info("Hooking LSASS process for SSL/TLS traffic decryption.")
            hook_lsass(parsed.pcap, parsed.verbose, parsed.keylog, parsed.live, parsed.debug, parsed.host, parsed.debugoutput, parsed.enable_default_fd, parsed.patterns, parsed.custom_script, parsed.json)
            atexit.register(cleanup_lsass_hook)

    install_lsass_hook = False
    
    def _make_inspection_config(parsed):
        return FriTapConfig.from_legacy_params(
            app=parsed.exec, verbose=parsed.verbose, spawn=parsed.spawn,
            mobile=parsed.mobile, environment_file=parsed.environment,
            debug_mode=parsed.debug, host=parsed.host, offsets=parsed.offsets,
            debug_output=parsed.debugoutput, experimental=parsed.experimental,
            anti_root=parsed.anti_root, enable_default_fd=parsed.enable_default_fd,
            patterns=parsed.patterns, custom_hook_script=parsed.custom_script,
            backend=parsed.backend,
        )

    def _run_early_exit_command(label, action_fn, logger, special_logger):
        logger.info(label)
        try:
            result = action_fn()
            special_logger.info(result)
        except BackendTransportError as fe:
            logger.error(f"Backend transport error: {fe}")
        except FridaBasedException as e:
            logger.error(f"Backend error: {e}")
        except Exception as e:
            logger.error(f"An error occurred: {e}")
        else:
            return
        raise Failure

    if parsed.list_libraries:
        config = _make_inspection_config(parsed)
        ssl_log = SSL_Logger(config=config)
        _run_early_exit_command("Listing loaded libraries...",
            ssl_log.inspect_libraries, logger, special_logger)

    if parsed.extract_libraries:
        config = _make_inspection_config(parsed)
        ssl_log = SSL_Logger(config=config)
        _run_early_exit_command(
            f"Extracting TLS libraries to {parsed.extract_libraries} ...",
            lambda: ssl_log.extract_libraries(parsed.extract_libraries),
            logger, special_logger)

    # --protocol all: install every protocol's hooks, but make the user confirm.
    # auto is the script-friendly alias (same hooks, no prompt) for unattended runs.
    if parsed.protocol == "all" and not parsed.yes:
        if not sys.stdin.isatty():
            parser.error(
                "--protocol all requires interactive confirmation. Pass -y/--yes "
                "to skip the prompt, or use --protocol auto for the same effect."
            )
            raise Failure
        sys.stderr.write(
            "--protocol all will hook TLS, QUIC, OHTTP, SSH, and IPsec libraries\n"
            "simultaneously. This may slow the target process, increase capture\n"
            "volume, and produce a mixed keylog and PCAPNG. Consider --protocol\n"
            "<one> for a focused capture. Continue? [y/N] "
        )
        sys.stderr.flush()
        answer = sys.stdin.readline().strip().lower()
        if answer not in ("y", "yes"):
            logger.info("Aborted by user.")
            raise Failure

    # --protocol ssh: the SSH agent lives only in the modern path. Force
    # use_modern=true so the user doesn't silently fall back to the legacy
    # TLS-only agent (which has no SSH support and would no-op SSH targets).
    if parsed.protocol == "ssh":
        if not getattr(parsed, "use_modern", False):
            logger.info("[ssh] --protocol ssh auto-enables use_modern=true (legacy path has no SSH support)")
            parsed.use_modern = True
        # sshd forks a pre-auth child for KEX and re-execs into sshd-session post-auth.
        # Frida hooks only follow forks when child-gating is on. Auto-enable when the
        # target name looks like an sshd binary.
        target = (getattr(parsed, "exec", "") or "")
        target_basename = target.rsplit("/", 1)[-1]
        if re.match(r"^sshd(-session)?$", target_basename) and not parsed.enable_child_gating:
            logger.info("[ssh] sshd target detected — enabling --enable_child_gating automatically")
            parsed.enable_child_gating = True

    # --protocol ipsec: the IPSec strongSwan executor is registered only on the
    # modern path. Force use_modern=true so the user doesn't silently fall back
    # to the legacy TLS-only agent (which would no-op strongSwan targets).
    if parsed.protocol == "ipsec":
        if not getattr(parsed, "use_modern", False):
            logger.info("[ipsec] --protocol ipsec auto-enables use_modern=true (legacy path has no IPSec support)")
            parsed.use_modern = True

    if parsed.use_modern:
        logger.warning(
            f"friTap modern hooks active (experimental). Known regressions vs legacy: "
            f"{_MODERN_REGRESSIONS}. Omit --modern to use the stable legacy path."
        )

    if parsed.full_capture and parsed.pcap is None:
        parser.error("--full_capture requires -p to set the pcap name")
        raise Failure

    if parsed.full_capture and parsed.keylog is None:
        logger.warning("Are you sure you want to proceed without recording the key material (-k <keys.log>)?")
        logger.warning("Without the key material, you have a complete network record, but no way to view the contents of the TLS traffic.")
        logger.info("Do you want to proceed without recording keys? : <press any key to proceed or Ctrl+C to abort>")
        input() 
    try:
        special_logger.info("Start logging")
        special_logger.info("Press Ctrl+C to stop logging")
        config = FriTapConfig.from_legacy_params(
            app=parsed.exec,
            pcap_name=parsed.pcap,
            verbose=parsed.verbose,
            spawn=parsed.spawn,
            keylog=parsed.keylog,
            enable_spawn_gating=parsed.enable_spawn_gating,
            spawn_gating_all=parsed.spawn_gating_all,
            enable_child_gating=parsed.enable_child_gating,
            mobile=parsed.mobile,
            live=parsed.live,
            environment_file=parsed.environment,
            debug_mode=parsed.debug,
            full_capture=parsed.full_capture,
            socket_trace=parsed.socket_tracing,
            host=parsed.host,
            offsets=parsed.offsets,
            debug_output=parsed.debugoutput,
            experimental=parsed.experimental,
            anti_root=parsed.anti_root,
            payload_modification=parsed.payload_modification,
            library_scan=parsed.library_scan,
            enable_default_fd=parsed.enable_default_fd,
            patterns=parsed.patterns,
            custom_hook_script=parsed.custom_script,
            json_output=parsed.json,
            install_lsass_hook=install_lsass_hook,
            timeout=parsed.timeout,
            backend=parsed.backend,
            protocol=parsed.protocol,
            proxy=parsed.proxy,
            filter_expression=getattr(parsed, 'filter', None),
            filter_infrastructure=getattr(parsed, 'filter_infrastructure', True),
            include_loopback=getattr(parsed, 'include_loopback', False),
            force_scan_modules=getattr(parsed, 'force_scan_modules', None),
        )

        # Validate filter expression early (before session starts)
        if config.output.filter_expression:
            from friTap.filter import FilterEngine
            err = FilterEngine.validate(config.output.filter_expression)
            if err:
                logger.error(f"Invalid filter expression: {err}")
                return

        ssl_log = SSL_Logger(config=config)

        # Propagate --protocol ssh's auto-enabled use_modern onto the logger so
        # the agent config_batch sees use_modern=true (legacy/ssl_logger_core.py
        # reads via getattr(self, 'use_modern', False)).
        if getattr(parsed, "use_modern", False):
            ssl_log.use_modern = True

        ssl_log.install_signal_handler()
        ssl_log.start_fritap_session()
        
        # Wait for user input or interrupt
        ssl_log.wait_for_completion()
            
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Cleaning up...")
        cleanup_lsass_hook()
        raise
    except SystemExit:
        cleanup_lsass_hook()
        raise
    except BackendTransportError as fe:
        logger.error(f"Backend transport error: {fe}")
    except FridaBasedException as e:
        logger.error(f"Backend error: {e}")
    except BackendTimedOutError as te:
        logger.error(f"TimeOutError: {te}")
    except BackendProcessNotFoundError as pe:
        logger.error(f"ProcessNotFoundError: {pe}")
    except BackendPermissionDeniedError as e:
        logger.error(f"Permission denied: {e}")
    except BackendNotRunningError as e:
        logger.error(f"Backend server is not running: {e}")
    except BackendInvalidArgumentError as e:
        logger.error(f"Invalid argument: {e}")
        if "device not found" in str(e):
            logger.error("Unable to identify the target device.")
            logger.error("If you have multiple devices connected, please specify the device ID using the `-m` option:")
            logger.error("\t1. Identify the target device ID (e.g., using `adb devices`).")
            logger.error("\t2. Run FriTap with the device ID:")
            logger.error("\t   fritap -m <device-id> <target>")
    except BackendInvalidOperationError as e:
        logger.error(f"Invalid operation: {e}")
    except UnsupportedProtocolBackendError as e:
        logger.error(f"Unsupported protocol-backend combination: {e}")
    except Exception as ar:
        ex_type, ex_value, ex_traceback = sys.exc_info()
        trace_back = traceback.extract_tb(ex_traceback)
        stack_trace = [
            "File : %s , Line : %d, Func.Name : %s, Message : %s" % (trace[0], trace[1], trace[2], trace[3])
            for trace in trace_back
        ]
        
        if parsed.debug or parsed.debugoutput:
            if "NotSupportedError" in ex_type.__name__:
                logger.error("Backend error:")
            logger.error("Exception type : %s " % ex_type.__name__)
            logger.error("Exception message : %s" %ex_value)
            logger.error("Stack trace : %s" %stack_trace)


        if "unable to connect to remote frida-server: closed" in str(ar):
            logger.error("Backend server is not running on remote device. Please start it and rerun.")
            
        if "NotSupportedError" in ex_type.__name__:
            logger.error(f"Backend error: {ex_value}")
        else:
            logger.error(f"Unknown error: {ex_value}")

        if "unable to access process with pid" in str(ex_value).lower():
            raise Success(special_logger)
        if "not yet supported on this os" in str(ex_value).lower():
            logger.error("This feature is currently not supported on this OS.")
            raise Success(special_logger)

        return

    else:
        # normal end, no error
        return
    finally:
        if 'ssl_log' in locals() and isinstance(ssl_log, SSL_Logger):
            ssl_log.pcap_cleanup(parsed.full_capture,parsed.mobile,parsed.pcap)
            ssl_log.cleanup(parsed.live,parsed.socket_tracing,parsed.full_capture,parsed.debug,parsed.debugoutput)
    
    # only reached when error
    raise Failure

def main():
    # Handle sub-commands before argparse
    if len(sys.argv) >= 3 and sys.argv[1] == "install-backend":
        if sys.argv[2] == "wireshark":
            from .commands.install_backend import install_wireshark_extcap
            install_wireshark_extcap()
            return
        else:
            print(f"Unknown backend: {sys.argv[2]}. Available: wireshark")
            return

    # Replay mode: fritap -r capture.tap  or  fritap capture.tap
    replay_file = None
    if len(sys.argv) >= 2 and sys.argv[1] in ("-r", "--replay"):
        if len(sys.argv) < 3:
            print("Usage: fritap -r <capture.tap>")
            return
        replay_file = sys.argv[2]
    elif len(sys.argv) == 2 and sys.argv[1].endswith(".tap"):
        replay_file = sys.argv[1]

    if replay_file is not None:
        try:
            from .tui.app import run_tui
            run_tui(replay_file=replay_file)
        except ImportError:
            logging.getLogger('friTap').error(
                "Textual TUI is not available. Please install the 'textual' package."
            )
        return

    # When invoked with no arguments, launch the interactive TUI
    if len(sys.argv) == 1:
        try:
            from .tui.app import run_tui
            run_tui()
            return
        except ImportError:
            logging.getLogger('friTap').error(
                "Textual TUI is not available. Please install the 'textual' package to use the interactive interface."
            )
            # fall through to CLI help

    try:
        cli()
    except FriTapExit as e:
        e.exit()


if __name__ == "__main__":
    main()
