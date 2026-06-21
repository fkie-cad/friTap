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


def _repair_shadowed_package_path():
    """Heal ``friTap.__path__`` when a stale install shadows the real source.

    A leftover ``site-packages/friTap`` directory (e.g. from a previous
    non-editable ``pip install .``) has no ``__init__.py``, so Python resolves
    ``friTap`` as a *namespace package* whose ``__path__`` points only at that
    stale directory. Subpackages such as ``friTap.tui`` then resolve into the
    empty stale tree, breaking the TUI with ``No module named 'friTap.tui.app'``.

    This module always loads from the real source tree, so ``__file__`` gives
    the correct package directory. We force ``friTap.__path__`` to it and drop
    any submodules already cached from the wrong location. The function is a
    no-op when the path is already correct, so it is safe to call eagerly.
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
        description="Decrypts and logs an executables or mobile applications encrypted traffic.",
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
    args.add_argument("--quic-capture-mode", required=False,
                      choices=["stream", "app-api"], default="stream",
                      dest="quic_capture_mode",
                      help="Select the QUIC plaintext capture boundary. "
                           "'stream' (default) uses the current lower-boundary "
                           "stream-level hooks (QuicStream/QuicStreamSequencer "
                           "Readv). 'app-api' captures at the application-API "
                           "Boundary-4 with decoded HTTP/3 headers "
                           "(Chrome/Android Google QUICHE only).")
    args.add_argument("--scan-keys-region", required=False, default=None,
                      metavar="<module|base,size|heap>", dest="scan_keys_region",
                      help="Scan a memory region for cryptographic key material "
                           "with the generic key-scan engine and emit ranked, "
                           "anonymous candidates to the keylog (requires -k). "
                           "Value is a module name, an explicit '0xADDR,SIZE' "
                           "region, or 'heap' (all writable ranges).")
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
    from friTap.protocols.registry import available_protocol_names
    args.add_argument("--protocol", type=str, default="tls",
                      choices=available_protocol_names() + ["all", "auto"],
                      help="Protocol to intercept (default: tls). "
                           "'tls' covers the TLS family — TLS, QUIC, and OHTTP. "
                           "'ssh', 'ipsec' and 'mtproto' (Telegram) are exclusive (only their hooks install). "
                           "'telegram' extracts MTProto cloud-chat keys AND Secret-Chat E2E keys into one keylog. "
                           "Some protocols are TLS-wrapped and additionally extract TLS keys; their -k "
                           "keylog is then split into <stem>.<proto><ext> + <stem>.tls<ext>. "
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

    # Telegram MTProto lives only in the modern agent (no legacy hooks exist).
    if parsed.protocol == "mtproto":
        if not getattr(parsed, "use_modern", False):
            logger.info("[mtproto] --protocol mtproto auto-enables use_modern=true (legacy path has no MTProto support)")
            parsed.use_modern = True
        # MTProto's obfuscated transport can only be decrypted offline when each
        # TCP stream is captured from its first 64 bytes. Attaching to an already
        # running Telegram misses that init block on connections opened earlier
        # (they come back "degraded" and decrypt to nothing), so nudge toward spawn.
        if not getattr(parsed, "spawn", False):
            logger.info(
                "[mtproto] attach mode: connections opened before capture can't be "
                "decrypted (obfuscated-transport init bytes are missed). Use -s (spawn) "
                "so every connection is captured from the start, or force-stop + relaunch "
                "the app before attaching."
            )
        # Live capture only needs to extract keys/plaintext (no Python-side crypto),
        # but offline decryption of the resulting pcap does. Nudge the user early so
        # a later `--mtproto-keylog` run does not surprise them.
        from friTap.offline.mtproto import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[mtproto] %s  (live key capture works without it; that backend is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )

    # Telegram (combined MTProto cloud + Secret-Chat E2E) lives only in the
    # modern agent. Both key kinds land in ONE combined keylog file.
    if parsed.protocol == "telegram":
        if not getattr(parsed, "use_modern", False):
            logger.info("[telegram] --protocol telegram auto-enables use_modern=true (legacy path has no Telegram support)")
            parsed.use_modern = True
        # Same byte-0 caveat as mtproto (cloud transport is the obfuscated MTProto):
        # attaching to a running Telegram misses the init block on already-open
        # connections, so those streams can't be decrypted offline. Nudge to spawn.
        if not getattr(parsed, "spawn", False):
            logger.info(
                "[telegram] attach mode: connections opened before capture can't be "
                "decrypted (obfuscated-transport init bytes are missed). Use -s (spawn) "
                "so every connection is captured from the start, or force-stop + relaunch "
                "the app before attaching."
            )
        # Require an explicit capture intent: -k extracts the combined Telegram
        # keys for offline decrypt, -p captures live plaintext, -f captures a raw
        # pcap for offline decrypt. Bare `--protocol telegram` would install hooks
        # that produce no output, so reject it with an actionable message.
        if not (parsed.keylog or parsed.pcap or parsed.full_capture):
            parser.error(
                "--protocol telegram requires a capture intent: -k (extract the "
                "combined MTProto cloud + Secret-Chat E2E keys for offline "
                "decryption) and/or -p (capture live plaintext); -f -p -k captures "
                "a raw pcap plus keys for offline decryption."
            )
            raise Failure
        # Live capture only extracts keys/plaintext (no Python-side crypto), but
        # offline decryption of the resulting pcap does. Nudge the user early so
        # a later `--telegram-keylog` run does not surprise them.
        from friTap.offline.mtproto import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[telegram] %s  (live key capture works without it; the extra is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )

    # Let the selected protocol's handler validate/adjust CLI intent. This keeps
    # protocol-specific rules (e.g. a TLS-wrapped E2E protocol that needs a
    # capture intent and the modern agent path) with the handler, out of the
    # generic parser and out of the public core. Meta values ('all'/'auto') and
    # unknown names have no single handler -> skipped.
    from friTap.protocols.registry import available_protocol_names, create_default_registry
    if parsed.protocol in available_protocol_names():
        try:
            _selected_handler = create_default_registry([parsed.protocol]).get(parsed.protocol)
        except Exception:
            _selected_handler = None
        if _selected_handler is not None:
            _selected_handler.validate_cli_intent(parsed, parser, logger)

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
    # Chrome's network service runs in a child process on modern Android builds,
    # so attaching to the browser process and hoping to see HTTP/3 page traffic
    # is a frequent footgun: the socket observer fires for the browser process's
    # own infra UDP (DoH/sync/Safe-Browsing) but QuicSpdyStream::WriteHeaders
    # never fires because the streams live in the subprocess. Surface a hint so
    # the user knows the right flags BEFORE they spend 10 minutes producing an
    # empty pcap. Heuristic: target name matches a known Chrome-family package,
    # we're in mobile mode, and the user did NOT pass --enable_child_gating.
    _CHROME_FAMILY_TARGETS = {
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "org.chromium.chrome",
        "Chrome",  # the friendly name Frida resolves on Android
    }
    target = (parsed.exec or "").strip()
    # Only surface the subprocess hint when the user actually opted into QUIC
    # capture (--quic-capture-mode app-api). Keylog-only Chrome captures
    # (e.g. `fritap -m <serial> -k logs.log Chrome`) work fine against the
    # browser process and don't need the subprocess warning — it would just
    # be noise that hides the real startup output.
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
            quic_capture_mode=getattr(parsed, 'quic_capture_mode', 'stream'),
            quic_only=getattr(parsed, 'quic_only', False),
            quic_egress_headers_layer=getattr(parsed, 'quic_egress_headers_layer', 'auto'),
            scan_keys_region=getattr(parsed, 'scan_keys_region', None),
            scan=getattr(parsed, 'scan', None),
            scan_report=getattr(parsed, 'scan_report', 'table'),
            scan_report_out=getattr(parsed, 'scan_report_out', None),
            scan_min_severity=getattr(parsed, 'scan_min_severity', 'info'),
            scan_min_confidence=getattr(parsed, 'scan_min_confidence', 0.0),
            scan_source=getattr(parsed, 'scan_source', None),
            scan_category=getattr(parsed, 'scan_category', None),
            scan_show_pii=getattr(parsed, 'scan_show_pii', False),
            scan_analyzer_path=getattr(parsed, 'scan_analyzer_path', None),
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
        # A transport error mid-session almost always means the target process
        # died (often a native crash inside a hook). If on_detach already
        # attributed it (process-terminated → clear crash message), don't repeat
        # the cryptic line; otherwise add a hint so the user isn't left guessing.
        _ssl_log = locals().get("ssl_log")
        if getattr(_ssl_log, "_crash_reported", False):
            pass  # already reported clearly by on_detach
        else:
            logger.error(f"Backend transport error: {fe}")
            crumb = getattr(_ssl_log, "_last_hook_breadcrumb", "")
            hint = "The target process appears to have terminated unexpectedly"
            if crumb:
                hint += f" (last hook entered: {crumb})"
            hint += " — it may have crashed inside an instrumented hook. Check the debug log."
            logger.error(hint)
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

def _looks_like_tap_input(token):
    """Return True when ``token`` looks like a ``.tap`` capture file argument.

    Used to disambiguate the bare ``analyze`` mode from a capture target that
    happens to be named ``analyze`` (see :func:`_dispatch_special_mode`).
    A token is treated as a ``.tap`` input only if it is a non-flag argument
    ending in ``.tap``.
    """
    return bool(token) and not token.startswith("-") and token.endswith(".tap")


def _looks_like_pcap_input(token):
    """Return True when ``token`` looks like a pcap/pcapng capture file argument.

    Used by :func:`_dispatch_special_mode` to route ``fritap -r capture.pcap``
    (and the bare trailing-path form) into the guided pcap-to-tap wizard rather
    than the ``.tap`` replay path. A token qualifies only if it is a non-flag
    argument ending in ``.pcap`` or ``.pcapng``.
    """
    return bool(token) and not token.startswith("-") and (
        token.endswith(".pcap") or token.endswith(".pcapng")
    )


def _dispatch_special_mode(argv):
    """Resolve the pre-argparse "special mode" from a raw ``argv`` list.

    friTap accepts a handful of leading positional/flag forms that must be
    handled *before* the normal capture argparse parser sees them. This helper
    centralizes that fragile chain in one readable, testable place. ``argv`` is
    the full process argument vector (i.e. ``sys.argv``); element 0 is the
    program name, so dispatch inspects ``argv[1]`` onward.

    Returns a ``(mode, payload)`` tuple where ``mode`` is one of:

    * ``"list-analyzers"``  — ``fritap --list-analyzers``: print the available
      analyzers (built-in + discovered externals) and exit. ``payload`` is
      ``None``; needs no target.
    * ``"install-backend"`` — ``fritap install-backend <name>``: install an
      external integration (currently only the Wireshark extcap). ``payload``
      is the backend name (``argv[2]``).
    * ``"from-pcap"``       — ``fritap --from-pcap capture.pcapng [...]``:
      offline decryption of an encrypted pcap into a ``.tap`` file. ``payload``
      is ``argv[1:]`` (forwarded verbatim to the offline CLI).
    * ``"analyze"``         — ``fritap --analyze ...`` or ``fritap analyze
      capture.tap``: passive offline analysis of an existing ``.tap``. ``payload``
      is the argument list after the mode token (``argv[2:]``).
    * ``"replay"``          — ``fritap -r capture.tap``, ``fritap --replay
      capture.tap`` or ``fritap capture.tap``: open the capture in the TUI.
      ``payload`` is the ``.tap`` path, or ``None`` when ``-r`` was given
      without a file (caller prints usage).
    * ``"pcap-wizard"``     — ``fritap -r capture.pcap``, ``fritap --replay
      capture.pcapng`` or ``fritap capture.pcap``: launch the guided pcap-to-tap
      wizard (confirm input, choose output ``.tap``, supply TLS + per-protocol
      keylogs, convert, then open the result in the replay TUI). ``payload`` is
      the pcap/pcapng path.
    * ``None``              — no special mode; fall through to normal capture.

    Disambiguation rule for the bare ``analyze`` subcommand: ``analyze`` is only
    treated as the analyze subcommand when the *next* token looks like a ``.tap``
    input (``_looks_like_tap_input``). This mirrors the explicit ``--analyze``
    flag (which is always the analyze mode) while ensuring that capturing a
    process literally named ``analyze`` — e.g. ``fritap analyze`` or
    ``fritap analyze -m`` — is *not* hijacked and falls through to capture.
    """
    # --list-analyzers: informational mode that needs no target. May appear
    # anywhere in the argument list (mirrors --from-pcap detection).
    if len(argv) >= 2 and "--list-analyzers" in argv[1:]:
        return ("list-analyzers", None)

    # install-backend: requires a following backend name.
    if len(argv) >= 3 and argv[1] == "install-backend":
        return ("install-backend", argv[2])

    # --from-pcap may appear anywhere in the argument list.
    if len(argv) >= 2 and "--from-pcap" in argv:
        return ("from-pcap", argv[1:])

    # Analyze: explicit --analyze always wins; bare 'analyze' only when it is
    # followed by a .tap input, so a target named 'analyze' is not hijacked.
    if len(argv) >= 2 and argv[1] == "--analyze":
        return ("analyze", argv[2:])
    if (len(argv) >= 3 and argv[1] == "analyze"
            and _looks_like_tap_input(argv[2])):
        return ("analyze", argv[2:])

    # Replay / pcap-wizard: -r/--replay <file>, or a single trailing path.
    # A .pcap/.pcapng input opens the guided pcap-to-tap wizard (convert +
    # replay); a .tap input opens the replay TUI directly.
    if len(argv) >= 2 and argv[1] in ("-r", "--replay"):
        target = argv[2] if len(argv) >= 3 else None
        if _looks_like_pcap_input(target):
            return ("pcap-wizard", target)
        return ("replay", target)
    if len(argv) == 2 and _looks_like_pcap_input(argv[1]):
        return ("pcap-wizard", argv[1])
    if len(argv) == 2 and argv[1].endswith(".tap"):
        return ("replay", argv[1])

    return None


def main():
    # Handle sub-commands before argparse via the centralized dispatcher.
    mode = _dispatch_special_mode(sys.argv)

    if mode is not None:
        kind, payload = mode

        if kind == "install-backend":
            if payload == "wireshark":
                from .commands.install_backend import install_wireshark_extcap
                install_wireshark_extcap()
                return
            print(f"Unknown backend: {payload}. Available: wireshark")
            return

        if kind == "from-pcap":
            from .offline.cli import run_offline_pcap_to_tap
            return run_offline_pcap_to_tap(payload)

        if kind == "list-analyzers":
            from .commands.analyze import (
                _format_analyzer_listing,
                list_analyzers_detailed,
            )
            print(_format_analyzer_listing(list_analyzers_detailed()))
            return

        if kind == "analyze":
            from .commands.analyze import run_analyze_cli
            return run_analyze_cli(payload)

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
        e.exit()


if __name__ == "__main__":
    main()
