#!/usr/bin/env python3

import argparse
import atexit
import logging
import re
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
from .config import FriTapConfig, UnsupportedProtocolBackendError
from .fritap_utility import (
    Failure,
    FriTapExit,
    Success,
    are_we_running_on_windows,
    get_pid_of_lsass,
    setup_fritap_logging,
)
from .inspector import LibraryInspector
from .ssl_logger import SSL_Logger


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


# Targets with no native modern implementation yet: under --modern the agent runs
# the proven legacy hooks for these, so both paths behave the same there.
_MODERN_LEGACY_DELEGATED = "iOS/macOS Cronet, Windows LSASS"


def _build_lsass_config(pid_of_lsass, *, pcap_name, verbose, keylog, live, debug_mode,
                        host, debug_output, enable_default_fd, patterns,
                        custom_hook_script, json_output, full_capture):
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
        install_lsass_hook=True
    )
    config.output.auxiliary_session = True
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
                        json_output=None, full_capture=False):
        """Start LSASS hooking in a background thread.

        ``full_capture`` is the TARGET session's -f mode: that session alone owns
        the -p file (sniffer, finalize, manifest), so the LSASS session then gets
        no pcap at all and only contributes keys.
        """

        # LSASS is a Windows service; hooking it off Windows is never valid.
        # Guard here as well as at the call sites so a direct call is a clear
        # no-op (never an attempt) regardless of how it was reached.
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
                # Create SSL_Logger instance for LSASS
                config = _build_lsass_config(
                    pid_of_lsass, pcap_name=pcap_name, verbose=verbose, keylog=keylog,
                    live=live, debug_mode=debug_mode, host=host, debug_output=debug_output,
                    enable_default_fd=enable_default_fd, patterns=patterns,
                    custom_hook_script=custom_hook_script, json_output=json_output,
                    full_capture=full_capture)
                self.lsass_logger = SSL_Logger(config=config)
                
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
            # The worker may have ended on its own (lsass session detached);
            # its output handlers are still open and must be released too.
            self._close_lsass_output_handlers()
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

        # Release the shared -k keylog handle (and any other outputs): nothing
        # else closes them before the process os._exit()s, and the SChannel
        # auto-relabel cannot rename a keylog that is still open on Windows.
        self._close_lsass_output_handlers()

        # Wait for thread to finish (with timeout)
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

# Global LSASS hook manager instance
_lsass_hook_manager = LsassHookManager()

def hook_lsass(pcap_name=None, verbose=False, keylog=False, live=False, debug_mode=False, 
               host=False, debug_output=False, enable_default_fd=False, patterns=None, 
               custom_hook_script=None, json_output=None, full_capture=False):
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
        full_capture=full_capture
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



def _format_seconds(seconds):
    """Render a duration without rounding a sub-second value away to "0.0s".

    A bound of "0.0s" would read as *disabled* (which is what 0 means for
    --script-load-timeout), so a diagnostic must never print it for a bound
    that actually fired.
    """
    return f"{seconds:.3f}s" if 0 < seconds < 1 else f"{seconds:.1f}s"


def _script_load_timeout_hints(elapsed_seconds, breadcrumb, timeout):
    """Return the user-facing message lines for a script-load timeout.

    Pure so the wording stays testable: the caller only logs the lines.
    ``breadcrumb`` is the agent's last reported stage (may be empty) and it is
    the single most useful signal about *where* the load wedged.
    """
    # The bound is optional: effective_script_load_timeout() returns None when
    # the user disabled it, and the breadcrumb may not have arrived at all.
    bound = f" (bound: {_format_seconds(timeout)})" if timeout else ""
    breadcrumb = breadcrumb or ""
    lines = [
        f"Agent did not finish loading within {_format_seconds(elapsed_seconds)}{bound}.",
    ]
    # Match the breadcrumb verdicts used by SSL_Logger's crash reporting so
    # both places tell the user the same story about the same marker.
    if breadcrumb.startswith("agent-init"):
        lines.append(
            f"  The agent died before any hook was installed "
            f"(last agent stage: {breadcrumb})."
        )
    elif breadcrumb.startswith("install-phase"):
        lines.append(
            f"  The agent died while installing hooks "
            f"(last agent stage: {breadcrumb})."
        )
    elif breadcrumb:
        lines.append(f"  Last agent stage: {breadcrumb}.")
    else:
        lines.append("  The agent never reported a startup stage.")
    lines.append(
        "  -> Rebuild the agent bundle with ./dev/compile_agent.sh — a stale or "
        "partially-built bundle is a common cause."
    )
    lines.append(
        "  -> Re-run with --probe (if available) to isolate the failing agent stage."
    )
    lines.append(
        "  -> Raise the bound with --script-load-timeout <seconds>, or pass "
        "--script-load-timeout 0 to disable it."
    )
    return lines


def _process_not_responding_hints(message, spawn):
    """Return the user-facing message lines for a not-responding target.

    Pure so the wording stays testable: the caller only logs the lines.
    """
    lines = [f"Target process is not responding: {message}"]
    lines.append(
        "  The target did not complete the agent-injection handshake in time."
    )
    if spawn:
        lines.append(
            "  -> Spawn-time injection stalls on targets that do heavy work (or "
            "an integrity check) at startup. Start the app yourself, then ATTACH "
            "friTap (run WITHOUT -s)."
        )
    else:
        lines.append(
            "  -> The process may be suspended, stopped in a debugger, or wedged "
            "in a syscall. Verify it is running and responsive, then retry."
        )
    lines.append(
        "  -> Also confirm the backend server version matches the friTap client."
    )
    return lines


# Capture-output flags that produce nothing in probe mode, paired with the
# spelling the user typed so the warning quotes their own command line back.
_PROBE_IGNORED_CAPTURE_FLAGS = (
    ("keylog", "-k/--keylog"),
    ("pcap", "-p/--pcap"),
    ("full_capture", "-f/--full_capture"),
    ("live", "--live"),
    ("json", "-j/--json"),
)


def _probe_conflict_warnings(parsed):
    """Return the warning lines for capture flags that do nothing under --probe.

    Pure so the wording stays testable: the caller only logs the lines.

    Warn, never error: --probe is meant to be added to the exact command line
    the user is already debugging, so rejecting that command line would defeat
    the purpose. The agent installs no hooks in probe mode, though, so every
    output flag would only create an empty file — say so once, up front.
    """
    if not getattr(parsed, "probe", False):
        return []
    ignored = [
        label for attr, label in _PROBE_IGNORED_CAPTURE_FLAGS
        if getattr(parsed, attr, None)
    ]
    if not ignored:
        return []
    return [
        "--probe is a dry run: friTap installs no hooks, so these flags produce "
        "no data and are ignored: " + ", ".join(ignored) + ".",
        "  -> Re-run the same command without --probe once the probe report looks healthy.",
    ]


def _confirm_full_capture_without_keylog(parsed, logger):
    """Handle ``-f`` without ``-k``: ask before capturing with no key material.

    With ``-ms`` the heap scanner records the keys into its own keylog, so the
    capture is decryptable and the blocking prompt is skipped.
    """
    if getattr(parsed, "memory_scan", False):
        logger.info("Full capture without -k: key material will be recorded by the memory scanner (-ms).")
        return
    logger.warning("Are you sure you want to proceed without recording the key material (-k <keys.log>)?")
    logger.warning("Without the key material, you have a complete network record, but no way to view the contents of the TLS traffic.")
    logger.info("Do you want to proceed without recording keys? : <press any key to proceed or Ctrl+C to abort>")
    input()


def _normalize_protocol_selection(raw, parser, valid_names):
    """Normalize and validate the multi-select ``--protocol`` values.

    *raw* is what argparse's ``action="append"`` produced: ``None`` (flag never
    given) or a list of strings, each of which may itself be comma-separated
    (``["tls,rc4", "ssh"]``). Returns an ordered, de-duplicated list of protocol
    names. The default (flag absent, or only empty tokens) collapses to
    ``["tls"]`` so the common single-protocol case is unchanged.

    Validation (all via ``parser.error`` for a clean CLI message):
      * every token must be a known protocol name or a meta value (all/auto);
      * ``all``/``auto`` are standalone meta-values — never combined with a
        named protocol;
      * ``ssh``/``ipsec``/``mtproto`` are exclusive — never combined with any
        other *non-custom* protocol (only their own hooks install);
      * ``custom`` expands to every registered custom cipher (category
        ``custom_cipher``, e.g. rc4). Custom ciphers combine with anything
        except ``all``/``auto`` — including the exclusive protocols — and are
        ordered after the non-custom protocols so ``protocols[0]`` stays the
        primary protocol.
    """
    from friTap.protocols.registry import (
        CUSTOM_GROUP,
        custom_cipher_handlers,
        expand_custom_group,
        order_protocol_selection,
    )
    META = ("all", "auto")
    EXCLUSIVE = ("ssh", "ipsec", "mtproto")
    if not raw:
        return ["tls"]
    tokens = []
    for item in raw:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                tokens.append(part)
    if not tokens:
        return ["tls"]
    known = set(valid_names) | set(META) | {CUSTOM_GROUP}
    unknown = [t for t in tokens if t not in known]
    if unknown:
        parser.error(
            "--protocol: unknown protocol(s): " + ", ".join(unknown) + "; "
            "choose from " + ", ".join(list(valid_names) + list(META) + [CUSTOM_GROUP])
        )
    # Every custom cipher (incl. upcoming ones selectable by explicit name)
    # classifies tokens; only the announced ones expand the `custom` group.
    cipher_handlers = custom_cipher_handlers(include_upcoming=True)
    all_cipher_names = [h.name for h in cipher_handlers]
    custom_ciphers = set(all_cipher_names)
    if CUSTOM_GROUP in tokens:
        group_names = [h.name for h in cipher_handlers if not getattr(h, "upcoming", False)]
        if not group_names:
            parser.error("--protocol custom: no custom ciphers available in this build")
        # Expand `custom` in place, then de-duplicate (order-preserving).
        selection = expand_custom_group(tokens, group_names)
    else:
        selection = list(dict.fromkeys(tokens))
    if len(selection) > 1:
        metas = [t for t in selection if t in META]
        if metas:
            parser.error(
                f"--protocol: '{metas[0]}' is a standalone meta-value and cannot "
                "be combined with other protocols."
            )
        # Custom ciphers ride along with any protocol, so exclusivity is only
        # checked among the non-custom (main) protocols.
        main_protocols = [t for t in selection if t not in custom_ciphers]
        exclusives = [t for t in main_protocols if t in EXCLUSIVE]
        if exclusives and len(main_protocols) > 1:
            parser.error(
                f"--protocol: '{exclusives[0]}' is exclusive and cannot be "
                "combined with other protocols."
            )
    # Keep the main protocol first: protocols[0] is the primary protocol.
    return order_protocol_selection(selection, all_cipher_names)


def _make_inspection_config(parsed):
    """Build the FriTapConfig the library-inspection commands run against.

    Only the flags that influence *finding* the target and its modules matter
    here -- no output/capture flags -- because ``-ll`` and
    ``--extract-libraries`` never start a capture session.
    """
    return FriTapConfig.from_legacy_params(
        app=parsed.exec, verbose=parsed.verbose, spawn=parsed.spawn,
        mobile=parsed.mobile, environment_file=parsed.environment,
        debug_mode=parsed.debug, host=parsed.host, offsets=parsed.offsets,
        debug_output=parsed.debug_output, experimental=parsed.experimental,
        anti_root=parsed.anti_root, enable_default_fd=parsed.enable_default_fd,
        patterns=parsed.patterns, custom_hook_script=parsed.custom_script,
        backend=parsed.backend,
    )


def _run_early_exit_command(label, action_fn, logger, special_logger):
    """Run a "print something and exit" command, then leave ``cli()`` for good.

    Lives at module scope on purpose. It used to be a nested helper inside
    :func:`cli`, where its success path was a bare ``return`` -- which returned
    from the *helper*, not from ``cli()``. ``fritap -ll <target>`` therefore
    printed its library listing and then fell straight through into a full
    capture session that blocks forever in ``wait_for_completion()``, despite
    the flag's promise not to start logging.

    Every path out of this function raises a :class:`FriTapExit` (``Success``
    on a clean listing, ``Failure`` otherwise). It must never ``return``.
    """
    logger.info(label)
    try:
        result = action_fn()
    except FriTapExit:
        # A controlled exit is not an error -- let it through untouched rather
        # than have `except Exception` below rewrite it as "An error occurred".
        raise
    except BackendTransportError as fe:
        logger.error(f"Backend transport error: {fe}")
    except FridaBasedException as e:
        logger.error(f"Backend error: {e}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    else:
        # Everything below MUST stay in the else: clause. Success/Failure
        # subclass Exception, so raising them inside the try: body would be
        # swallowed by our own `except Exception` above and re-reported as
        # "An error occurred: ".
        special_logger.info(result)
        # The inspectors report failure in their return value rather than by
        # raising, so a scan that failed still has to exit non-zero.
        if LibraryInspector.is_error(result):
            raise Failure
        # Keyword, not positional: FriTapExit.__init__(self, info=None,
        # logger=None, ...) takes *info* first, so raise Success(special_logger)
        # would print the Logger's repr instead of the goodbye banner.
        raise Success(logger=special_logger)
    # Only reached after one of the except clauses above logged the cause.
    raise Failure


def _reject_invalid_headless_filter(filter_expression, logger):
    """Exit with :class:`Failure` (code 2) when ``--filter`` cannot be used headless.

    ``cli()`` calls this after the ``-ll``/``--extract-libraries`` early-exit
    commands (which ignore ``--filter``) and before the capture banners, the
    LSASS hook, device lookup or spawning. The check used to sit inside the
    capture ``try:`` after "Start logging" had been printed, and its bare
    ``return`` fell out of ``cli()`` with exit status 0, so a rejected filter
    looked like a successful (empty) run to wrapper scripts.

    Only the headless CLI reaches this: the TUI is launched without ``--filter``
    and builds flows, so it accepts the full filter engine (``telegram``,
    ``http.host`` ...). ``headless_filter_error`` is therefore applied here only.
    """
    if not filter_expression:
        return
    from friTap.filter.pipeline_filter import headless_filter_error
    err = headless_filter_error(filter_expression)
    if err:
        raise Failure(info=err, logger=logger)


class ArgParser(argparse.ArgumentParser):
    """Argument parser that prints the full help on a usage error.

    The help text stays on stdout (a lot of tooling greps it), but the exit
    code is 2 -- the value documented in docs/api/cli.md for "invalid
    arguments/configuration" -- so wrapper scripts and CI jobs can actually
    detect a bad command line. ``fritap --help`` is served by the explicit
    ``-h/--help`` action registered in :func:`cli`, not by this method.
    """

    def error(self, message):
        print("friTap v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(2)


def _hex_text_or_none(data):
    """*data* as lowercase hex when it is hex text (whitespace ignored), else None."""
    try:
        text = "".join(data.decode("ascii").split())
    except UnicodeDecodeError:
        return None
    if not text or len(text) % 2:
        return None
    try:
        bytes.fromhex(text)
    except ValueError:
        return None
    return text.lower()


def _resolve_ms_rc4_ciphertext(value):
    """Resolve the ``--ms-rc4-ciphertext`` argument into a string.

    A leading ``@`` means the rest is a path whose contents are the sample. The
    file is read as BYTES: contents that are hex text (whitespace/newlines
    ignored) are used as that hex, anything else is the raw ciphertext and is
    hex-encoded byte for byte (a text decode would corrupt binary samples).
    Any other value is returned unchanged -- inline hex/plain-text
    normalisation stays in ``loader.apply_rc4_param_overrides`` so the CLI and
    config paths agree. ``None`` stays ``None``.

    Raises ``ValueError`` with a user-facing message when the file is missing,
    unreadable or empty.
    """
    if not value or not isinstance(value, str) or not value.startswith("@"):
        return value
    path = value[1:]
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise ValueError(
            f"--ms-rc4-ciphertext: cannot read '{path}': {exc.strerror or exc}"
        ) from exc
    if not data:
        raise ValueError(f"--ms-rc4-ciphertext: file '{path}' is empty")
    return _hex_text_or_none(data) or data.hex()


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
    args.add_argument("-do", "--debug-output", required=False, action="store_const", const=True,
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
    args.add_argument('--version', action='version',version=f'friTap v{__version__}')
    # The parser is built with add_help=False, so the help action has to be
    # registered explicitly. Without it, `fritap --help` would only "work" as a
    # side effect of error() printing the help text -- and error() must exit 2
    # so that wrappers and CI can detect a bad command line.
    args.add_argument("-h", "--help", action="help",
                      help="Show this help message and exit.")
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes matching the target app (useful for Android multi-process apps)")
    args.add_argument("--spawn_gating_all", required=False, action="store_const", const=True,
                      help="Catch ALL newly spawned processes without filtering (use with caution)")
    args.add_argument("--enable_child_gating", required=False, action="store_const", const=True,
                      help="Intercept child processes spawned by the target application")
    args.add_argument("exec", metavar="<executable/app name/pid>", nargs="+",
                      help="executable/app whose SSL calls to log. Accepts a "
                           "command with arguments for spawn mode, e.g. "
                           "'wine /path/to/application.exe' (issue #66).")
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
                           "keys are written to '<target>_memscan.keylog'; combined with "
                           "-k it shares that keylog, and with -p/-c it runs alongside "
                           "them. Which scan engine(s) run is derived from --protocol "
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
    from friTap.protocols.registry import (
        CUSTOM_GROUP,
        available_protocol_names,
        custom_cipher_names,
    )
    # --protocol is MULTI-SELECT (Foundation F1): repeatable and/or
    # comma-separated, so `--protocol tls,rc4` and `--protocol tls --protocol rc4`
    # both select TLS AND a companion protocol (each active and independent).
    # Values are normalized (split on commas, de-duplicated, order-preserving)
    # and validated after parsing in _normalize_protocol_selection(); the default
    # collapses to ["tls"], identical to the historical single-value behaviour.
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
    parsed = parser.parse_args()

    # The target positional now captures one-or-more tokens (nargs="+") so a
    # spawn command with arguments parses, e.g. `wine /path/app.exe` (issue #66).
    # Keep the original token list as parsed.exec_argv so spawn can pass the real
    # argv to device.spawn() (preserving paths that contain spaces, e.g.
    # ".../Program Files/app.exe"), and collapse parsed.exec to the single
    # space-joined string the rest of friTap expects for attach-by-name/display.
    if isinstance(parsed.exec, list):
        parsed.exec_argv = list(parsed.exec)
        parsed.exec = " ".join(parsed.exec)
    else:
        parsed.exec_argv = None

    # Foundation F1 — multi-protocol selection. Normalize/validate the repeatable,
    # comma-separated --protocol values into an ordered, de-duplicated list.
    # `parsed.protocols` is the canonical selection; `parsed.protocol` is kept as
    # the primary (first) element so the single-value branches and config threading
    # below keep working unchanged.
    from friTap.protocols.registry import available_protocol_names as _avail_names
    parsed.protocols = _normalize_protocol_selection(
        parsed.protocol, parser, _avail_names()
    )
    parsed.protocol = parsed.protocols[0]

    # Configure logging after parsing arguments to respect debug flags
    logger, special_logger = setup_fritap_logging(
        debug=parsed.debug, debug_output=parsed.debug_output
    )

    # Bring up the debug-log file subsystem when the user asked for one,
    # either explicitly via --debug-log or implicitly via --debug-output.
    # Done immediately after console-logging is configured so init-time
    # errors below this line land in the file. The TUI entry point
    # (run_tui) calls prime_debug_log too — both call sites are idempotent.
    debug_log_path_override = getattr(parsed, "debug_log", None)
    if debug_log_path_override or parsed.debug_output:
        from .fritap_utility import prime_debug_log
        opened = prime_debug_log(debug_log_path_override)
        if opened:
            logger.info(f"Debug log: {opened}")
        else:
            logger.warning("Failed to initialise friTap debug log file")

    # Handled before the LSASS block below: these flags promise not to start
    # logging, so `fritap -ll app.exe` on Windows must not install a full LSASS
    # instrumentation session just to print a library listing.
    #
    # The SSL_Logger is built inside the lambda so that a config or
    # protocol-registry error becomes the helper's "An error occurred" + exit 2
    # path instead of a raw traceback -- and so neither `config` nor `ssl_log`
    # leaks into this function's locals(), which the capture path's error
    # handlers below inspect for an `ssl_log` to clean up.
    # The label doubles as the only progress feedback the user gets: tlsLibHunter
    # pattern-scans every candidate module and emits nothing until it is done.
    # That is ~1-2s on macOS now, but stays proportional to module count and
    # pattern set (--scan-all-modules, or a few hundred modules on Android), so
    # say a scan is running rather than leaving a silent terminal that looks like
    # the hang this command used to have.
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

    # A rejected --filter is an invalid-argument error: fail with exit 2 before
    # the capture starts (no banners, no LSASS hook, no attach/spawn). It runs
    # after -ll/--extract-libraries on purpose: those commands never use the
    # filter, so `fritap -ll app --filter telegram` must not be rejected by it.
    _reject_invalid_headless_filter(getattr(parsed, 'filter', None), logger)

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
                       full_capture=bool(parsed.full_capture or getattr(parsed, 'owner_capture', False)))
            atexit.register(cleanup_lsass_hook)
    elif (parsed.mobile or parsed.host) and not parsed.no_lsass:
        logger.debug("LSASS hooking is a local-Windows-only feature; skipping for the mobile/remote target.")

    install_lsass_hook = False

    # --protocol all: install every protocol's hooks, but make the user confirm.
    # auto is the script-friendly alias (same hooks, no prompt) for unattended runs.
    if "all" in parsed.protocols and not parsed.yes:
        if not sys.stdin.isatty():
            parser.error(
                "--protocol all requires interactive confirmation. Pass -y/--yes "
                "to skip the prompt, or use --protocol auto for the same effect."
            )
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

    if "ssh" in parsed.protocols:
        # sshd forks a pre-auth child for KEX and re-execs into sshd-session post-auth.
        # Frida hooks only follow forks when child-gating is on. Auto-enable when the
        # target name looks like an sshd binary.
        target = (getattr(parsed, "exec", "") or "")
        target_basename = target.rsplit("/", 1)[-1]
        if re.match(r"^sshd(-session)?$", target_basename) and not parsed.enable_child_gating:
            logger.info("[ssh] sshd target detected — enabling --enable_child_gating automatically")
            parsed.enable_child_gating = True

    # MTProto and Telegram CLI rules (spawn nudge, capture-intent gate,
    # offline-backend warning) live in MTProtoHandler/TelegramHandler
    # .validate_cli_intent, dispatched below.

    # Let the selected protocol's handler validate/adjust CLI intent. This keeps
    # protocol-specific rules (e.g. a TLS-wrapped E2E protocol that needs a
    # capture intent) with the handler, out of the
    # generic parser and out of the public core. Meta values ('all'/'auto') and
    # unknown names have no single handler -> skipped.
    from friTap.protocols.registry import (
        available_protocol_names,
        create_default_registry,
    )
    # Run EACH selected protocol's handler validation (multi-protocol selection),
    # not just the primary. Meta values ('all'/'auto') and unknown names have no
    # single handler and are skipped.
    for _proto_name in parsed.protocols:
        if _proto_name not in available_protocol_names():
            continue
        try:
            _selected_handler = create_default_registry([_proto_name]).get(_proto_name)
        except Exception:
            _selected_handler = None
        if _selected_handler is not None:
            _selected_handler.validate_cli_intent(parsed, parser, logger)

    if parsed.use_modern:
        logger.warning(
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

    # Resolve '@file' up front so a missing/unreadable sample is a clean CLI
    # error instead of a traceback from inside config construction.
    try:
        parsed.ms_rc4_ciphertext = _resolve_ms_rc4_ciphertext(
            getattr(parsed, 'ms_rc4_ciphertext', None))
    except ValueError as exc:
        parser.error(str(exc))

    if parsed.full_capture and parsed.keylog is None:
        _confirm_full_capture_without_keylog(parsed, logger)
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

        # --owner-capture produces an app-scoped full pcap; it implies -f.
        if getattr(parsed, 'owner_capture', False) and not parsed.full_capture:
            logger.info("--owner-capture implies a full capture; enabling -f/--full_capture.")
            parsed.full_capture = True

        config = FriTapConfig.from_legacy_params(
            app=parsed.exec,
            spawn_argv=getattr(parsed, "exec_argv", None),
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
            owner_capture=getattr(parsed, 'owner_capture', False),
            owner_strict=getattr(parsed, 'owner_strict', False),
            owner_no_dns=getattr(parsed, 'owner_no_dns', False),
            owner_nflog_group=getattr(parsed, 'owner_nflog_group', 30),
            host=parsed.host,
            offsets=parsed.offsets,
            debug_output=parsed.debug_output,
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
            script_load_timeout=parsed.script_load_timeout,
            backend=parsed.backend,
            protocol=parsed.protocol,
            protocols=parsed.protocols,
            proxy=parsed.proxy,
            filter_expression=getattr(parsed, 'filter', None),
            filter_infrastructure=getattr(parsed, 'filter_infrastructure', True),
            include_loopback=getattr(parsed, 'include_loopback', False),
            auto_relabel=getattr(parsed, 'auto_relabel', True),
            force_scan_modules=getattr(parsed, 'force_scan_modules', None),
            quic_capture_mode=getattr(parsed, 'quic_capture_mode', 'stream'),
            quic_only=getattr(parsed, 'quic_only', False),
            no_loader_hook=getattr(parsed, 'no_loader_hook', False),
            stealth_loader=getattr(parsed, 'stealth_loader', False),
            pairip_safe=getattr(parsed, 'pairip_safe', False),
            probe=parsed.probe,
            force_anchor_locator=getattr(parsed, 'force_anchor_locator', False),
            quic_egress_headers_layer=getattr(parsed, 'quic_egress_headers_layer', 'auto'),
            scan_keys_region=getattr(parsed, 'scan_keys_region', None),
            memory_scan=bool(getattr(parsed, 'memory_scan', False)),
            memory_scan_patterns=(
                parsed.memory_scan
                if isinstance(getattr(parsed, 'memory_scan', False), str)
                else None
            ),
            memory_scan_interval=getattr(parsed, 'memory_scan_interval', 2.0),
            memory_scan_emit_unconfirmed=bool(
                getattr(parsed, 'ms_emit_unconfirmed', False)
            ),
            memory_scan_rc4_known_plaintext=getattr(
                parsed, 'ms_rc4_known_plaintext', None
            ),
            memory_scan_rc4_ciphertext=getattr(parsed, 'ms_rc4_ciphertext', None),
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

        # --filter was already validated by _reject_invalid_headless_filter()
        # right after argument parsing, before the banners above.

        ssl_log = SSL_Logger(config=config)

        # Propagate an explicit --modern onto the logger so the agent
        # config_batch sees use_modern=true (legacy/ssl_logger_core.py reads
        # via getattr(self, 'use_modern', False)).
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
            spawn = getattr(_ssl_log, "spawn", False)
            # Call it a plain exit only when the agent fully initialised in attach
            # mode ("agent-init: complete"); an empty/partial crumb (especially in
            # spawn mode) is treated as a possible hook crash, as before.
            if not spawn and crumb == "agent-init: complete":
                logger.error(
                    "The target process ended (last agent stage: agent-init: "
                    "complete); if this was unexpected, check the debug log.")
            else:
                extra = f" (last instrumented: {crumb})" if crumb else ""
                logger.error(
                    f"The target process appears to have terminated unexpectedly"
                    f"{extra} — it may have crashed inside an instrumented hook. "
                    f"Check the debug log.")
    except BackendScriptLoadTimeout as se:
        # The agent's breadcrumb lives on SSL_Logger; prefer the one the
        # exception already carries (set by whoever raised it with context).
        _ssl_log = locals().get("ssl_log")
        crumb = se.breadcrumb or getattr(_ssl_log, "_last_hook_breadcrumb", "")
        # se.bound_seconds is the EFFECTIVE bound (tripled for scan-heavy runs);
        # parsed.script_load_timeout is only what the user typed, so it would
        # under-report for --patterns / --library-scan / --scan-keys-region.
        bound = se.bound_seconds or parsed.script_load_timeout
        for line in _script_load_timeout_hints(se.elapsed_seconds, crumb, bound):
            logger.error(line)
    except BackendProcessNotRespondingError as pe:
        for line in _process_not_responding_hints(str(pe), parsed.spawn):
            logger.error(line)
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
        
        if parsed.debug or parsed.debug_output:
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
            raise Success(logger=special_logger)
        if "not yet supported on this os" in str(ex_value).lower():
            logger.error("This feature is currently not supported on this OS.")
            raise Success(logger=special_logger)

        return

    else:
        # normal end, no error
        return
    finally:
        if 'ssl_log' in locals() and isinstance(ssl_log, SSL_Logger):
            ssl_log.pcap_cleanup(parsed.full_capture,parsed.mobile,parsed.pcap)
            ssl_log.cleanup(parsed.live,parsed.socket_tracing,parsed.full_capture,parsed.debug,parsed.debug_output)
    
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
