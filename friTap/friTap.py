#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import frida
import logging
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
from .fritap_utility import get_pid_of_lsass, are_we_running_on_windows, supports_color, CustomFormatter, Success, Failure, FriTapExit



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
                    import time
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"LSASS hook failed: {e}")
                import traceback
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
        
        # Give the thread time to start
        import time
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
            if self.lsass_process:
                try:
                    self.lsass_process.detach()
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
    debug_script_file = "_ssl_log_debug.js"
    f = open(debug_script_file, 'wt', encoding='utf-8')
    f.write(debug_script_version)
    f.close()
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
                      help="Attach to a process on remote frida device")
    args.add_argument("-c", "--custom_script", metavar="<path>", required=False,
                      help="Path to the custom Frida script that will be executed prior to applying the friTap hooks.")
    args.add_argument("-d", "--debug", required=False, action="store_const", const=True,
                      help="Set friTap into debug mode this include debug output as well as a listening Chrome Inspector server for remote debugging.")
    args.add_argument("-do", "--debugoutput", required=False, action="store_const", const=True,
                      help="Activate the debug output only.")
    args.add_argument("-ar", "--anti_root", required=False, action="store_const", const=True, default=False, help="Activate anti root hooks for Android")
    args.add_argument("-ed", "--enable_default_fd", required=False, action="store_const", const=True, default=False, help="Activate the fallback socket information (127.0.0.1:1234-127.0.0.1:2345) whenever the file descriptor (FD) of the socket cannot be determined")
    args.add_argument("-f", "--full_capture", required=False, action="store_const", const=True, default=False,
                      help="Do a full packet capture instead of logging only the decrypted TLS payload. Set pcap name with -p <PCAP name>")
    args.add_argument("-k", "--keylog", metavar="<path>", required=False,
                      help="Log the keys used for tls traffic")
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
    args.add_argument('--version', action='version',version='friTap v{version}'.format(version=__version__))
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes. ATTENTION: These could be unrelated to the current process!")
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
    args.add_argument("-j", "--json", metavar="<path>", required=False,
                      help="Save session metadata and analysis results in JSON format")
    args.add_argument("-ll", "--list-libraries", required=False, action="store_const", const=True,
                      help="List loaded libraries in order to help debugging the hooking process. This will not start the logging process, but only list the libraries and exit.", dest="list_libraries")
    args.add_argument("-nl", "--no-lsass", required=False, action="store_const", const=True,default=False,
                      help="Only applied on windows systems. By default friTap is hooking the Local Security Authority Subsystem Service (LSASS) process as well as its the default TLS provider on Windows systems. With this parameter we are not hooking LSASS", dest="no_lsass")
    args.add_argument("-t", "--timeout", metavar="<seconds>", type=int, required=False, default=None,
                      help="Set a timeout in seconds for the process. After the timeout, the process will be resumed automatically. If not set, the process will resume immediately.")
    parsed = parser.parse_args()

    # Configure logging after parsing arguments to respect debug flags
    if parsed.debug or parsed.debugoutput:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
        
    logger.setLevel(log_level)
    
    # Create console handler with custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter(use_color=supports_color(console_handler.stream)))
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)

    # Create a special logger to print clean messages without prefixes (e.g. farewell line)
    special_logger = logging.getLogger('friTap.no_prefix')
    special_logger.setLevel(log_level)
    special_handler = logging.StreamHandler()
    special_handler.setFormatter(logging.Formatter("%(message)s"))
    special_logger.addHandler(special_handler)
    special_logger.propagate = False
    logger.propagate = False  # Prevent duplicate messages

    install_lsass_hook = True

    if are_we_running_on_windows() and not parsed.mobile:
        if parsed.no_lsass:
            logger.info("LSASS hooking is disabled. Proceeding without LSASS.")
        else:
            logger.info("Hooking LSASS process for SSL/TLS traffic decryption.")
            hook_lsass(parsed.pcap, parsed.verbose, parsed.keylog, parsed.live, parsed.debug, parsed.host, parsed.debugoutput, parsed.enable_default_fd, parsed.patterns, parsed.custom_script, parsed.json)
            
            # Register cleanup handler for LSASS hook
            atexit.register(cleanup_lsass_hook)

        install_lsass_hook = False
    else:
        install_lsass_hook = False
    
    if parsed.list_libraries:
        logger.info("Listing loaded libraries...")
        try:
            # Create a minimal SSL_Logger instance for library inspection
            temp_ssl_log = SSL_Logger(parsed.exec, None, parsed.verbose,
                    parsed.spawn, False, parsed.enable_spawn_gating, parsed.mobile, 
                    False, parsed.environment, parsed.debug, False, False, 
                    parsed.host, parsed.offsets, parsed.debugoutput, parsed.experimental, 
                    parsed.anti_root, False, parsed.enable_default_fd, parsed.patterns, 
                    parsed.custom_script, None)
            
            # Use the SSL_Logger's library inspection capability
            result = temp_ssl_log.inspect_libraries()
            special_logger.info(result)
            
        except frida.TransportError as fe:
            logger.error(f"Problems while attaching to frida-server: {fe}")
        except FridaBasedException as e:
            logger.error(f"Frida based error: {e}")
        except Exception as e:
            logger.error(f"An error occurred: {e}")
        else:
            # no error, simply exit main
            return
        # reach here when error
        raise Failure

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
        ssl_log = SSL_Logger(parsed.exec, parsed.pcap, parsed.verbose,
                parsed.spawn, parsed.keylog, parsed.enable_spawn_gating, parsed.mobile, parsed.live, parsed.environment, parsed.debug, parsed.full_capture, parsed.socket_tracing, parsed.host, parsed.offsets, parsed.debugoutput, parsed.experimental, parsed.anti_root, parsed.payload_modification, parsed.enable_default_fd, parsed.patterns, parsed.custom_script, parsed.json, install_lsass_hook, parsed.timeout)

        ssl_log.install_signal_handler()        
        ssl_log.start_fritap_session()  
        
        # Wait for user input or interrupt
        while ssl_log.running:
            pass
            
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Cleaning up...")
        cleanup_lsass_hook()
        raise
    except SystemExit:
        cleanup_lsass_hook()
        raise
    except frida.TransportError as fe:
        logger.error(f"Problems while attaching to frida-server: {fe}")
    except FridaBasedException as e:
        logger.error(f"Frida based error: {e}")
    except frida.TimedOutError as te:
        logger.error(f"TimeOutError: {te}")
    except frida.ProcessNotFoundError as pe:
        logger.error(f"ProcessNotFoundError: {pe}")
    except frida.PermissionDeniedError as e:
        logger.error(f"Frida Permission Denied: {e}")
    except frida.ServerNotRunningError as e:
        logger.error(f"Frida server is not running: {e}")
    except frida.InvalidArgumentError as e:
        logger.error(f"Invalid Argument passed to Frida: {e}")
        if "device not found" in str(e):
            logger.error("Frida is unable to identify the target device.")
            logger.error("If you have multiple devices connected, please specify the device ID using the `-m` option:")
            logger.error("\t1. Identify the target device ID (e.g., using `adb devices` or `frida-ls-devices`).")
            logger.error("\t2. Run FriTap with the device ID:")
            logger.error("\t   fritap -m <device-id> <target>")
    except frida.InvalidOperationError as e:
        logger.error(f"Invalid Operation Error in Frida: {e}")
    except Exception as ar:
        # Get current system exception
        ex_type, ex_value, ex_traceback = sys.exc_info()
        
        # Extract unformatter stack traces as tuples
        trace_back = traceback.extract_tb(ex_traceback)
        
        # Format stacktrace
        stack_trace = list()
        
        for trace in trace_back:
            stack_trace.append("File : %s , Line : %d, Func.Name : %s, Message : %s" % (trace[0], trace[1], trace[2], trace[3]))
        
        if parsed.debug or parsed.debugoutput:
            if "NotSupportedError" in ex_type.__name__:
                logger.error("Frida based error:")
            logger.error("Exception type : %s " % ex_type.__name__)
            logger.error("Exception message : %s" %ex_value)
            logger.error("Stack trace : %s" %stack_trace)


        if "unable to connect to remote frida-server: closed" in str(ar):
            logger.error("frida-server is not running in remote device. Please run frida-server and rerun")
            
        if "NotSupportedError" in ex_type.__name__:
            logger.error(f"Frida error: {ex_value}")
        else:
            logger.error(f"Unknown error: {ex_value}")

        if "unable to access process with pid" in str(ex_value).lower():
            raise Success(special_logger)
        if "not yet supported on this os" in str(ex_value).lower():
            logger.error("This feature is currently not supported by frida on this OS.")
            raise Success(special_logger)

        if 'ssl_log' in locals():
            ssl_log.pcap_cleanup(parsed.full_capture,parsed.mobile,parsed.pcap)
            ssl_log.cleanup(parsed.live,parsed.socket_tracing,parsed.full_capture,parsed.debug,parsed.debugoutput)    
        return

    else:
        # normal end, no error
        return
    finally:
        if 'ssl_log' in locals() and isinstance(ssl_log, SSL_Logger):
            ssl_log.pcap_cleanup(parsed.full_capture,parsed.mobile,parsed.pcap)
            ssl_log.cleanup(parsed.live,parsed.socket_tracing,parsed.full_capture,parsed.debug)
    
    # only reached when error
    raise Failure

def main():
    try:
        cli()
    except FriTapExit as e:
        e.exit()


if __name__ == "__main__":
    main()
