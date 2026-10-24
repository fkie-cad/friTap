import json
import logging
import os
import shlex
import sys

logger = None

try:
    import gdb  # noqa: F401
except ImportError:
    logging.error("gdb library not available")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

FRITAP_KEYLOG = None
PATTERNS = None


def write_keylog(label, client_random, secret):
    line = f"{label} {client_random} {secret}"

    if FRITAP_KEYLOG is not None:
        with open(FRITAP_KEYLOG, "a") as f:
            f.write(line + "\n")
    logging.info(f"{line}")


def read_unicode_string(struct_address):
    inferior = gdb.selected_inferior()

    length_bytes = inferior.read_memory(struct_address, 2)
    length = int.from_bytes(length_bytes, byteorder="little")

    buffer_ptr_bytes = inferior.read_memory(struct_address + 8, 8)
    buffer_ptr = int.from_bytes(buffer_ptr_bytes, byteorder="little")

    if buffer_ptr == 0 or length == 0:
        return ""

    raw = bytes(inferior.read_memory(buffer_ptr, length))
    return raw.decode("utf-16-le", errors="replace")


class GnuTLSCallKeylogUnixBP(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        rdi = frame.read_register("rdi")
        rsi = frame.read_register("rsi")
        rdx = frame.read_register("rdx")
        rcx = frame.read_register("rcx")

        label = rsi.cast(gdb.lookup_type("char").pointer()).string()
        secret_size = rcx
        secret = bytes(inferior.read_memory(rdx, secret_size)).hex()
        client_random = bytes(inferior.read_memory(rdi + 0x50, 32)).hex()

        write_keylog(label, client_random, secret)
        return False


class GnuTLSCallKeylogWindowsBP(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()

        label = (
            frame.read_register("rdx").cast(gdb.lookup_type("char").pointer()).string()
        )
        client_random = bytes(
            inferior.read_memory(frame.read_register("rcx") + 0x50, 32)
        ).hex()
        secret_size = frame.read_register("r9")
        secret = bytes(
            inferior.read_memory(frame.read_register("r8"), secret_size)
        ).hex()

        write_keylog(label, client_random, secret)
        return False


class OpenSSLCallSSLLogSecretWindowsBP(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()

        label = (
            frame.read_register("rdx").cast(gdb.lookup_type("char").pointer()).string()
        )
        client_random = bytes(
            inferior.read_memory(frame.read_register("rcx") + 388, 32)
        ).hex()
        secret_size = frame.read_register("r9")
        secret = bytes(
            inferior.read_memory(frame.read_register("r8"), secret_size)
        ).hex()

        write_keylog(label, client_random, secret)
        return False


class GnuTLSNssKeylogFuncUnixBP(gdb.Breakpoint):
    """GnuTLS NSS keylog *callback* (SysV ABI):

        int keylog_func(gnutls_session_t session, const char *label,
                        const gnutls_datum_t *secret)

    gnutls registers this callback unconditionally and invokes it for every
    secret of every handshake (the SSLKEYLOGFILE check happens *inside* it), so
    hooking its entry captures keys passively -- no SSLKEYLOGFILE needed. This is
    the function to hook on builds where ``_gnutls_call_keylog_func`` is inlined
    into the key schedule (e.g. Ubuntu gnutls 3.8.x), where the standalone
    ``GnuTLSCallKeylog*`` signatures above never match. ``gnutls_datum_t`` is
    ``{ unsigned char *data; unsigned int size; }`` and client_random lives at
    ``session + 0x50`` (same session layout as the handlers above).
    """

    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        rdi = frame.read_register("rdi")
        rsi = frame.read_register("rsi")
        rdx = frame.read_register("rdx")

        label = rsi.cast(gdb.lookup_type("char").pointer()).string()
        datum_ptr = int(rdx)
        data_ptr = int.from_bytes(
            inferior.read_memory(datum_ptr, 8), byteorder="little"
        )
        secret_size = int.from_bytes(
            inferior.read_memory(datum_ptr + 8, 4), byteorder="little"
        )
        secret = bytes(inferior.read_memory(data_ptr, secret_size)).hex()
        client_random = bytes(inferior.read_memory(int(rdi) + 0x50, 32)).hex()

        write_keylog(label, client_random, secret)
        return False


class LdrLoadDLLWindowsBP(gdb.Breakpoint):
    def stop(self):
        ranges = get_memory_ranges()

        LdrLoadDllWindowsFinishBP(old_ranges=ranges)

        uni_ptr = int(gdb.newest_frame().read_register("r8"))
        logging.debug(f"LdrLoadDll called for Dll {read_unicode_string(uni_ptr)}")

        return False


class LdrLoadDllWindowsFinishBP(gdb.FinishBreakpoint):
    def __init__(self, old_ranges=[]):
        super().__init__()
        self.old_ranges = old_ranges

    def stop(self):
        ranges = get_memory_ranges()
        new_ranges = [x for x in ranges if x not in self.old_ranges]
        find_hookable_functions(new_ranges)
        logging.debug("LdrLoadDll finished")
        return False


class FindHookablesBP(gdb.Breakpoint):
    def stop(self):
        find_hookable_functions()
        return False


# Maps handler name strings to their classes for JSON loading.
HANDLER_REGISTRY = {
    "GnuTLSCallKeylogUnixBP": GnuTLSCallKeylogUnixBP,
    "GnuTLSCallKeylogWindowsBP": GnuTLSCallKeylogWindowsBP,
    "GnuTLSNssKeylogFuncUnixBP": GnuTLSNssKeylogFuncUnixBP,
    "OpenSSLCallSSLLogSecretWindowsBP": OpenSSLCallSSLLogSecretWindowsBP,
    "FindHookablesBP": FindHookablesBP,
    "LdrLoadDLLWindowsBP": LdrLoadDLLWindowsBP,
    "LdrLoadDllWindowsFinishBP": LdrLoadDllWindowsFinishBP,
}

DEFAULT_TLS_PATTERNS = {
    "f30f1efa554989d089ca4889e54883ec20488b8fc006000064488b042528000000": {
        "name": "_gnutls_call_keylog_func unix",
        "offset": 0,
        "handler": "GnuTLSCallKeylogUnixBP",
    },
    "4883ec384c8b916006000031c04d85d274124c8944": {
        "name": "_gnutls_call_keylog_func windows",
        "offset": 0,
        "handler": "GnuTLSCallKeylogWindowsBP",
    },
    "4157415641554154555756534883ec28488b71084889cb4d89c44d89ce4883be0004000000": {
        "name": "SSL_log_secret windows",
        "offset": 0,
        "handler": "OpenSSLCallSSLLogSecretWindowsBP",
    },
    # Fallback for builds that inline _gnutls_call_keylog_func (e.g. Ubuntu
    # gnutls 3.8.x): hook the registered NSS keylog callback instead. Prologue of
    # the callback in libgnutls.so.30 (gnutls 3.8.9). See GnuTLSNssKeylogFuncUnixBP.
    "f30f1efa554889e54157415641554154534881ece800000064488b0425280000": {
        "name": "gnutls nss keylog callback unix (gnutls 3.8.x)",
        "offset": 0,
        "handler": "GnuTLSNssKeylogFuncUnixBP",
    },
}

DEFAULT_WINE_PATTERNS = {
    "4154555756534883ec404889cd498b48084189d44c89c34c89cfe81912030048": {
        "name": "LdrLoadDll@ntdll.dll windows",
        "handler": "LdrLoadDLLWindowsBP",
        "offset": 0,
    },
    "554889e541574189ff415641554154534889f34881ecc8000000488d050f9f07": {
        "name": "__wine_main@ntdll.so unix",
        "handler": "FindHookablesBP",
        "offset": 2412,
    },
    "4889e0488da42470ffffff48890424488d356a30000048c7c70210000048c7c0": {
        "name": "_start@wine-preloader unix",
        "handler": "FindHookablesBP",
        "offset": 46,
    },
    "554889e541544189fc488d3d38130000534889f3e8f70100004889c74885c074": {
        "name": "main@wine unix",
        "handler": "FindHookablesBP",
        "offset": 45,
    },
    "4883ec2883fa01740fb8010000004883c428c30f1f44000048894c2430": {
        "name": "DllMain",
        "handler": "FindHookablesBP",
        "offset": 0,
    },
}
# NOTE: on the newer "wow64" Wine layout (e.g. wine 9.x on Ubuntu) there is no
# wine-preloader and the loader entry points differ, so the loader signatures
# above do not match. We deliberately do NOT add entry-point (offset 0) fallbacks
# for the wow64 loader: a breakpoint planted at __wine_main/_start entry is torn
# down during Wine's early wow64/exec transition and gdb then fails to re-insert
# it ("Cannot insert breakpoint ... Cannot access memory"), aborting the run.
# Re-scanning on this layout is instead driven by the new_objfile event (see
# _connect_scan_events), which fires whenever a shared object -- including the
# TLS library -- is mapped, so the loader breakpoints are redundant here anyway.


def _load_patterns(config):
    env_var = os.environ.get("FRITAP_PATTERNS")
    if not env_var:
        return {}

    patterns = json.loads(env_var)

    return {bytes.fromhex(x): y for x, y in patterns.items()}


def _build_patterns(config):
    """Merge default patterns with any overrides from JSON env vars."""
    tls = {bytes.fromhex(x): y for x, y in DEFAULT_TLS_PATTERNS.items()}
    wine = {bytes.fromhex(x): y for x, y in DEFAULT_WINE_PATTERNS.items()}

    combined = {**tls, **wine}

    for pattern, metadata in _load_patterns(config).items():
        combined[pattern] = metadata

    logging.debug(f"Patterns loaded: {combined}")

    return combined


def get_memory_ranges():
    regions = []
    with open(f"/proc/{gdb.selected_inferior().pid}/maps") as f:
        for line in f:
            addr, perms, *_ = line.split()
            start, end = [int(x, 16) for x in addr.split("-")]
            if "x" in perms and "r" in perms:
                regions.append((start, end))
    return regions


# (inferior_num, address) pairs we have already planted a breakpoint on.
# Tracked ourselves instead of querying gdb.breakpoints(): gdb.Breakpoint.locations
# only exists on gdb >= 13, and touching it on older gdb (e.g. 10.2) raises
# AttributeError inside the scan, which previously aborted hooking entirely.
_HOOKED = set()

# (inferior_num, start, stop) ranges already read + pattern-scanned. new_objfile
# fires once per shared object mapped (dozens of times during a Wine cold boot);
# without this, every event would re-ptrace-copy and re-scan ALL executable
# memory from scratch. Executable code does not change after a range is mapped
# and freshly loaded libraries get fresh ranges, so scanning each range once is
# sufficient. Mirrors the new-ranges diff already done in LdrLoadDllWindowsFinishBP.
_SCANNED_RANGES = set()


def is_hooked(address):
    return (gdb.selected_inferior().num, address) in _HOOKED


def hook_function(pattern, address):
    target_address = address + PATTERNS[pattern]["offset"]
    if is_hooked(target_address):
        return
    logging.debug(
        f"Hooking in {gdb.selected_inferior().num}: {PATTERNS[pattern]['name']}"
    )
    bp = HANDLER_REGISTRY[PATTERNS[pattern]["handler"]]("* " + hex(target_address))
    bp.inferior = gdb.selected_inferior().num
    _HOOKED.add((gdb.selected_inferior().num, target_address))


def find_hookable_functions(ranges=None):
    if ranges is None:
        ranges = get_memory_ranges()

    process = gdb.selected_inferior()
    inferior_num = process.num

    for start, stop in ranges:
        key = (inferior_num, start, stop)
        if key in _SCANNED_RANGES:
            continue  # already read + scanned this exact range (see _SCANNED_RANGES)
        # Wine maps exotic/guard regions that are listed as readable in
        # /proc/pid/maps but are not actually accessible to the debugger (and in
        # non-stop mode a region can vanish mid-scan). A raised MemoryError here
        # used to abort the whole scan, so a later range holding the TLS library
        # was never searched. Skip unreadable ranges instead (do not mark them
        # scanned, so a later attempt may retry).
        try:
            mem = bytes(process.read_memory(start, stop - start))
        except (gdb.MemoryError, gdb.error):
            continue
        _SCANNED_RANGES.add(key)

        for pattern in PATTERNS:
            offset = mem.find(pattern)
            if offset != -1:
                hook_function(pattern, start + offset)


def on_executable_changed_handler(event):
    logging.debug(
        f"scan event {type(event).__name__}; inferior {gdb.selected_inferior().num}"
    )
    find_hookable_functions()


def _connect_scan_events():
    """Connect re-scan triggers in a way that works across gdb versions.

    ``gdb.events.executable_changed`` only exists on gdb >= 12 (the version the
    original signatures were produced against). ``gdb.events.new_objfile`` exists
    on every supported gdb and fires whenever a shared object (e.g. a TLS library)
    is mapped -- exactly when we want to re-scan. Connect whichever are present so
    the extractor runs unchanged on older gdb builds too.
    """
    connected = []
    for name in ("executable_changed", "new_objfile"):
        event = getattr(gdb.events, name, None)
        if event is not None:
            event.connect(on_executable_changed_handler)
            connected.append(name)
    logging.debug(f"connected scan events: {connected}")


def _try_execute(cmd):
    """Run an optional gdb setting, ignoring it if this gdb doesn't know it.

    e.g. ``set exception-verbose`` is not available on older gdb (10.2) and
    otherwise aborts attach before it even starts.
    """
    try:
        gdb.execute(cmd)
    except gdb.error as exc:
        logging.debug(f"gdb command not supported, skipping: {cmd!r} ({exc})")


def attach(pid):
    _try_execute("set exception-verbose on")
    # All-stop (not non-stop) for attach: the script drives gdb with no tty, so
    # a non-stop "continue" returns immediately, the script ends and gdb detaches
    # before any handshake fires ("No unwaited-for children left"). In all-stop,
    # "continue" blocks until the target exits, keeping gdb alive and firing the
    # keylog breakpoints the whole time; the scan also reads a stopped process.
    # Our stop() handlers return False, so each hit resumes immediately.
    gdb.execute("set non-stop off")
    gdb.execute("set follow-fork-mode parent")
    gdb.execute("handle all nostop")
    gdb.execute("set detach-on-fork off")
    gdb.execute("set breakpoint pending on")

    _connect_scan_events()

    logging.info(f"attaching to {pid}")
    gdb.execute(f"attach {pid}")

    find_hookable_functions()

    gdb.execute("c")


def spawn(config, program_args=None):
    wine_bin = config.get("wine-bin") or "wine"
    gdb.execute("set auto-solib-add on")
    gdb.execute("set non-stop on")
    # Quote the loader path: it may live under a directory with spaces, and gdb's
    # `file` tokenizes on whitespace otherwise.
    gdb.execute("file " + shlex.quote(wine_bin))
    gdb.execute("set follow-fork-mode parent")

    gdb.execute("handle all nostop")
    gdb.execute("set detach-on-fork off")
    gdb.execute("set breakpoint pending on")

    _connect_scan_events()

    # Shell-quote the program and its args (paths like "C:\Program Files\app.exe"
    # contain spaces); gdb's `run` passes the string to the shell, so the fd
    # redirection stays unquoted shell syntax.
    quoted = " ".join(shlex.quote(a) for a in [config["spawn"], *(program_args or [])])
    arguments = f"{quoted} 1>&{config['stdout-fd']} 2>&{config['stderr-fd']}"
    logging.info(f"Spawning executable {arguments}")
    gdb.execute(f"r {arguments}")


def supports_color(stream) -> bool:
    try:
        return (
            hasattr(stream, "isatty")
            and stream.isatty()
            and os.getenv("NO_COLOR") is None
            and os.getenv("TERM", "") not in ("", "dumb")
        )
    except Exception:
        return False


class CustomFormatter(logging.Formatter):
    """friTap prefix + optional ANSI colors (only when record._colorize=True)."""

    RESET = "\x1b[0m"
    COLORS = {
        logging.DEBUG: "\x1b[95m",  # magenta
        logging.INFO: "\x1b[32m",  # green
        logging.WARNING: "\x1b[33m",  # yellow
        logging.ERROR: "\x1b[31m",  # red
        logging.CRITICAL: "\x1b[31;1m",  # bright red
    }

    PREFIXES = {
        logging.INFO: "[*]",
        logging.DEBUG: "[!]",
        logging.WARNING: "[-]",
        logging.ERROR: "[-]",
        logging.CRITICAL: "[-]",
    }

    def __init__(self, *, use_color: bool = True):
        # we ignore parent fmt; we fully control the line format here
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        prefix = self.PREFIXES.get(record.levelno, "[*]")
        text = f"{prefix} {record.getMessage()}"
        if self.use_color and getattr(record, "_colorize", False):
            color = self.COLORS.get(record.levelno)
            if color:
                return f"{color}{text}{self.RESET}"
        return text


def setup_logging(config):
    log_stream = os.fdopen(os.dup(int(config["log-fd"])), "w", buffering=1)
    level = logging.WARNING

    if config["verbose"]:
        level = logging.INFO
    if config["debug_output"]:
        level = logging.DEBUG

    logging.basicConfig(level=level, stream=log_stream)

    for handler in logging.getLogger().handlers:
        handler.setFormatter(CustomFormatter(use_color=supports_color(handler.stream)))


def main():
    global FRITAP_KEYLOG, PATTERNS
    config = json.loads(os.environ.get("FRITAP_ARGS"))

    setup_logging(config=config)

    FRITAP_KEYLOG = config["keylog"]

    PATTERNS = _build_patterns(config)

    if config["attach"] and not config["spawn"]:
        attach(config["attach"])
    elif config["spawn"] and not config["attach"]:
        spawn(config, program_args=config["program_args"])
    else:
        logging.error("Either a executable or a PID must be specified")
        sys.exit(1)


if __name__ == "__main__":
    main()
