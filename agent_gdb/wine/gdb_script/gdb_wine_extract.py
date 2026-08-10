import os
import sys
import json
import logging

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
        logging.debug(f"LdrLoadDll finished")
        return False


class FindHookablesBP(gdb.Breakpoint):
    def stop(self):
        find_hookable_functions()
        return False


# Maps handler name strings to their classes for JSON loading.
HANDLER_REGISTRY = {
    "GnuTLSCallKeylogUnixBP": GnuTLSCallKeylogUnixBP,
    "GnuTLSCallKeylogWindowsBP": GnuTLSCallKeylogWindowsBP,
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

    for pattern, metadata in _load_patterns(config):
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


def is_hooked(address):
    curr_inferior = gdb.selected_inferior().num
    for breakpoint in gdb.breakpoints():
        for location in breakpoint.locations:
            if address == location.address and breakpoint.inferior == curr_inferior:
                return True
    return False


def hook_function(pattern, address):
    target_address = address + PATTERNS[pattern]["offset"]
    if is_hooked(target_address):
        return
    logging.debug(
        f"Hooking in {gdb.selected_inferior().num}: {PATTERNS[pattern]['name']}"
    )
    bp = HANDLER_REGISTRY[PATTERNS[pattern]["handler"]]("* " + hex(target_address))
    bp.inferior = gdb.selected_inferior().num


def find_hookable_functions(ranges=None):
    if ranges is None:
        ranges = get_memory_ranges()

    process = gdb.selected_inferior()

    for start, stop in ranges:
        mem = bytes(process.read_memory(start, stop - start))

        for pattern in PATTERNS:
            offset = mem.find(pattern)
            if offset != -1:
                hook_function(pattern, start + offset)


def on_executable_changed_handler(event):
    logging.debug(
        f"new program executed {event.progspace.filename}; {gdb.selected_inferior().num}"
    )
    find_hookable_functions()


def attach(pid):
    gdb.execute("set exception-verbose on")
    gdb.execute("set non-stop on")
    gdb.execute("set follow-fork-mode parent")
    gdb.execute("handle all nostop")
    gdb.execute("set detach-on-fork off")
    gdb.execute("set breakpoint pending on")

    gdb.events.executable_changed.connect(on_executable_changed_handler)

    logging.info(f"attaching to {pid}")
    gdb.execute(f"attach {pid}")

    find_hookable_functions()

    gdb.execute("c")


def spawn(config, program_args=None):
    gdb.execute("set auto-solib-add on")
    gdb.execute("set non-stop on")
    gdb.execute("file wine")
    gdb.execute("set follow-fork-mode parent")

    gdb.execute("handle all nostop")
    gdb.execute("set detach-on-fork off")
    gdb.execute("set breakpoint pending on")

    gdb.events.executable_changed.connect(on_executable_changed_handler)

    arguments = " ".join([config["spawn"], *(program_args or [])])
    arguments += f" 1>&{config["stdout-fd"]} 2>&{config["stderr-fd"]}"
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
