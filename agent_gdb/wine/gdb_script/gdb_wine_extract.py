import json
import logging
import os
import shlex
import signal
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

MASK64 = 0xFFFFFFFFFFFFFFFF

# LibreSSL emits raw TLS 1.3 key-schedule labels; map them to the NSS keylog
# labels Wireshark expects. Mirrors agent/tls/definitions/shared_constants.ts.
TLS13_LABEL_MAP = {
    "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
    "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
    "exp master": "EXPORTER_SECRET",
    "res master": "RESUMPTION_MASTER_SECRET",
}

# Per-inferior client_random for LibreSSL. client_random is NOT reachable from
# any LibreSSL KDF frame, so it is parsed out of the plaintext ClientHello written
# to ws2_32!send (see Ws2SendClientHelloBP) and consumed by the leaf HKDF /
# tls1_PRF hooks. Keyed by inferior number.
_LIBRESSL_CLIENT_RANDOM = {}

# Whether the ws2_32!send client_random breakpoint has been installed (once per
# inferior that has a LibreSSL hook).
_WS2_SEND_HOOKED = set()

# Inferiors where a KDF-only (LibreSSL) hook was installed — drives the
# ws2_32!send retry in find_hookable_functions until the send BP lands.
_LIBRESSL_DETECTED = set()


def _read_cstr(inferior, addr, limit=64):
    # NOTE: gdb's Inferior.read_memory returns a memoryview; comparing it to a
    # bytes literal (memoryview == b"\x00") does NOT match by content, so the
    # NUL terminator must be detected on the converted bytes. Reading the whole
    # chunk once and splitting on NUL is both correct and faster; fall back to a
    # byte-at-a-time read when the string sits near the end of a mapping and a
    # bulk read would run off into unmapped memory.
    try:
        raw = bytes(inferior.read_memory(addr, limit))
    except gdb.error:
        raw = bytearray()
        for i in range(limit):
            try:
                raw += bytes(inferior.read_memory(addr + i, 1))
            except gdb.error:
                break
        raw = bytes(raw)
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _ru16(inferior, addr):
    return int.from_bytes(inferior.read_memory(addr, 2), "little")


def _ru32(inferior, addr):
    return int.from_bytes(inferior.read_memory(addr, 4), "little")


def _find_pe_module_base(dll_substr):
    """Return the load base of a PE module whose maps path contains dll_substr
    (case-insensitive), picking the offset-0 mapping (the image header)."""
    pid = gdb.selected_inferior().pid
    needle = dll_substr.lower()
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr, _perms, offset = parts[0], parts[1], parts[2]
                path = parts[5]
                if needle not in path.lower():
                    continue
                if int(offset, 16) != 0:
                    continue  # want the image base (header at offset 0)
                return int(addr.split("-")[0], 16)
    except OSError:
        return None
    return None


def _pe_find_export(base, export_name):
    """Resolve an export address from a loaded PE image by walking its export
    table in inferior memory. Ported from agent/platforms/wine.ts
    parse_pe_find_export. Returns absolute VA or None."""
    inf = gdb.selected_inferior()
    try:
        if _ru16(inf, base) != 0x5A4D:  # "MZ"
            return None
        pe_off = _ru32(inf, base + 0x3C)
        if pe_off <= 0 or pe_off > 0x10000:
            return None
        if _ru32(inf, base + pe_off) != 0x00004550:  # "PE\0\0"
            return None
        opt_off = pe_off + 24
        magic = _ru16(inf, base + opt_off)
        if magic == 0x20B:
            data_dir = opt_off + 112  # PE32+
        elif magic == 0x10B:
            data_dir = opt_off + 96   # PE32
        else:
            return None
        export_rva = _ru32(inf, base + data_dir)
        if export_rva == 0:
            return None
        ed = base + export_rva
        num_funcs = _ru32(inf, ed + 0x14)
        num_names = _ru32(inf, ed + 0x18)
        funcs_rva = _ru32(inf, ed + 0x1C)
        names_rva = _ru32(inf, ed + 0x20)
        ords_rva = _ru32(inf, ed + 0x24)
        if num_names == 0 or num_funcs == 0:
            return None
        for i in range(num_names):
            name_rva = _ru32(inf, base + names_rva + i * 4)
            if _read_cstr(inf, base + name_rva, 64) != export_name:
                continue
            ordinal = _ru16(inf, base + ords_rva + i * 2)
            if ordinal >= num_funcs:
                return None
            func_rva = _ru32(inf, base + funcs_rva + ordinal * 4)
            if func_rva == 0:
                return None
            return base + func_rva
    except gdb.error:
        return None
    return None


def _parse_clienthello_random(inferior, buf, length):
    """Extract the 32-byte client_random (hex) from a ClientHello buffer in
    either framing (TLS record 0x16 / bare handshake message 0x01), mirroring
    agent/shared/clienthello_random.ts. Returns hex str or None."""
    if buf == 0 or length < 38:
        return None
    try:
        b = bytes(inferior.read_memory(buf, min(length, 11 + 32)))
    except gdb.error:
        return None
    if b[0] == 0x16 and len(b) >= 11 + 32:
        if b[5] == 0x01 and b[9] == 0x03:
            return b[11:43].hex()
    elif b[0] == 0x01 and len(b) >= 6 + 32:
        if b[4] == 0x03:
            return b[6:38].hex()
    return None


class Ws2SendClientHelloBP(gdb.Breakpoint):
    """ws2_32!send(SOCKET s, const char *buf, int len, int flags) (Win64 ABI:
    rcx=s, rdx=buf, r8=len). Parses the plaintext ClientHello to recover
    client_random for the LibreSSL KDF hooks (which have no SSL* in frame)."""

    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        buf = int(frame.read_register("rdx")) & MASK64
        length = int(frame.read_register("r8")) & 0xFFFFFFFF
        cr = _parse_clienthello_random(inferior, buf, length)
        if cr:
            _LIBRESSL_CLIENT_RANDOM[inferior.num] = cr
            logging.debug(f"[LibreSSL] client_random from ws2_32!send: {cr}")
        return False


def ensure_ws2_send_bp():
    """Resolve ws2_32!send in the current inferior and plant a client_random
    breakpoint on it (once). Called when a LibreSSL KDF hook is installed."""
    num = gdb.selected_inferior().num
    if num in _WS2_SEND_HOOKED:
        return
    base = _find_pe_module_base("ws2_32.dll")
    if base is None:
        logging.debug("[LibreSSL] ws2_32.dll not mapped yet; send hook deferred")
        return
    addr = _pe_find_export(base, "send")
    if addr is None:
        logging.debug("[LibreSSL] could not resolve ws2_32!send export")
        return
    _WS2_SEND_HOOKED.add(num)
    bp = Ws2SendClientHelloBP("* " + hex(addr))
    bp.inferior = num
    logging.info(f"[LibreSSL] ws2_32!send client_random hook @ {hex(addr)}")


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


class LibreSSLHkdfFinishWinBP(gdb.FinishBreakpoint):
    """Reads the derived TLS 1.3 secret from *out after
    tls13_hkdf_expand_label[_with_length] returns, then emits the keylog line."""

    def __init__(self, out_ptr, nss_label):
        super().__init__(internal=True)
        self.out_ptr = out_ptr
        self.nss_label = nss_label

    def stop(self):
        inferior = gdb.selected_inferior()
        try:
            data_ptr = int.from_bytes(inferior.read_memory(self.out_ptr, 8), "little") & MASK64
            data_len = int.from_bytes(inferior.read_memory(self.out_ptr + 8, 8), "little")
        except gdb.error:
            return False
        if data_ptr == 0 or not (0 < data_len < 256):
            return False
        try:
            secret = bytes(inferior.read_memory(data_ptr, data_len)).hex()
        except gdb.error:
            return False
        cr = _LIBRESSL_CLIENT_RANDOM.get(inferior.num)
        if not cr:
            logging.debug(f"[LibreSSL] client_random unknown, dropping {self.nss_label}")
            return False
        write_keylog(self.nss_label, cr, secret)
        return False


class LibreSSLHkdfExpandLabelWinBP(gdb.Breakpoint):
    """LibreSSL TLS 1.3 tls13_hkdf_expand_label_with_length (Win64 ABI).

        int tls13_hkdf_expand_label_with_length(struct tls13_secret *out,
            const EVP_MD *md, const struct tls13_secret *secret,
            const uint8_t *label, size_t label_len, const struct tls13_secret *context)

    rcx=out, r9=label, [rsp+0x20]=label_len. The derived secret is written into
    *out only on return, so we hand off to a FinishBreakpoint. tls13_secret is
    { uint8_t *data; size_t len; }.
    """

    # Arms the ws2_32!send client_random capture (see hook_function).
    needs_ws2_send_client_random = True

    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        out_ptr = int(frame.read_register("rcx")) & MASK64
        label_ptr = int(frame.read_register("r9")) & MASK64
        rsp = int(frame.read_register("rsp")) & MASK64
        try:
            label_len = int.from_bytes(inferior.read_memory(rsp + 0x20, 8), "little")
            if 0 < label_len < 64:
                label = bytes(inferior.read_memory(label_ptr, label_len)).decode("latin-1")
            else:
                label = _read_cstr(inferior, label_ptr)
        except gdb.error:
            return False
        nss_label = TLS13_LABEL_MAP.get(label)
        if not nss_label:
            return False
        try:
            LibreSSLHkdfFinishWinBP(out_ptr, nss_label)
        except (gdb.error, ValueError) as e:
            logging.debug(f"[LibreSSL] could not set finish bp: {e}")
        return False


class LibreSSLTls1PrfWinBP(gdb.Breakpoint):
    """LibreSSL TLS 1.2 tls1_PRF (Win64 ABI).

    The "key expansion" PRF call carries the master secret in its register args
    (secret=rdx, secret_len=r8, label=r9); client_random comes from the
    ws2_32!send ClientHello capture (Ws2SendClientHelloBP). No SSL*, symbol, or
    struct offset needed. Emits `CLIENT_RANDOM <cr> <master>`.
    """

    # Arms the ws2_32!send client_random capture (see hook_function).
    needs_ws2_send_client_random = True

    def stop(self):
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        try:
            label_ptr = int(frame.read_register("r9")) & MASK64
            if _read_cstr(inferior, label_ptr, 32) != "key expansion":
                return False
            secret_ptr = int(frame.read_register("rdx")) & MASK64
            secret_len = int(frame.read_register("r8")) & 0xFFFFFFFF
            if secret_ptr == 0 or not (0 < secret_len <= 64):
                return False
            cr = _LIBRESSL_CLIENT_RANDOM.get(inferior.num)
            if not cr:
                logging.debug("[LibreSSL] tls1_PRF: client_random not yet known")
                return False
            master = bytes(inferior.read_memory(secret_ptr, secret_len)).hex()
            write_keylog("CLIENT_RANDOM", cr, master)
        except gdb.error as e:
            logging.debug(f"[LibreSSL] tls1_PRF read failed: {e}")
        return False


# Maps handler name strings to their classes for JSON loading.
HANDLER_REGISTRY = {
    "LibreSSLHkdfExpandLabelWinBP": LibreSSLHkdfExpandLabelWinBP,
    "LibreSSLTls1PrfWinBP": LibreSSLTls1PrfWinBP,
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
    # LibreSSL (BoringSSL's SSL_log_secret does NOT exist in LibreSSL, and its
    # keylog callback is never invoked). Keys come from the KDF. These x86-64/
    # Win64 signatures are from curl-for-win LibreSSL 4.4.0; regenerate for other
    # builds with utils/wine_hunter.py. client_random is recovered from the
    # plaintext ClientHello written to ws2_32!send (see ensure_ws2_send_bp,
    # armed when a LibreSSL hook is installed) — it is not reachable from any KDF
    # frame, so no struct offsets / cr_chain are needed.
    "f30f1efa5541565657534881eca0000000488dac24800000": {
        "name": "libressl tls13_hkdf_expand_label_with_length windows",
        "offset": 0,
        "handler": "LibreSSLHkdfExpandLabelWinBP",
    },
    "f30f1efa5541574156415541545657534881ecd8000000": {
        "name": "libressl tls1_PRF windows",
        "offset": 0,
        "handler": "LibreSSLTls1PrfWinBP",
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
    handler_cls = HANDLER_REGISTRY[PATTERNS[pattern]["handler"]]
    bp = handler_cls("* " + hex(target_address))
    bp.inferior = gdb.selected_inferior().num
    _HOOKED.add((gdb.selected_inferior().num, target_address))
    # A KDF-only handler (LibreSSL) exposes client_random nowhere else: request
    # the ws2_32!send ClientHello capture, armed at the end of
    # find_hookable_functions (and retried on later scans until ws2_32 maps).
    if getattr(handler_cls, "needs_ws2_send_client_random", False):
        _LIBRESSL_DETECTED.add(gdb.selected_inferior().num)


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
            # Hook EVERY occurrence, not just the first. Several TLS prologues are
            # not unique within a module (e.g. LibreSSL's tls1_PRF /
            # tls13_hkdf_expand_label_with_length share their frame-setup prologue
            # with sibling functions — 7 and 2 matches respectively in
            # curl-for-win 4.4.0). mem.find() returns only the lowest address,
            # which was usually the WRONG twin, so the real KDF was never hooked.
            # The handlers filter by label / "key expansion", so breakpoints on
            # non-KDF twins are harmless no-ops.
            pos = 0
            while True:
                offset = mem.find(pattern, pos)
                if offset == -1:
                    break
                hook_function(pattern, start + offset)
                pos = offset + 1

    # Once a LibreSSL KDF hook is in, arm the ws2_32!send client_random
    # breakpoint, retrying on every scan until it lands (ensure_ws2_send_bp is
    # idempotent). ws2_32.dll is frequently mapped AFTER the app image;
    # new_objfile re-drives this scan when ws2_32 appears, and all-stop keeps the
    # app frozen at that event, so the send hook is installed before the first
    # send() call.
    if inferior_num in _LIBRESSL_DETECTED:
        try:
            ensure_ws2_send_bp()
        except Exception as e:
            logging.debug(f"[LibreSSL] ensure_ws2_send_bp retry failed: {e}")


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
    # Detach from forked children and stay on the process we attached to (the one
    # doing the TLS). With detach-on-fork OFF, all-stop cannot "resume the parent
    # over vfork while holding the child stopped" when the app vfork+execs a Wine
    # helper, so `c` aborts and gdb quits before the handshake. Detaching the
    # child lets it run free while our breakpoints stay live in the parent.
    gdb.execute("set detach-on-fork on")
    gdb.execute("set breakpoint pending on")

    _connect_scan_events()

    # Keep SIGSTOP/SIGCONT quiet and non-stopping: the launcher freezes the app
    # with SIGSTOP before we attach (so a one-shot like curl can't finish its
    # handshake before the hooks are in — see _find_wine_app_pid(freeze=True)),
    # then resumes it with SIGCONT to the process group WHILE we are blocked in
    # `c` below. `handle all nostop` already covers these, but be explicit.
    gdb.execute("handle SIGSTOP nostop noprint pass")
    gdb.execute("handle SIGCONT nostop noprint pass")

    logging.info(f"attaching to {pid}")
    gdb.execute(f"attach {pid}")

    find_hookable_functions()

    # Signal the launcher that hooks are installed, so it can SIGCONT the frozen
    # app. Touching this is safe to race against the `c` below: the app is held
    # ptrace-stopped until `c` regardless of when the SIGCONT lands, so it only
    # clears the external group-stop. No-op outside the freeze-on-attach flow.
    ready_file = os.environ.get("FRITAP_WINE_READY_FILE")
    if ready_file:
        try:
            open(ready_file, "w").close()
        except OSError as e:
            logging.debug(f"could not write ready file {ready_file}: {e}")

    # Hooks are installed above (synchronously, before any continue), so the app
    # cannot reach TLS until this `c`. In all-stop, `c` blocks until the target
    # exits, keeping the breakpoints live for the whole run; the launcher's
    # SIGCONT clears the external group-stop once we are here.
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
