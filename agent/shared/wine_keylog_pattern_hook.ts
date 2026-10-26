// agent/shared/wine_keylog_pattern_hook.ts


// Byte-pattern-scanned keylog extraction for Wine targets, complementing the
// symbol-based gnutls_init/callback path in agent/tls/libs/gnutls.ts. This
// module is the fallback for cases where the callback path missed the session
// (attach after handshake, session resumption, sessions created via non-init
// entry points).

//
// WHY THIS EXISTS
// ---------------
// friTap injects native (Linux-host) Frida into a Wine process. On x86-64 a
// Wine process runs code in TWO calling conventions at once:
//
//   * Unix-side native .so libraries — e.g. the libgnutls.so that Wine's
//     schannel/secur32 bridges to — use the System V ABI
//     (args in rdi, rsi, rdx, rcx).
//   * PE-side Windows DLLs an app bundles — e.g. a PE-compiled libgnutls-30.dll
//     or a PE libssl — use the Win64 ABI (args in rcx, rdx, r8, r9).
//

// AArch64 Wine (mainline since Wine 9) collapses both to AAPCS64
// (args in x0..x7), a single ABI, but the internal keylog function still needs
// locating in memory.
//

// The export-resolving + args[]-reading Windows TLS executors silently read the
// wrong registers for PE code, and never catch schannel's internal gnutls use.
//
// This module instead scans loaded modules for the BYTE SIGNATURE of the
// internal keylog / secret-logging function and, at each match, reads the
// arguments straight from the CPU registers matching that signature's ABI via
// `this.context`. This mirrors agent/tls/decoders/gotls_registers.ts, which
// already reads registers directly for Go's non-System-V ABI.
//

// ARCH COVERAGE
// -------------
//   * x86-64: bundled patterns for `_gnutls_call_keylog_func` (SysV + Win64)
//     and `SSL_log_secret` (Win64). Works out of the box.
//   * arm64 / x86 / arm: no bundled patterns yet. When the user supplies
//     `--patterns` with a `wine.<arch>` block, this module scans and hooks
//     using the register set for the matching ABI. Without a --patterns
//     override, this module skips its scan on non-x86-64 and lets the
//     symbol-based path in agent/tls/libs/gnutls.ts capture keys — that
//     path is fully cross-arch and uses runtime pattern discovery.
//
// The bundled x86-64 byte signatures and struct offsets come from the research
// done by Lars Morkovsky (@marten-der-Eisbaer); see the PoC in
// research/wine/tls_wine/ (combined.py, gdb_hook_forks.py,
// magic_bytes_gnutls_vlc.txt).
//
// STATUS: experimental.

import { toHexString } from "../util/hex.js";
import { sendKeylog } from "./shared_structures.js";
import { log, devlog, devlog_error } from "../util/log.js";
import { normalizeArchKey } from "../util/process_infos.js";
import { resolveKdfPattern } from "./libressl_kdf.js";
import { argAt, type CallAbi } from "./call_abi.js";
import { TLS13_LABEL_MAP } from "../tls/definitions/shared_constants.js";
import { installLibreSslClientRandomViaSend, getLibreSslClientRandom } from "./libressl_client_random.js";

type WineAbi = CallAbi;

interface WineKeylogSig {
    /** Human-readable id used in logs and as the pattern.json action key. */
    id: string;
    /** "openssl" is BoringSSL's ssl_log_secret (LibreSSL has none; see below). */
    library: "gnutls" | "openssl";
    abi: WineAbi;

    /**
     * Space-separated hex byte pattern. For x64 signatures these are x86-64
     * bytes (SysV or Win64 ABI); for arm64 signatures they are AArch64
     * little-endian 4-byte instruction words. Frida Memory.scan syntax.
     */
    pattern: string;
    /**
     * Offset (bytes) from the session/SSL pointer (the first argument) at which
     * the 32-byte client_random lives. gnutls session: 0x50. OpenSSL SSL*: 0x184.
     */
    clientRandomOffset: number;
}

/**
 * Bundled default signatures — the exact x86-64 bytes proven in the research
 * PoC. Users can override/extend per app+version via --patterns (see
 * resolvePattern()). The two gnutls variants are the highest value because they
 * also cover Windows schannel, which delegates to gnutls under Wine.
 */
const WINE_KEYLOG_SIGNATURES: WineKeylogSig[] = [
    {
        // _gnutls_call_keylog_func, native .so (System V ABI). Covers schannel.
        id: "gnutls_keylog_sysv",
        library: "gnutls",
        abi: "sysv",
        pattern:
            "F3 0F 1E FA 55 49 89 D0 89 CA 48 89 E5 48 83 EC 20 48 8B 8F C0 06 00 00 64 48 8B 04 25 28 00 00 00",
        clientRandomOffset: 0x50,
    },
    {
        // _gnutls_call_keylog_func, PE-compiled gnutls DLL (Win64 ABI).
        id: "gnutls_keylog_win64",
        library: "gnutls",
        abi: "win64",
        pattern: "48 83 EC 38 4C 8B 91 60 06 00 00 31 C0 4D 85 D2 74 12 4C 89 44",
        clientRandomOffset: 0x50,
    },
    {
        // OpenSSL SSL_log_secret, PE-compiled libssl (Win64 ABI).
        id: "openssl_log_secret_win64",
        library: "openssl",
        abi: "win64",
        pattern:
            "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 28 48 8B 71 08 48 89 CB 4D 89 C4 4D 89 CE 48 83 BE 00 04 00 00 00",
        clientRandomOffset: 0x184,
    },
];

/** Largest plausible keylog secret is 64 bytes; reject anything absurd so a
 *  pattern that matches non-code (or the wrong ABI) doesn't dump garbage. */
function isPlausibleSecretLen(len: number): boolean {
    return len > 0 && len < 1024;
}

/**
 * Read one SSLKEYLOGFILE line ("LABEL CR_HEX SECRET_HEX") from the registers
 * present at the hooked keylog-function entry, using the register set for this
 * signature's ABI. Returns null on any null pointer / implausible length /
 * memory read error.
 *
 *   sysv    (x86-64 Linux): arg0=rdi(session/SSL) arg1=rsi(label) arg2=rdx(secret) arg3=rcx(size)
 *   win64   (Wine PE):      arg0=rcx(session/SSL) arg1=rdx(label) arg2=r8(secret)  arg3=r9(size)
 *   aarch64 (AAPCS64):      arg0=x0 (session/SSL) arg1=x1(label)  arg2=x2(secret)  arg3=x3(size)
 *
 * NOTE: _gnutls_call_keylog_func / SSL_log_secret pass the secret as a raw
 * (pointer, size) pair — NOT a gnutls_datum_t. This differs from the public
 * gnutls keylog callback path; we follow the internal-function contract here.
 */
export function readWineKeylogLine(
    ctx: CpuContext,
    sig: WineKeylogSig,
): string | null {
    const [a0, a1, a2, a3] = [0, 1, 2, 3].map((i) => argAt(ctx, sig.abi, i));

    if (a0.isNull() || a1.isNull() || a2.isNull()) return null;

    const secretLen = a3.toInt32();
    if (!isPlausibleSecretLen(secretLen)) return null;

    try {
        const label = a1.readUtf8String();
        if (!label || label.length === 0) return null;

        const crBytes = a0.add(sig.clientRandomOffset).readByteArray(32);
        const secretBytes = a2.readByteArray(secretLen);
        // readByteArray can return null on an unreadable page; bail rather than
        // emit a malformed line (toHexString(null) would otherwise throw/empty).
        if (crBytes === null || secretBytes === null) return null;

        const clientRandom = toHexString(crBytes);
        const secret = toHexString(secretBytes);
        return `${label} ${clientRandom} ${secret}`;
    } catch (e) {
        return null;
    }
}

/**
 * Resolve the byte pattern for a signature, preferring a user-supplied override
 * from --patterns over the bundled research bytes. Schema (legacy pattern.json
 * shape, "wine" platform, current arch):
 *
 *   modules.<library>.wine.<arch>.<sig.id>.{primary,fallback}
 *
 *   <arch> is "x64" | "arm64" | "x86" | "arm" — matches Frida's Process.arch
 *   through normalizeArchKey() in agent/util/process_infos.ts (the canonical
 *   arch mapping used across the codebase).
 *
 * Returns an ordered list of pattern strings to try (primary, then fallbacks).
 * On architectures where friTap ships no bundled pattern for a signature,
 * an empty list tells the caller to skip scanning that signature.
 */
function resolvePatterns(sig: WineKeylogSig, userPatterns: any): string[] {
    const archKey = normalizeArchKey(Process.arch);
    try {
        const node =
            userPatterns?.modules?.[sig.library]?.wine?.[archKey]?.[sig.id];
        if (node) {
            const list: string[] = [];
            for (const key of ["primary", "fallback", "second_fallback"]) {
                const p = node[key];
                if (typeof p === "string" && p.length > 0) list.push(p);
            }
            if (list.length > 0) {
                devlog(`[Wine] Using --patterns override (arch=${archKey}) for ${sig.id}`);
                return list;
            }
        }
    } catch (e) {
        devlog_error(`[Wine] Error reading --patterns override for ${sig.id}: ${e}`);
    }

    // Bundled patterns are x86-64 SysV/Win64 only. On other arches we return
    // an empty list so the caller skips the scan; the dynamic-discovery
    // callback path (agent/tls/libs/gnutls.ts) still catches keys.
    if (archKey !== "x64") return [];
    return [sig.pattern];
}

// Addresses we have already hooked, so re-scans across DLL loads never double
// hook the same function. Keyed by absolute address string.
const hookedAddresses: Set<string> = new Set();

function attachKeylogHook(address: NativePointer, sig: WineKeylogSig): void {
    const key = address.toString();
    if (hookedAddresses.has(key)) return;
    hookedAddresses.add(key);

    Interceptor.attach(address, {
        onEnter() {
            try {
                const line = readWineKeylogLine(this.context, sig);
                if (line) sendKeylog(line);
            } catch (e) {
                devlog_error(`[Wine] keylog read error (${sig.id}): ${e}`);
            }
        },
    });
    log(`[Wine] keylog hook installed via pattern (${sig.id} @ ${address})`);
}

/** Collect a module's executable ranges. Scans readable+executable AND
 *  readable+writable+executable — Wine's PE loader and some JIT paths map code
 *  rwx, so the research PoC scanned both ('r-x' and 'rwx' in
 *  frida_gnutls_vlc.js); r-x alone misses those. Enumerated once per module so
 *  every signature/pattern can reuse the result. */
function enumerateExecRanges(mod: Module): RangeDetails[] {
    const ranges: RangeDetails[] = [];
    for (const prot of ["r-x", "rwx"]) {
        try {
            for (const r of mod.enumerateRanges(prot)) ranges.push(r);
        } catch (e) {
            devlog(`[Wine] enumerateRanges(${prot}) failed for ${mod.name}: ${e}`);
        }
    }
    return ranges;
}

/** Scan pre-enumerated ranges for `pattern`, calling `attach` on each match.
 *  Returns true if at least one match was found. */
function scanRangesForPattern(
    ranges: RangeDetails[],
    pattern: string,
    attach: (address: NativePointer) => void,
    modName: string,
): boolean {
    let found = false;
    for (const range of ranges) {
        try {
            const matches = Memory.scanSync(range.base, range.size, pattern);
            for (const m of matches) {
                attach(m.address);
                found = true;
            }
        } catch (e) {
            // A range may become unreadable; skip it and keep going.
            devlog(`[Wine] scan skipped a range in ${modName}: ${e}`);
        }
    }
    return found;
}

/**
 * Scan loaded modules for the dual-ABI keylog/secret-logging signatures and
 * install register-reading hooks at every match.
 *
 * @param moduleFilter  Optional case-insensitive substring. When provided, only
 *                      modules whose name matches are scanned (used to scan a
 *                      single freshly-loaded DLL from the LdrLoadDll hook).
 *                      When omitted, all loaded modules are scanned once.
 * @param userPatterns  Optional parsed --patterns object for per-app overrides.
 */
export function installWineKeylogPatternHooks(
    moduleFilter?: string,
    userPatterns?: any,
): void {
    // Bundled byte signatures are x86-64 (System V + Win64 ABIs) only. On
    // arm64 / arm / x86 the bundled patterns won't match anything, but a
    // user-supplied --patterns override for the current arch WILL be applied
    // — resolvePatterns() looks up by normalizeArchKey(Process.arch). Also,
    // gnutls key extraction still works end-to-end via the symbol-based hook
    // + NativeCallback path in agent/tls/libs/gnutls.ts, so failing this
    // gate silently is not a regression — it's just skipping a fallback.
    const archKey = normalizeArchKey(Process.arch);
    const scanKeylogSigs = archKey === "x64" || !!userPatterns?.modules;
    if (!scanKeylogSigs) {
        devlog(
            `[Wine] keylog pattern hooking: no bundled ${archKey} patterns and no --patterns override; ` +
            `symbol-based gnutls hooks (native path) still active.`,
        );
    }
    const libreHkdfPatterns = resolveKdfPattern("hkdfWithLen", userPatterns);
    if (!scanKeylogSigs && libreHkdfPatterns.length === 0) return;

    let modules: Module[];
    try {
        modules = Process.enumerateModules();
    } catch (e) {
        devlog_error(`[Wine] enumerateModules failed: ${e}`);
        return;
    }

    if (moduleFilter) {
        const needle = moduleFilter.toLowerCase();
        modules = modules.filter((m) => m.name.toLowerCase().includes(needle));
    }

    // Patterns don't vary per module — resolve each signature's pattern list
    // once, not once per module.
    const sigPatterns = scanKeylogSigs
        ? WINE_KEYLOG_SIGNATURES.map((sig) => ({ sig, patterns: resolvePatterns(sig, userPatterns) }))
        : [];

    for (const mod of modules) {
        // Enumerate this module's executable ranges once, then scan every
        // signature/pattern against them.
        const ranges = enumerateExecRanges(mod);
        if (ranges.length === 0) continue;
        for (const { sig, patterns } of sigPatterns) {
            // Try patterns in order; stop at the first that hits in this module.
            for (const pattern of patterns) {
                if (scanRangesForPattern(ranges, pattern, (a) => attachKeylogHook(a, sig), mod.name)) break;
            }
        }
        for (const pattern of libreHkdfPatterns) {
            if (scanRangesForPattern(ranges, pattern, attachLibreSslHkdfHook, mod.name)) break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LibreSSL (Wine PE) — EXPERIMENTAL
//
// LibreSSL has no keylog callback and no SSL_log_secret (the openssl signature
// above is BoringSSL's ssl_log_secret, which LibreSSL does NOT have). Keys come
// from the KDF: tls13_hkdf_expand_label_with_length(out, md, secret, label,
// label_len, context) writes the derived secret into *out on return, and the
// raw TLS 1.3 label (arg3) maps to an NSS keylog label. The leaf has no SSL* in
// its frame, so client_random is recovered by parsing the plaintext ClientHello
// off the socket send() (agent/shared/libressl_client_random.ts) — no struct
// offsets needed.
//
// This is the Frida counterpart of the GDB handlers in
// agent_gdb/wine/gdb_script/gdb_wine_extract.py. For a name-matched / enumerable
// PE libssl the full LibreSSL definition (agent/tls/definitions/libressl.ts,
// with its own pattern fallback) is preferred; this hook targets the statically
// linked exe. Under Wine the send() capture is best-effort (libc send); the GDB
// backend, the default for Wine, resolves the PE ws2_32!send itself.

function currentWineAbi(): WineAbi {
    if (Process.arch === "arm64") return "aarch64";
    // Under Wine on x86-64, PE code uses the Win64 ABI.
    return "win64";
}

function attachLibreSslHkdfHook(address: NativePointer): void {
    const key = "hkdf:" + address.toString();
    if (hookedAddresses.has(key)) return;
    hookedAddresses.add(key);

    // Only needed once a LibreSSL KDF is actually present.
    installLibreSslClientRandomViaSend();

    const abi = currentWineAbi();
    Interceptor.attach(address, {
        onEnter() {
            try {
                this.outPtr = argAt(this.context, abi, 0);
                this.label = argAt(this.context, abi, 3).readCString();
            } catch (_) { this.label = null; }
        },
        onLeave() {
            try {
                if (!this.label) return;
                const nss = (TLS13_LABEL_MAP as any)[this.label];
                if (!nss) return;
                const dataPtr = (this.outPtr as NativePointer).readPointer();
                const dataLen = (this.outPtr as NativePointer).add(Process.pointerSize).readULong() as number;
                if (dataPtr.isNull() || dataLen === 0 || dataLen > 256) return;
                const cr = getLibreSslClientRandom();
                if (!cr) return;
                const secret = toHexString(dataPtr.readByteArray(dataLen));
                sendKeylog(`${nss} ${cr} ${secret}`);
            } catch (e) {
                devlog_error(`[Wine/LibreSSL] hkdf onLeave error: ${e}`);
            }
        },
    });
    log(`[Wine/LibreSSL] hkdf hook @ ${address}`);
}
