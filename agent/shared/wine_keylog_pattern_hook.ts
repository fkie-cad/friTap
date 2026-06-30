// agent/shared/wine_keylog_pattern_hook.ts
//
// Dual-ABI, pattern-scanned keylog extraction for Wine targets (x86-64).
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
// The export-resolving + args[]-reading Windows TLS executors silently read the
// wrong registers for PE code, and never catch schannel's internal gnutls use.
//
// This module instead scans loaded modules for the BYTE SIGNATURE of the
// internal keylog / secret-logging function and, at each match, reads the
// arguments straight from the CPU registers matching that signature's ABI via
// `this.context`. This mirrors agent/tls/decoders/gotls_registers.ts, which
// already reads registers directly for Go's non-System-V ABI.
//
// The byte signatures and struct offsets are taken from the research PoC in
// research/wine/tls_wine/ (combined.py, gdb_hook_forks.py,
// magic_bytes_gnutls_vlc.txt).
//
// EXPERIMENTAL. x86-64 only.

import { toHexString } from "../util/hex.js";
import { sendKeylog } from "./shared_structures.js";
import { log, devlog, devlog_error } from "../util/log.js";

type WineAbi = "sysv" | "win64";

interface WineKeylogSig {
    /** Human-readable id used in logs and as the pattern.json action key. */
    id: string;
    /** "openssl" also covers LibreSSL. */
    library: "gnutls" | "openssl";
    abi: WineAbi;
    /** Space-separated hex byte pattern (x86-64). Frida Memory.scan syntax. */
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
 *   sysv:  arg0=rdi(session/SSL) arg1=rsi(label) arg2=rdx(secret) arg3=rcx(size)
 *   win64: arg0=rcx(session/SSL) arg1=rdx(label) arg2=r8(secret)  arg3=r9(size)
 *
 * NOTE: _gnutls_call_keylog_func / SSL_log_secret pass the secret as a raw
 * (pointer, size) pair — NOT a gnutls_datum_t. This differs from the public
 * gnutls keylog callback path; we follow the internal-function contract here.
 */
export function readWineKeylogLine(
    ctx: X64CpuContext,
    sig: WineKeylogSig,
): string | null {
    const [a0, a1, a2, a3] =
        sig.abi === "win64"
            ? [ctx.rcx, ctx.rdx, ctx.r8, ctx.r9]
            : [ctx.rdi, ctx.rsi, ctx.rdx, ctx.rcx];

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
 * shape, "wine" platform, "x64" arch):
 *
 *   modules.<library>.wine.x64.<sig.id>.{primary,fallback}
 *
 * Returns an ordered list of pattern strings to try (primary, then fallbacks).
 */
function resolvePatterns(sig: WineKeylogSig, userPatterns: any): string[] {
    try {
        const node =
            userPatterns?.modules?.[sig.library]?.wine?.x64?.[sig.id];
        if (node) {
            const list: string[] = [];
            for (const key of ["primary", "fallback", "second_fallback"]) {
                const p = node[key];
                if (typeof p === "string" && p.length > 0) list.push(p);
            }
            if (list.length > 0) {
                devlog(`[Wine] Using --patterns override for ${sig.id}`);
                return list;
            }
        }
    } catch (e) {
        devlog_error(`[Wine] Error reading --patterns override for ${sig.id}: ${e}`);
    }
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
                const line = readWineKeylogLine(
                    this.context as X64CpuContext,
                    sig,
                );
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

/** Scan pre-enumerated ranges for `pattern`, attaching on each match.
 *  Returns true if at least one match was found. */
function scanRangesForPattern(
    ranges: RangeDetails[],
    pattern: string,
    sig: WineKeylogSig,
    modName: string,
): boolean {
    let found = false;
    for (const range of ranges) {
        try {
            const matches = Memory.scanSync(range.base, range.size, pattern);
            for (const m of matches) {
                attachKeylogHook(m.address, sig);
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
    if (Process.arch !== "x64") {
        devlog(
            `[Wine] keylog pattern hooking supports x86-64 only (arch=${Process.arch}); skipping.`,
        );
        return;
    }

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
    const sigPatterns = WINE_KEYLOG_SIGNATURES.map((sig) => ({
        sig,
        patterns: resolvePatterns(sig, userPatterns),
    }));

    for (const mod of modules) {
        // Enumerate this module's executable ranges once, then scan every
        // signature/pattern against them.
        const ranges = enumerateExecRanges(mod);
        if (ranges.length === 0) continue;
        for (const { sig, patterns } of sigPatterns) {
            // Try patterns in order; stop at the first that hits in this module.
            for (const pattern of patterns) {
                if (scanRangesForPattern(ranges, pattern, sig, mod.name)) break;
            }
        }
    }
}
