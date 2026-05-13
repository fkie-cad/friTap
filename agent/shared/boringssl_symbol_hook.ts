import { get_hex_string_from_byte_array } from "./shared_functions.js";
import { sendKeylog } from "./shared_structures.js";
import { devlog, devlog_debug, devlog_error } from "../util/log.js";
import { safeKeyLenLogged } from "./keylog_length.js";
import { LruMap } from "./lru.js";
import {
    CLIENT_RANDOM_CACHE_MAX,
    tryReadClientRandomAt,
} from "./ssl_struct_walk.js";

/*
 * Shared BoringSSL ssl_log_secret hook.
 *
 * Acts as a unified fallback for every library tagged libraryType: "boringssl"
 * when its primary key-extraction mechanism (byte-pattern scan for Cronet
 * variants, SSL_CTX_set_keylog_callback interception for libssl / Conscrypt)
 * cannot install. The function bssl::ssl_log_secret is internal BoringSSL,
 * called unconditionally from the handshake regardless of whether a keylog
 * callback was registered, with stable signature
 *
 *     bssl::ssl_log_secret(SSL const*, char const*, Span<u8 const>)
 *
 * which lays out as (ssl, label, data, size) on every supported ABI.
 *
 * The resolver is a chain of strategies; new ones can be appended without
 * touching call sites.
 */

// Known C++-mangled names of bssl::ssl_log_secret across BoringSSL versions.
// Add new entries here as we observe them in the wild.
export const BORINGSSL_SSL_LOG_SECRET_MANGLED: string[] = [
    // Span<const uint8_t> form (newer BoringSSL, observed in libwarp_mobile.so)
    "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE",
    // Older raw-pointer + length form
    "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcPKhm",
];

export interface SymbolResolution {
    address: NativePointer;
    via: string;
    symbolName: string;
}

/**
 * Single-pass scan of mod.enumerateSymbols() that ranks hits by priority:
 *   1. Known C++-mangled name (highest — return immediately)
 *   2. Exact unmangled "ssl_log_secret"
 *   3. Any function-typed symbol containing "log_secret"
 * `enumerateSymbols()` is the most expensive call in the install path on
 * stripped libs (tens of thousands of entries → tens of MB of JS objects);
 * the previous chain re-walked it three times.
 */
function scanSymbolsRanked(mod: Module): SymbolResolution | null {
    const wantedMangled = new Set(BORINGSSL_SSL_LOG_SECRET_MANGLED);
    let exact: SymbolResolution | null = null;
    let substr: SymbolResolution | null = null;
    for (const s of mod.enumerateSymbols()) {
        if (wantedMangled.has(s.name)) {
            return { address: s.address, via: "mangled-exact", symbolName: s.name };
        }
        if (!exact && s.name === "ssl_log_secret") {
            exact = { address: s.address, via: "exact-name", symbolName: s.name };
        }
        if (!substr && s.type === "function" && s.name.toLowerCase().includes("log_secret")) {
            substr = { address: s.address, via: "symbol-substring", symbolName: s.name };
        }
    }
    return exact ?? substr;
}

function lookupViaDebugSymbol(mod: Module): SymbolResolution | null {
    try {
        const d = DebugSymbol.fromName("bssl::ssl_log_secret");
        if (d && !d.address.isNull() && d.moduleName === mod.name) {
            return {
                address: d.address,
                via: "debugsymbol",
                symbolName: d.name ?? "bssl::ssl_log_secret",
            };
        }
    } catch (_) {
        /* DebugSymbol.fromName throws on unresolved names */
    }
    return null;
}

function scanExports(mod: Module): SymbolResolution | null {
    // ssl_log_secret is usually NOT exported in BoringSSL, but cheap to try
    // last for forks that re-export it.
    for (const e of mod.enumerateExports()) {
        if (e.type === "function" && e.name.toLowerCase().includes("log_secret")) {
            return { address: e.address, via: "export-substring", symbolName: e.name };
        }
    }
    return null;
}

type Strategy = (mod: Module) => SymbolResolution | null;

const strategies: Strategy[] = [
    scanSymbolsRanked,
    lookupViaDebugSymbol,
    scanExports,
    // Future strategies (xref scan from SSL_CTX_set_keylog_callback,
    // Capstone-driven prologue match, etc.) go here.
];

export function resolveSslLogSecretSymbol(mod: Module): SymbolResolution | null {
    for (const strat of strategies) {
        try {
            const r = strat(mod);
            if (r) {
                devlog(
                    `[boringssl-sym] ${mod.name}: resolved via ${r.via} -> ${r.symbolName} @ ${r.address}`
                );
                return r;
            }
        } catch (e) {
            devlog_debug(`[boringssl-sym] strategy threw on ${mod.name}: ${e}`);
        }
    }
    devlog_debug(`[boringssl-sym] ${mod.name}: no ssl_log_secret found via symbols`);
    return null;
}

/**
 * Returns true if `addr` is a real, non-null NativePointer. Used by the
 * loader and the legacy *_execute wrappers to detect "primary keylog API
 * couldn't be resolved" (in which case the entry in `addresses` is undefined
 * — readAddresses doesn't write a key on resolution failure).
 */
export function isResolvedSymbol(addr: NativePointer | undefined | null): boolean {
    return !!addr && !addr.isNull();
}

export type DumpKeysCb = (
    labelPtr: NativePointer,
    sslPtr: NativePointer,
    secretPtr: NativePointer,
    secretLen: number
) => void;

export function attachSslLogSecretHook(addr: NativePointer, cb: DumpKeysCb): boolean {
    try {
        Interceptor.attach(addr, {
            onEnter(args) {
                // bssl::ssl_log_secret(SSL const*, char const*, Span<u8 const>)
                // ABI: arg0=ssl, arg1=label, arg2=secret.data(), arg3=secret.size()
                cb(args[1], args[0], args[2], args[3].toUInt32());
            },
        });
        return true;
    } catch (e) {
        devlog_error(`[boringssl-sym] Interceptor.attach failed: ${e}`);
        return false;
    }
}

/**
 * Default 1-second wait used by scheduleBoringSSLSymbolFallback. Pattern-based
 * hookers fan out async Memory.scan calls during install; the timer outlasts
 * that scan tree so no_hooking_success has settled before we read it.
 */
export const PATTERN_HOOKING_SETTLE_MS = 1000;

/**
 * Schedules the BoringSSL symbol-hook rescue path for legacy pattern-based
 * Cronet wrappers. Centralises the load-bearing invariant that the rescue
 * MUST still fire when execute_hooks() threw before producing a hooker (the
 * `hooker === null` arm). Each platform supplies its own hooker-fallback
 * (typically `() => instance.execute_symbol_based_hooking(hooker)`) and its
 * own dumpKeys forwarder so 3-arg vs 4-arg dumpKeys signatures stay opaque
 * to the helper.
 */
export function scheduleBoringSSLSymbolFallback(
    moduleName: string,
    hooker: { no_hooking_success: boolean } | null,
    runHookerFallback: () => void,
    dumpKeys: DumpKeysCb,
    delayMs: number = PATTERN_HOOKING_SETTLE_MS,
): void {
    setTimeout(() => {
        try {
            if (hooker !== null) {
                runHookerFallback();
            } else {
                devlog_debug(`Trying symbol-based ssl_log_secret hook on ${moduleName} (no hooker available)`);
                installBoringSSLSymbolHook(moduleName, dumpKeys);
            }
        } catch (e) {
            devlog_error(`Error in BoringSSL symbol fallback for ${moduleName}: ${e}`);
        }
    }, delayMs);
}

/**
 * One-call composition: resolve the symbol on `moduleName` and attach the
 * interceptor. Returns true iff both steps succeed.
 */
export function installBoringSSLSymbolHook(moduleName: string, dumpKeys: DumpKeysCb): boolean {
    let mod: Module;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        devlog_debug(`[boringssl-sym] ${moduleName} not loaded yet: ${e}`);
        return false;
    }
    const r = resolveSslLogSecretSymbol(mod);
    if (!r) return false;
    const ok = attachSslLogSecretHook(r.address, dumpKeys);
    if (ok) {
        devlog(
            `Installed ssl_log_secret() hook on ${moduleName} via symbol (${r.via}).`
        );
    }
    return ok;
}

/* ------------------------------------------------------------------------- *
 *  boringSslDumpKeys
 *
 *  Reusable free-function variant of the dumpKeys body in
 *  agent/tls/libs/cronet.ts:147. Used by the symbol-based fallback for
 *  BoringSSL libs that don't have a Cronet-class instance to forward to
 *  (libssl, Conscrypt, etc.).
 *
 *  Format: emits a standard NSS-keylog line:
 *      <LABEL> <client_random_hex> <secret_hex>
 * ------------------------------------------------------------------------- */

const clientRandomCache = new LruMap<string, string>(CLIENT_RANDOM_CACHE_MAX);

function s3OffsetForArch(): number | null {
    switch (Process.arch) {
        case "x64":
        case "arm64":
            return 0x30;
        case "ia32":
        case "arm":
            return 0x2c;
        default:
            return null;
    }
}

function readClientRandom(sslStructPtr: NativePointer): string {
    if (sslStructPtr.isNull()) return "";

    const cacheKey = sslStructPtr.toString();
    const cached = clientRandomCache.get(cacheKey);
    if (cached !== undefined) return cached;

    const primary = s3OffsetForArch();
    if (primary === null) {
        devlog("[boringssl-sym] unsupported architecture for client_random extraction");
        return "";
    }

    // Probe order: arch-primary first (covers stock BoringSSL), then the
    // opposite-width primary, then two nearby slots observed in WARP's fork.
    const alt = primary === 0x30 ? 0x2c : 0x30;
    const candidates = [primary, alt, 0x28, 0x38];

    for (const off of candidates) {
        const cr = tryReadClientRandomAt(sslStructPtr, off);
        if (cr) {
            if (off !== primary) {
                devlog_debug(
                    `[boringssl-sym] client_random recovered via fallback s3 offset 0x${off.toString(16)}`
                );
            }
            clientRandomCache.set(cacheKey, cr);
            return cr;
        }
    }

    // Negative-cache the failure so repeated keylog calls on the same SSL*
    // (5x per TLS 1.3 session) don't re-probe four offsets and re-log.
    devlog_debug("[boringssl-sym] client_random not recoverable via struct walk");
    clientRandomCache.set(cacheKey, "");
    return "";
}

export function boringSslDumpKeys(
    labelPtr: NativePointer,
    sslStructPtr: NativePointer,
    keyPtr: NativePointer,
    keyLen: number
): void {
    const labelStr = labelPtr.isNull() ? "" : labelPtr.readCString() ?? "";
    const clientRandom = readClientRandom(sslStructPtr);

    let secretHex = "";
    let loggedLen = keyLen;
    if (!keyPtr.isNull()) {
        // No class-level byte-walk available here; default closure returns 32.
        const { len } = safeKeyLenLogged(keyLen, labelStr, keyPtr, () => 32);
        loggedLen = len;
        try {
            const buf = keyPtr.readByteArray(len);
            secretHex = get_hex_string_from_byte_array(buf);
        } catch (e) {
            devlog_debug(`[boringssl-sym] secret read failed: ${e}`);
        }
    }

    // Mirrors standalone/libwarp_mobile_ssl_log_secret.js:209 — line-for-line
    // diffable when cross-validating friTap against the standalone reference.
    devlog_debug(
        `[ssl_log_secret] label=${labelStr} ssl=${sslStructPtr} len=${loggedLen} secret=${secretHex}`
    );

    sendKeylog(`${labelStr} ${clientRandom} ${secretHex}`);
}
