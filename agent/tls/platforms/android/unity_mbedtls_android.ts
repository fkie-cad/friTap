// agent/tls/platforms/android/unity_mbedtls_android.ts
//
// TLS key extraction for Unity's statically-linked MbedTLS (UnityTLS), used by
// native UnityWebRequest traffic. Unity builds MbedTLS 3.x WITHOUT the
// export-keys API (MBEDTLS_SSL_EXPORT_KEYS is compiled out), so there is no
// callback to register and no exported symbols. We instead OFFSET-hook the
// master-secret computation (ssl_compute_master) and SCRAPE the master secret +
// client_random from the mbedtls_ssl_context, emitting a TLS1.2-style
// `CLIENT_RANDOM <client_random> <master_secret>` keylog line (Wireshark-compatible).
//
// Offsets are BUILD-SPECIFIC (per Unity/libunity version). The function offset
// MUST be supplied via --offsets keyed by the module name (e.g. "libunity.so"):
//   { "libunity.so": { "ssl_compute_master": {"address":"0xf76600","absolute":false} } }
// The mbedtls_ssl_context struct field offsets default to the analyzed MbedTLS 3.x
// layout and can be overridden via the same offsets block if a build differs.
//
// NOTE: unlike the BoringSSL keylog-callback (a heap data-field), this is an
// INLINE hook on libunity .text that must remain resident to scrape each
// handshake — so it does NOT participate in the pairip-safe "blink" persistence
// and carries a higher integrity-check detection risk if PairIP checksums
// libunity. TLS 1.3 is not covered (Unity's MbedTLS here is TLS1.2-only).

import { offsets } from "../../../fritap_agent.js";
import { sendKeylog } from "../../../shared/shared_structures.js";
import { get_hex_string_from_byte_array } from "../../../shared/shared_functions.js";
import { log, devlog, devlog_error } from "../../../util/log.js";

// MbedTLS 3.x struct layout (analyzed from libunity; overridable via --offsets).
const DEFAULTS = {
    ssl_session_negotiate: 0x68, // mbedtls_ssl_context.session_negotiate*
    ssl_handshake: 0x70,         // mbedtls_ssl_context.handshake*
    session_master: 0x40,        // mbedtls_ssl_session.master[48]
    handshake_randbytes: 0x3f0,  // handshake.randbytes[64] (client[32]@+0, server[32]@+32)
    master_len: 48,
    client_random_len: 32,
};

/** Read a numeric struct offset from --offsets (relative add), else the default. */
function structOff(modName: string, key: keyof typeof DEFAULTS): number {
    try {
        const o: any = (offsets as any)?.[modName] ?? (offsets as any)?.["libunity"];
        const v = o?.[key];
        if (v && typeof v.address === "string") return parseInt(v.address, 16);
    } catch (e) { /* fall through */ }
    return DEFAULTS[key];
}

// Built-in ssl_compute_master offsets for known libunity builds, keyed by the
// in-memory module SIZE (a cheap, reliable per-build discriminator). Used ONLY
// when --offsets supplies nothing, so attach is turnkey on a known build
// without the caller hand-passing an offset. A size MISMATCH yields no built-in:
// we never apply a guessed offset to an unknown build (a wrong .text address
// would risk a crash). Extend this table as new libunity builds are analysed.
const UNITY_BUILTIN_COMPUTE_MASTER: { [size: number]: number } = {
    22892544: 0xf76600, // com.blizzard.arc (Warcraft Rumble 16.53.0), libunity.so arm64
};

// Definitive-verdict instrumentation: how many times ssl_compute_master actually
// fired. 0 after the watch window == "Unity MbedTLS is NOT exercised by this
// app" (it may route TLS through Chromium/Cronet/Conscrypt instead), which is
// the open question for PAIRIP_SAFE_HANDOFF Image-#2 row (d).
let unityComputeMasterFireCount = 0;

/**
 * Resolve the ssl_compute_master hook address from EXPLICIT --offsets only.
 *
 * The built-in profile is intentionally NOT auto-applied: this is an inline
 * .text hook on an APP-BUNDLED lib (libunity sits in the split APK, inside
 * PairIP's code-integrity checksum scope) and, unlike the BoringSSL keylog
 * callback, it does NOT participate in blink — so a PairIP sweep that lands on
 * the patched .text SIGSEGVs the app (observed: death marker
 * "install-tls-hooks: libunity.so"). On com.blizzard.arc the hook was also
 * measured as never-firing (fire-count 0, idle and startup). So the inline hook
 * is opt-in: pass --offsets to force it. builtinComputeMasterOffset() supplies
 * the known offset only as a copy-paste hint in the skip message.
 */
function resolveComputeMaster(modName: string, base: NativePointer): NativePointer | null {
    const o: any = (offsets as any)?.[modName] ?? (offsets as any)?.["libunity"];
    const v = o?.["ssl_compute_master"];
    if (v && typeof v.address === "string") {
        const addr = ptr(v.address);
        return v.absolute ? addr : base.add(addr);
    }
    return null;
}

/** Known ssl_compute_master offset for this build (size-keyed) — hint only. */
function builtinComputeMasterOffset(modName: string): number | undefined {
    try {
        return UNITY_BUILTIN_COMPUTE_MASTER[Process.getModuleByName(modName).size];
    } catch (e) {
        return undefined;
    }
}

// Resolved mbedtls_ssl_context field offsets for one libunity build.
interface UnityStructOffsets {
    sess: number; hs: number; master: number; rand: number;
    masterLen: number; crLen: number;
}

/** Increment the fire-count and log first-fire / periodic milestones. */
function recordComputeMasterFire(moduleName: string): void {
    unityComputeMasterFireCount++;
    if (unityComputeMasterFireCount === 1) {
        log(`[unity-mbedtls] ${moduleName}: ssl_compute_master FIRED (first time) — Unity MbedTLS IS exercised by this app.`);
    } else if (unityComputeMasterFireCount % 10 === 0) {
        devlog(`[unity-mbedtls] ${moduleName}: ssl_compute_master fire-count=${unityComputeMasterFireCount}`);
    }
}

/** Scrape master secret + client_random from the mbedtls_ssl_context and emit a TLS1.2 keylog line. */
function scrapeAndEmitMasterSecret(ssl: NativePointer, O: UnityStructOffsets, moduleName: string): void {
    try {
        if (ssl.isNull()) return;
        const sess = ssl.add(O.sess).readPointer();
        const hs = ssl.add(O.hs).readPointer();
        if (sess.isNull() || hs.isNull()) return;
        const master = sess.add(O.master).readByteArray(O.masterLen);
        const cr = hs.add(O.rand).readByteArray(O.crLen);
        if (!master || !cr) return;
        const line = `CLIENT_RANDOM ${get_hex_string_from_byte_array(cr)} ${get_hex_string_from_byte_array(master)}`;
        devlog(`[unity-mbedtls] ${moduleName}: ${line.slice(0, 40)}...`);
        sendKeylog(line);
    } catch (e) {
        devlog_error(`[unity-mbedtls] scrape error: ${e}`);
    }
}

/** Schedule fire-count summaries so a 0 count gives a definitive "not exercised" verdict. */
function scheduleFireCountReports(moduleName: string): void {
    const reportCount = (secs: number) => log(
        `[unity-mbedtls] ${moduleName}: ssl_compute_master fire-count after ${secs}s = ${unityComputeMasterFireCount}`
        + (unityComputeMasterFireCount === 0 ? " (Unity MbedTLS NOT exercised in this window)" : ""));
    setTimeout(() => reportCount(30), 30000);
    setTimeout(() => reportCount(120), 120000);
}

export function unity_mbedtls_execute(moduleName: string, is_base_hook: boolean): void {
    let base: NativePointer;
    try {
        base = Process.getModuleByName(moduleName).base;
    } catch (e) {
        devlog_error(`[unity-mbedtls] ${moduleName} not resolvable: ${e}`);
        return;
    }

    const hookAddr = resolveComputeMaster(moduleName, base);
    if (hookAddr === null) {
        const builtin = builtinComputeMasterOffset(moduleName);
        const hintAddr = builtin !== undefined ? `0x${builtin.toString(16)}` : "0x...";
        log(`[!] ${moduleName}: Unity MbedTLS inline hook SKIPPED (opt-in). It patches an app-bundled lib inside PairIP's checksum scope and does NOT blink, so it risks a SIGSEGV; on this title its TLS was measured as not-exercised. To force it: --offsets '{"${moduleName}":{"ssl_compute_master":{"address":"${hintAddr}","absolute":false}}}' (TLS1.2 CLIENT_RANDOM scrape).`);
        return;
    }

    const O = {
        sess: structOff(moduleName, "ssl_session_negotiate"),
        hs: structOff(moduleName, "ssl_handshake"),
        master: structOff(moduleName, "session_master"),
        rand: structOff(moduleName, "handshake_randbytes"),
        masterLen: DEFAULTS.master_len,
        crLen: DEFAULTS.client_random_len,
    };

    try {
        Interceptor.attach(hookAddr, {
            onEnter(args: any) { this.ssl = args[0]; },
            onLeave() {
                recordComputeMasterFire(moduleName);
                scrapeAndEmitMasterSecret(this.ssl, O, moduleName);
            },
        });
        log(`[*] ${moduleName}: Unity MbedTLS keylog (TLS1.2 CLIENT_RANDOM scrape) installed @ ${hookAddr} (via --offsets)`);
        // Definitive negative/positive: a 0 fire-count after the watch window
        // attributes "0 keys" to "Unity TLS not exercised" rather than a broken hook.
        scheduleFireCountReports(moduleName);
    } catch (e) {
        devlog_error(`[unity-mbedtls] failed to hook ssl_compute_master @ ${hookAddr}: ${e}`);
    }
}

// Modern and legacy share the same offset-based memory scrape (no symbols, no
// classes involved) — the allowlist references this for both.
export const unity_mbedtls_execute_modern = unity_mbedtls_execute;
