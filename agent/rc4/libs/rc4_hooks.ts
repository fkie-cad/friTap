/**
 * agent/rc4/libs/rc4_hooks.ts — cross-platform RC4 key-setup hooks.
 *
 * Recovers the RC4 *key* at the moment a program builds an RC4 key schedule,
 * across the RC4-bearing crypto libraries and the Windows crypto providers, and
 * emits each recovered key on the GENERIC private-key-material channel
 * (`sendKeyMaterial({contentType:"private_key_material", classifier:"rc4", …})`).
 * The host router (friTap/message_router.py::_emit_private_key_material) routes
 * that verbatim to the RC4 keylog formatter — no message-router changes needed.
 *
 * Hook targets (resolved by export name; each is skipped gracefully when absent):
 *   - OpenSSL / LibreSSL / BoringSSL (decrepit):  RC4_set_key(RC4_KEY*, int len, const uchar* data)
 *   - Nettle / GnuTLS:                            nettle_arcfour_set_key(ctx, size_t len, const uint8_t* key)
 *   - mbedTLS:                                    mbedtls_arc4_setup(ctx, const uchar* key, uint keylen)
 *   - Windows CNG (bcrypt.dll):                   BCryptOpenAlgorithmProvider + BCryptGenerateSymmetricKey
 *   - Windows legacy CryptoAPI (advapi32.dll):    CryptEncrypt + CryptGetKeyParam(KP_ALGID) + CryptExportKey
 *
 * Ported from research/memory_scan_lsass/agent/rc4_decrypt.js. This file only
 * hooks key SETUP; it does not scan memory or decrypt (those are separate
 * workstreams).
 */

import { devlog, log } from "../../util/log.js";
import { keylog_enabled, sendKeyMaterial } from "../../shared/shared_structures.js";
import {
    RC4_KAT_KEY, RC4_KAT_PLAINTEXT, RC4_KAT_CIPHERTEXT_HEX,
    CALG_RC4, KP_ALGID, PLAINTEXTKEYBLOB,
    RC4_MIN_KEY_LEN, RC4_MAX_KEY_LEN,
} from "../definitions/rc4.js";

// ---------------------------------------------------------------------------
// Hex + guarded reads (ported from rc4_decrypt.js: a guarded read returns null
// on a faulting/unmapped page instead of throwing).
// ---------------------------------------------------------------------------

export function hexBytes(u: Uint8Array): string {
    let s = "";
    for (let i = 0; i < u.length; i++) s += (u[i] < 16 ? "0" : "") + u[i].toString(16);
    return s;
}

function asciiBytes(str: string): Uint8Array {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
    return out;
}

export function readBytes(addr: NativePointer, len: number): Uint8Array | null {
    try {
        const buf = addr.readByteArray(len);
        return buf === null ? null : new Uint8Array(buf);
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// RC4 core + known-answer self test (RC4("Key","Plaintext") == bbf316e8d940af0ad3).
// ---------------------------------------------------------------------------

function rc4Ksa(key: Uint8Array): Uint8Array {
    const S = new Uint8Array(256);
    let i: number, j = 0, t: number;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.length]) & 0xff;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    return S;
}

export function rc4Prga(S: Uint8Array, data: Uint8Array): Uint8Array {
    const s = S.slice(), out = new Uint8Array(data.length);
    let i = 0, j = 0, n: number, t: number;
    for (n = 0; n < data.length; n++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        t = s[i]; s[i] = s[j]; s[j] = t;
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff];
    }
    return out;
}

export function rc4(key: Uint8Array, data: Uint8Array): Uint8Array {
    return rc4Prga(rc4Ksa(key), data);
}

/** Assert the RC4 known-answer vector; throws on mismatch. Called at load. */
export function selfTest(): boolean {
    const got = hexBytes(rc4(asciiBytes(RC4_KAT_KEY), asciiBytes(RC4_KAT_PLAINTEXT)));
    if (got !== RC4_KAT_CIPHERTEXT_HEX) {
        throw new Error(`RC4 KAT failed: ${got} != ${RC4_KAT_CIPHERTEXT_HEX}`);
    }
    return true;
}

let rc4SelfTestRan = false;

/**
 * Run the RC4 KAT once, on the first real RC4 hook install. Deliberately NOT at
 * module load: agent/rc4/index.ts is side-effect imported into every agent build,
 * so a load-time KAT ran (and logged) for every session regardless of --protocol.
 * Non-fatal: a broken KAT is reported but disables nothing.
 */
export function ensureRc4SelfTest(): void {
    if (rc4SelfTestRan) return;
    rc4SelfTestRan = true;
    try {
        selfTest();
        devlog("[rc4] RC4 self-test OK");
    } catch (e: any) {
        log(`[rc4] RC4 self-test FAILED: ${e && e.message ? e.message : e}`);
    }
}

// ---------------------------------------------------------------------------
// Export resolution + attach (Frida-17 compatible), ported from rc4_decrypt.js.
// Frida 17 removed the static Module.findExportByName(module, name); use the
// module instance's findExportByName/getExportByName and the global
// Module.getGlobalExportByName as fallbacks.
// ---------------------------------------------------------------------------

export function resolveExport(mod: string, name: string): NativePointer | null {
    const M: any = Module;
    const P: any = Process;
    try {
        const m = P.findModuleByName ? P.findModuleByName(mod) : null;
        if (m) {
            if (typeof m.findExportByName === "function") { const a = m.findExportByName(name); if (a) return a; }
            if (typeof m.getExportByName === "function") { try { const b = m.getExportByName(name); if (b) return b; } catch (e) { /* not present */ } }
        }
    } catch (e) { /* fall through */ }
    try { if (typeof M.findExportByName === "function") { const c = M.findExportByName(mod, name); if (c) return c; } } catch (e) { /* */ }
    try { if (typeof M.getGlobalExportByName === "function") { const d = M.getGlobalExportByName(name); if (d) return d; } } catch (e) { /* */ }
    try { if (typeof M.findGlobalExportByName === "function") { const f = M.findGlobalExportByName(name); if (f) return f; } } catch (e) { /* */ }
    return null;
}

/** One attach per (module, function) — a lib is reported loaded several times. */
const _attachedSites = new Set<string>();

function attachOnce(mod: string, fn: string, callbacks: InvocationListenerCallbacks): boolean {
    const site = `${mod}!${fn}`;
    if (_attachedSites.has(site)) return true;
    try {
        const addr = resolveExport(mod, fn);
        if (addr === null) return false;
        Interceptor.attach(addr, callbacks);
        _attachedSites.add(site);
        devlog(`[rc4] hooked ${site}`);
        return true;
    } catch (e: any) {
        devlog(`[rc4] attach ${site} failed: ${e && e.message ? e.message : e}`);
        return false;
    }
}

// ---------------------------------------------------------------------------
// Emit a recovered RC4 key on the generic private-key-material channel.
// ---------------------------------------------------------------------------

/**
 * @param keyBytes  Raw RC4 key.
 * @param source    Hook that recovered it (becomes the keylog `source` field).
 * @param direction "out" | "in" | "unknown" (key setup rarely knows direction).
 */
export function emitRc4Key(keyBytes: Uint8Array, source: string, direction: string): void {
    if (!keyBytes || keyBytes.length < RC4_MIN_KEY_LEN || keyBytes.length > RC4_MAX_KEY_LEN) return;
    const keyHex = hexBytes(keyBytes);
    // Association hint for the nested (RC4-in-TLS) case: keys set up on the same
    // thread as the RC4 record traffic group together for a downstream offline
    // decryptor. Best-effort; "-" when unavailable.
    let assoc = "-";
    try { assoc = String((Process as any).getCurrentThreadId ? Process.getCurrentThreadId() : "-"); } catch (e) { /* */ }
    sendKeyMaterial({
        contentType: "private_key_material",
        classifier: "rc4",
        key: keyHex,
        key_len: keyBytes.length,
        source: source,
        direction: direction || "unknown",
        assoc: assoc,
    });
    devlog(`[rc4] key recovered (${keyBytes.length}B) via ${source} [dir=${direction || "unknown"}]`);
}

// ---------------------------------------------------------------------------
// Executor factory — wraps a per-module installer with the shared gate every
// platform executor needs: RC4 key capture is a keys-for-offline-decrypt intent,
// so it runs only under -k (keylog_enabled); a failure in one library never
// blocks another (try/catch). Keeps the per-OS platform files DRY.
// ---------------------------------------------------------------------------

export type Rc4Installer = (moduleName: string) => boolean;
export type Rc4Executor = (moduleName: string, is_base_hook: boolean) => void;

export function makeRc4Executor(label: string, install: Rc4Installer): Rc4Executor {
    return function (moduleName: string, is_base_hook: boolean): void {
        if (!keylog_enabled) {
            devlog(`[rc4] keylog disabled (-k not set); skipping ${label} RC4 key hooks on ${moduleName}.`);
            return;
        }
        ensureRc4SelfTest();
        try {
            install(moduleName);
        } catch (e: any) {
            devlog(`[rc4] ${label} executor error on ${moduleName} (is_base_hook=${is_base_hook}): ${e && e.stack ? e.stack : e}`);
        }
    };
}

// ---------------------------------------------------------------------------
// OpenSSL / LibreSSL / BoringSSL — RC4_set_key(RC4_KEY* key, int len, const uchar* data)
// ---------------------------------------------------------------------------

export function installOpenSslRc4Hooks(moduleName: string): boolean {
    let any = false;
    any = attachOnce(moduleName, "RC4_set_key", {
        onEnter(args) {
            try {
                const len = args[1].toInt32();
                if (len >= RC4_MIN_KEY_LEN && len <= RC4_MAX_KEY_LEN) {
                    const key = readBytes(args[2], len);
                    if (key !== null) emitRc4Key(key, "RC4_set_key", "unknown");
                }
            } catch (e) { /* guarded: a miss, never a fault */ }
        },
    }) || any;
    // Optional: RC4(const RC4_KEY*, size_t, const uchar* in, uchar* out) exposes
    // only the (already-expanded) key schedule, not the key bytes, so it cannot
    // recover the key. We attach nothing to it here to avoid hot-path overhead.
    return any;
}

// ---------------------------------------------------------------------------
// Nettle / GnuTLS — nettle_arcfour_set_key(ctx, size_t len, const uint8_t* key)
// ---------------------------------------------------------------------------

export function installNettleRc4Hooks(moduleName: string): boolean {
    // Both the historical and current export names carry the same (ctx, len, key)
    // shape; try each.
    let any = false;
    for (const fn of ["nettle_arcfour_set_key", "arcfour_set_key"]) {
        any = attachOnce(moduleName, fn, {
            onEnter(args) {
                try {
                    const len = args[1].toInt32();
                    if (len >= RC4_MIN_KEY_LEN && len <= RC4_MAX_KEY_LEN) {
                        const key = readBytes(args[2], len);
                        if (key !== null) emitRc4Key(key, fn, "unknown");
                    }
                } catch (e) { /* */ }
            },
        }) || any;
    }
    return any;
}

// ---------------------------------------------------------------------------
// mbedTLS — mbedtls_arc4_setup(ctx, const uchar* key, uint keylen)
// ---------------------------------------------------------------------------

export function installMbedtlsRc4Hooks(moduleName: string): boolean {
    return attachOnce(moduleName, "mbedtls_arc4_setup", {
        onEnter(args) {
            try {
                const keylen = args[2].toInt32();
                if (keylen >= RC4_MIN_KEY_LEN && keylen <= RC4_MAX_KEY_LEN) {
                    const key = readBytes(args[1], keylen);
                    if (key !== null) emitRc4Key(key, "mbedtls_arc4_setup", "unknown");
                }
            } catch (e) { /* */ }
        },
    });
}

// ---------------------------------------------------------------------------
// Windows CNG (bcrypt.dll) — record the RC4 algorithm handle, then capture the
// pbSecret handed to BCryptGenerateSymmetricKey for that handle.
// ---------------------------------------------------------------------------

const _rc4AlgHandles: Record<string, boolean> = {};

export function installWindowsCngRc4Hooks(moduleName: string): boolean {
    let any = false;
    any = attachOnce(moduleName, "BCryptOpenAlgorithmProvider", {
        // (phAlgorithm, pszAlgId, pszImplementation, dwFlags)
        onEnter(args) {
            (this as any).phAlg = args[0];
            try { (this as any).alg = args[1].readUtf16String(); } catch (e) { (this as any).alg = ""; }
        },
        onLeave() {
            const alg = (this as any).alg;
            if (alg && String(alg).toUpperCase() === "RC4") {
                try { _rc4AlgHandles[(this as any).phAlg.readPointer().toString()] = true; } catch (e) { /* */ }
            }
        },
    }) || any;
    any = attachOnce(moduleName, "BCryptGenerateSymmetricKey", {
        // (hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags)
        onEnter(args) {
            try {
                const isRc4 = _rc4AlgHandles[args[0].toString()] === true;
                const cbSecret = args[5].toInt32();
                if (cbSecret >= RC4_MIN_KEY_LEN && cbSecret <= RC4_MAX_KEY_LEN) {
                    const key = readBytes(args[4], cbSecret);
                    // Only emit when we know it is RC4 (its alg handle was opened
                    // for "RC4"): the same call services every symmetric cipher.
                    if (key !== null && isRc4) emitRc4Key(key, "BCryptGenerateSymmetricKey", "unknown");
                }
            } catch (e) { /* */ }
        },
    }) || any;
    return any;
}

// ---------------------------------------------------------------------------
// Windows legacy CryptoAPI (advapi32.dll) — identify RC4 via
// CryptGetKeyParam(KP_ALGID)==CALG_RC4 on a CryptEncrypt call, and recover the
// key via CryptExportKey(PLAINTEXTKEYBLOB) when the key is exportable.
// ---------------------------------------------------------------------------

function queryCapiAlg(hKey: NativePointer): number {
    try {
        const fn = resolveExport("advapi32.dll", "CryptGetKeyParam");
        if (fn === null) return 0;
        const CryptGetKeyParam = new NativeFunction(fn, "int", ["pointer", "int", "pointer", "pointer", "int"]);
        const outBuf = Memory.alloc(4), lenBuf = Memory.alloc(4);
        lenBuf.writeU32(4);
        if ((CryptGetKeyParam as any)(hKey, KP_ALGID, outBuf, lenBuf, 0) !== 0) return outBuf.readU32();
    } catch (e) { /* */ }
    return 0;
}

/**
 * Best-effort raw-key recovery for a legacy CryptoAPI RC4 key. Works only when
 * the key was imported/derived with CRYPT_EXPORTABLE; otherwise the HCRYPTKEY is
 * opaque and no key bytes are available (reported once, not emitted).
 * PLAINTEXTKEYBLOB layout: BLOBHEADER(8) + DWORD keylen + key bytes.
 */
function tryExportCapiKey(hKey: NativePointer): Uint8Array | null {
    try {
        const fn = resolveExport("advapi32.dll", "CryptExportKey");
        if (fn === null) return null;
        const CryptExportKey = new NativeFunction(fn, "int", ["pointer", "pointer", "int", "int", "pointer", "pointer"]);
        const lenBuf = Memory.alloc(4);
        lenBuf.writeU32(0);
        // First call: NULL data buffer -> required blob length in *lenBuf.
        if ((CryptExportKey as any)(hKey, ptr(0), PLAINTEXTKEYBLOB, 0, ptr(0), lenBuf) === 0) return null;
        const blobLen = lenBuf.readU32();
        if (blobLen <= 12 || blobLen > 12 + RC4_MAX_KEY_LEN) return null;
        const blob = Memory.alloc(blobLen);
        if ((CryptExportKey as any)(hKey, ptr(0), PLAINTEXTKEYBLOB, 0, blob, lenBuf) === 0) return null;
        // BLOBHEADER is 8 bytes, then a DWORD keylen, then the key bytes.
        const keyLen = blob.add(8).readU32();
        if (keyLen < RC4_MIN_KEY_LEN || keyLen > RC4_MAX_KEY_LEN) return null;
        return readBytes(blob.add(12), keyLen);
    } catch (e) { return null; }
}

let _reportedNonExportable = false;

export function installWindowsCapiRc4Hooks(moduleName: string): boolean {
    return attachOnce(moduleName, "CryptEncrypt", {
        // (hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
        onEnter(args) {
            try {
                if (queryCapiAlg(args[0]) !== CALG_RC4) return;
                const key = tryExportCapiKey(args[0]);
                if (key !== null) {
                    emitRc4Key(key, "CryptEncrypt/RC4(CryptExportKey)", "out");
                } else if (!_reportedNonExportable) {
                    _reportedNonExportable = true;
                    devlog("[rc4] legacy CryptoAPI RC4 in use but key is non-exportable (HCRYPTKEY opaque); no key bytes captured.");
                }
            } catch (e) { /* */ }
        },
    });
}
