// agent/shared/keylog_callback_tracker.ts
//
// Frida glue around KeylogCallbackRegistry for the BoringSSL callback tier
// (SSL_new / SSL_CTX_new -> SSL_CTX_set_keylog_callback(ctx, <script cb>)).
// It records every CTX we write, follows its lifetime, and on teardown puts the
// previous callback back so no live CTX is left pointing at the freed
// NativeCallback.
//
// Lifetime (see keylog_callback_registry.ts for the model):
//   * Preferred -- observed destruction: when libssl imports CRYPTO_free_ex_data
//     from a separate OpenSSL 1.1/3.x libcrypto, that call with class_index ==
//     CRYPTO_EX_INDEX_SSL_CTX (1) is made only by the FINAL SSL_CTX_free, while
//     the CTX is still allocated. Hooking it (read-only) tells us exactly when a
//     CTX dies, independent of SSL_CTX_up_ref being inlined (Homebrew OpenSSL
//     3.x inlines it into ossl_ssl_init / ossl_ssl_connection_new_int).
//   * Fallback -- refcount lower bound via SSL_CTX_free / SSL_CTX_up_ref; when
//     the bound reaches 0 the previous callback is restored right inside
//     SSL_CTX_free's onEnter (the CTX is still alive there), never just dropped.
//     Used for BoringSSL (its SSL_CTX_free calls a different, class-pointer
//     CRYPTO_free_ex_data, usually module-internal), LibreSSL / OpenSSL 1.0.x
//     (different CRYPTO_EX_INDEX_SSL_CTX), statically linked builds (the call is
//     internal and may be inlined/LTO'd) and Wine-hosted DLLs (Win64 ABI).
//
// Retention: every callback handed to createKeylogCallbackTracker is also kept
// in a module-level array that is never cleared, so the NativeCallback lives
// until the script itself is destroyed -- detach (detachAll dropping the hook
// closures that referenced it) can no longer free it under a CTX that we failed
// to restore.
//
// Teardown ordering (restoreTrackedKeylogCallbacks, called by releaseAgentHooks
// BEFORE Interceptor.detachAll):
//   1. The registry is sealed first: every install() after that is a no-op, so
//      no hook can re-write our callback behind the restore.
//   2. The restore runs while the SSL_CTX_free hook is still attached and while
//      this JS thread holds the script lock. A thread entering SSL_CTX_free
//      blocks in our onEnter BEFORE the CTX is released, so every CTX we write
//      is still alive at that moment. After detachAll that guarantee is gone.
//   3. setter/getter are "exclusive" NativeFunctions: the JS lock stays held
//      across the native call, so an install on another thread can never be
//      half-way through (lock dropped, store pending) while we restore.

import { devlog } from "../util/log.js";
import { KeylogCallbackRegistry } from "./keylog_callback_registry.js";

interface TrackedCtx {
    ctx: NativePointer;
    previous: NativePointer;
    owner: TrackerImpl;
}

const registry = new KeylogCallbackRegistry<TrackedCtx>();
// moduleName -> whether its SSL_CTX_free hook is live (attached once per module).
const lifetimeHookedModules = new Map<string, boolean>();
// libssl moduleName -> whether its CTXs' destruction is observed (F1).
const destructionObservedModules = new Map<string, boolean>();
// libcrypto module name -> whether its CRYPTO_free_ex_data hook is live.
const destructionHookedLibcrypto = new Map<string, boolean>();
// Every keylog callback ever handed to a tracker. NEVER cleared: keeps each
// NativeCallback alive until script destroy (see "Retention" above).
const retainedKeylogCallbacks: NativePointer[] = [];

/** OpenSSL 1.1.0+ / 3.x value of CRYPTO_EX_INDEX_SSL_CTX (crypto.h). */
export const CRYPTO_EX_INDEX_SSL_CTX_OPENSSL_1_1 = 1;
/** Exports only BoringSSL (and its forks, e.g. AWS-LC) have. */
const BORINGSSL_LIBCRYPTO_MARKERS = ["CRYPTO_BUFFER_new", "BORINGSSL_self_test"];
const LIBCRYPTO_NAME = /^libcrypto([-_.][\w.-]*)?\.(dylib|dll|so(\.[\w.]+)?)$/i;

export interface KeylogCallbackTracker {
    /** Write our callback into `ctx` (and record it). No-op once teardown began. */
    install(ctx: NativePointer): void;
    /** The app called SSL_CTX_set_keylog_callback itself; remember its callback. */
    noteAppCallback(ctx: NativePointer, callback: NativePointer): void;
    /** True once releaseAgentHooks has started tearing the callback tier down. */
    readonly sealed: boolean;
}

function findFunction(moduleName: string, name: string): NativePointer | null {
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod === null) return null;
        const address = mod.findExportByName(name) ?? mod.findSymbolByName(name);
        return address !== null && !address.isNull() ? address : null;
    } catch (_e) {
        return null;
    }
}

/**
 * Hook SSL_CTX_free (required) and SSL_CTX_up_ref (optional) once per module.
 * Returns whether lifetime tracking is live. Never throws: a failed free hook
 * only disables restore for this module, it must not take the keylog tier down.
 * A missing/failed/bypassed (inlined) up_ref is covered by the destruction hook
 * or by the restore at refs 0 (see keylog_callback_registry.ts).
 */
function attachLifetimeHooks(moduleName: string, freeAddress: NativePointer): boolean {
    const known = lifetimeHookedModules.get(moduleName);
    if (known !== undefined) return known;
    let attached = false;
    try {
        Interceptor.attach(freeAddress, {
            // At refs 0 (fallback mode) restore while the CTX is still alive.
            onEnter(args) { registry.noteFree(args[0].toString(), (tracked) => { tracked.owner.restore(tracked); }); },
        });
        attached = true;
    } catch (e) {
        devlog(`[keylog-cb-registry] ${moduleName}: SSL_CTX_free hook failed, CTXs will not be restored: ${e}`);
    }
    lifetimeHookedModules.set(moduleName, attached);
    const upRefAddress = attached ? findFunction(moduleName, "SSL_CTX_up_ref") : null;
    if (upRefAddress !== null) {
        try {
            Interceptor.attach(upRefAddress, {
                onEnter(args) { registry.noteUpRef(args[0].toString()); },
            });
        } catch (e) {
            devlog(`[keylog-cb-registry] ${moduleName}: SSL_CTX_up_ref hook failed (refs-0 restore covers it): ${e}`);
        }
    }
    return attached;
}

/**
 * The CRYPTO_EX_INDEX_SSL_CTX class index SSL_CTX_free passes to
 * CRYPTO_free_ex_data in this libcrypto, or null when the observed-destruction
 * path must not be used. Pure policy: only OpenSSL 1.1.x (0x101xxxxx) and 3.x
 * (0x3xxxxxxx) qualify. BoringSSL reports OPENSSL_VERSION_NUMBER 0x1010107f but
 * takes a class POINTER (so must be excluded by its markers); LibreSSL reports
 * 0x20000000 and OpenSSL 1.0.x uses index 2; 4.x is unverified -- all of these
 * fall back to the refcount path.
 */
export function sslCtxExDataClassIndex(hasExport: (name: string) => boolean,
                                       versionNumber: number | null): number | null {
    if (BORINGSSL_LIBCRYPTO_MARKERS.some(hasExport)) return null;
    if (versionNumber === null) return null;
    const isOpenSsl11 = versionNumber >= 0x10100000 && versionNumber < 0x10200000;
    const isOpenSsl3 = versionNumber >= 0x30000000 && versionNumber < 0x40000000;
    return isOpenSsl11 || isOpenSsl3 ? CRYPTO_EX_INDEX_SSL_CTX_OPENSSL_1_1 : null;
}

function basename(path: string): string {
    return path.split(/[\\/]/).pop() ?? path;
}

/** A module that is not `self` and looks like libcrypto. */
function asForeignLibcrypto(mod: Module | null, self: Module): Module | null {
    if (mod === null || mod.name === self.name) return null;
    return LIBCRYPTO_NAME.test(mod.name) ? mod : null;
}

/** A loaded libcrypto in the same directory as `ssl` (last-resort lookup). */
function findSiblingLibcrypto(ssl: Module): Module | null {
    const dirOf = (path: string) => path.slice(0, path.length - basename(path).length);
    const dir = dirOf(ssl.path);
    return Process.enumerateModules().find((mod) => dirOf(mod.path) === dir
        && asForeignLibcrypto(mod, ssl) !== null) ?? null;
}

/**
 * The separate libcrypto that `moduleName` imports CRYPTO_free_ex_data from.
 * Requiring a cross-module import guarantees SSL_CTX_free really calls the
 * exported function (an internal call could be inlined and never fire).
 */
function findImportingLibcrypto(moduleName: string): Module | null {
    const ssl = Process.findModuleByName(moduleName);
    if (ssl === null || typeof (ssl as any).enumerateImports !== "function") return null;
    const imp = ssl.enumerateImports().find((i) => i.name === "CRYPTO_free_ex_data");
    if (imp === undefined) return null;
    const byAddress = imp.address ? Process.findModuleByAddress(imp.address) : null;
    const byName = imp.module ? Process.findModuleByName(basename(imp.module)) : null;
    return asForeignLibcrypto(byAddress, ssl) ?? asForeignLibcrypto(byName, ssl) ?? findSiblingLibcrypto(ssl);
}

function readOpenSslVersionNumber(crypto: Module): number | null {
    const address = crypto.findExportByName("OpenSSL_version_num");
    if (address === null || address.isNull()) return null;
    const raw = new NativeFunction(address, "ulong", [])() as unknown;
    return Number(String(raw));
}

/** Hook libcrypto's CRYPTO_free_ex_data once (read-only). Never throws. */
function attachDestructionHook(crypto: Module, classIndex: number): boolean {
    const known = destructionHookedLibcrypto.get(crypto.name);
    if (known !== undefined) return known;
    let attached = false;
    try {
        const freeExData = crypto.findExportByName("CRYPTO_free_ex_data");
        if (freeExData !== null && !freeExData.isNull()) {
            Interceptor.attach(freeExData, {
                onEnter(args) {
                    if (args[0].toInt32() === classIndex) registry.noteDestroyed(args[1].toString());
                },
            });
            attached = true;
        }
    } catch (e) {
        devlog(`[keylog-cb-registry] ${crypto.name}: CRYPTO_free_ex_data hook failed: ${e}`);
    }
    destructionHookedLibcrypto.set(crypto.name, attached);
    return attached;
}

/**
 * Whether the real destruction of `moduleName`'s SSL_CTXs can be observed (F1).
 * Cached per module; any failure means "no" (the refcount fallback applies).
 */
function observeCtxDestruction(moduleName: string): boolean {
    const known = destructionObservedModules.get(moduleName);
    if (known !== undefined) return known;
    let observed = false;
    try {
        const crypto = findImportingLibcrypto(moduleName);
        const wineHosted = crypto !== null && /\.dll$/i.test(crypto.name) && Process.platform !== "windows";
        if (crypto !== null && !wineHosted) {
            const hasExport = (name: string) => crypto.findExportByName(name) !== null;
            const classIndex = sslCtxExDataClassIndex(hasExport, readOpenSslVersionNumber(crypto));
            observed = classIndex !== null && attachDestructionHook(crypto, classIndex);
        }
    } catch (e) {
        devlog(`[keylog-cb-registry] ${moduleName}: SSL_CTX destruction not observable: ${e}`);
    }
    destructionObservedModules.set(moduleName, observed);
    return observed;
}

class TrackerImpl implements KeylogCallbackTracker {
    private readonly setter: NativeFunction<void, [NativePointer, NativePointer]>;
    private readonly getter: NativeFunction<NativePointer, [NativePointer]> | null;
    private readonly tracksLifetime: boolean;
    private readonly observesDestruction: boolean;

    constructor(moduleName: string, setterAddress: NativePointer,
                private readonly ourCallback: NativePointer, trackLifetime: boolean) {
        this.setter = new NativeFunction(setterAddress, "void", ["pointer", "pointer"], { scheduling: "exclusive" });
        const getterAddress = findFunction(moduleName, "SSL_CTX_get_keylog_callback");
        this.getter = getterAddress === null ? null
            : new NativeFunction(getterAddress, "pointer", ["pointer"], { scheduling: "exclusive" });
        const freeAddress = trackLifetime ? findFunction(moduleName, "SSL_CTX_free") : null;
        this.tracksLifetime = freeAddress !== null && attachLifetimeHooks(moduleName, freeAddress);
        this.observesDestruction = this.tracksLifetime && observeCtxDestruction(moduleName);
        devlog(`[keylog-cb-registry] ${moduleName}: lifetime tracking=${this.tracksLifetime}, ` +
            `destruction observed=${this.observesDestruction}, getter=${this.getter !== null}`);
    }

    get sealed(): boolean { return registry.sealed; }

    install(ctx: NativePointer): void {
        if (ctx.isNull() || registry.sealed) return;
        if (this.tracksLifetime) {
            registry.recordInstall(ctx.toString(), () => ({ ctx, previous: this.readPrevious(ctx), owner: this }),
                this.observesDestruction);
        }
        this.setter(ctx, this.ourCallback);
    }

    noteAppCallback(ctx: NativePointer, callback: NativePointer): void {
        if (registry.sealed || callback.equals(this.ourCallback)) return;
        const tracked = registry.get(ctx.toString());
        if (tracked !== undefined) tracked.previous = callback;
    }

    /** Put `previous` back, but only if the CTX still holds OUR callback. */
    restore(tracked: TrackedCtx): boolean {
        if (this.getter !== null && !this.getter(tracked.ctx).equals(this.ourCallback)) return false;
        this.setter(tracked.ctx, tracked.previous);
        return true;
    }

    private readPrevious(ctx: NativePointer): NativePointer {
        if (this.getter === null) return NULL;
        try {
            const current = this.getter(ctx);
            return current.equals(this.ourCallback) ? NULL : current;
        } catch (_e) {
            return NULL;
        }
    }
}

/**
 * Build the tracker for one module's callback tier. `trackLifetime` must be
 * false when the install hooks blink (pairip-safe): the SSL_CTX_free hook would
 * then miss frees, so those CTXs are written but deliberately not restored.
 */
export function createKeylogCallbackTracker(moduleName: string, setterAddress: NativePointer,
                                            ourCallback: NativePointer, trackLifetime: boolean): KeylogCallbackTracker {
    retainKeylogCallback(ourCallback);
    return new TrackerImpl(moduleName, setterAddress, ourCallback, trackLifetime);
}

/** Keep `callback` reachable until script destroy (idempotent per object). */
function retainKeylogCallback(callback: NativePointer): void {
    if (!retainedKeylogCallbacks.includes(callback)) retainedKeylogCallbacks.push(callback);
}

/** Number of distinct keylog callbacks retained for the script's lifetime. */
export function retainedKeylogCallbackCount(): number {
    return retainedKeylogCallbacks.length;
}

/**
 * Seal the registry and restore every CTX still believed alive. Best effort and
 * idempotent. Must run BEFORE Interceptor.detachAll (see ordering note above).
 */
export function restoreTrackedKeylogCallbacks(): { restored: number; skipped: number } {
    const result = registry.sealAndDrain((_key, tracked) => tracked.owner.restore(tracked));
    if (result.restored + result.skipped > 0) {
        try { devlog(`[keylog-cb-registry] restored ${result.restored} SSL_CTX keylog callback(s), skipped ${result.skipped}`); }
        catch (_e) { /* host may be gone */ }
    }
    return result;
}
