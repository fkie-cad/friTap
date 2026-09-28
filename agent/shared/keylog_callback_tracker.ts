// agent/shared/keylog_callback_tracker.ts
//
// Frida glue around KeylogCallbackRegistry for the BoringSSL callback tier
// (SSL_new / SSL_CTX_new -> SSL_CTX_set_keylog_callback(ctx, <script cb>)).
// It records every CTX we write, follows its lifetime via SSL_CTX_up_ref /
// SSL_CTX_free, and on teardown puts the previous callback back so no live CTX
// is left pointing at the freed NativeCallback.
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
 * A missing/failed up_ref hook is fail-safe (see keylog_callback_registry.ts).
 */
function attachLifetimeHooks(moduleName: string, freeAddress: NativePointer): boolean {
    const known = lifetimeHookedModules.get(moduleName);
    if (known !== undefined) return known;
    let attached = false;
    try {
        Interceptor.attach(freeAddress, {
            onEnter(args) { registry.noteFree(args[0].toString()); },
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
            devlog(`[keylog-cb-registry] ${moduleName}: SSL_CTX_up_ref hook failed (fail-safe): ${e}`);
        }
    }
    return attached;
}

class TrackerImpl implements KeylogCallbackTracker {
    private readonly setter: NativeFunction<void, [NativePointer, NativePointer]>;
    private readonly getter: NativeFunction<NativePointer, [NativePointer]> | null;
    private readonly tracksLifetime: boolean;

    constructor(moduleName: string, setterAddress: NativePointer,
                private readonly ourCallback: NativePointer, trackLifetime: boolean) {
        this.setter = new NativeFunction(setterAddress, "void", ["pointer", "pointer"], { scheduling: "exclusive" });
        const getterAddress = findFunction(moduleName, "SSL_CTX_get_keylog_callback");
        this.getter = getterAddress === null ? null
            : new NativeFunction(getterAddress, "pointer", ["pointer"], { scheduling: "exclusive" });
        const freeAddress = trackLifetime ? findFunction(moduleName, "SSL_CTX_free") : null;
        this.tracksLifetime = freeAddress !== null && attachLifetimeHooks(moduleName, freeAddress);
        devlog(`[keylog-cb-registry] ${moduleName}: lifetime tracking=${this.tracksLifetime}, getter=${this.getter !== null}`);
    }

    get sealed(): boolean { return registry.sealed; }

    install(ctx: NativePointer): void {
        if (ctx.isNull() || registry.sealed) return;
        if (this.tracksLifetime) {
            registry.recordInstall(ctx.toString(), () => ({ ctx, previous: this.readPrevious(ctx), owner: this }));
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
    return new TrackerImpl(moduleName, setterAddress, ourCallback, trackLifetime);
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
