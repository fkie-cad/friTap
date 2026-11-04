/**
 * Record protocol: the protocol a hook's MESSAGES belong to.
 *
 * A registry row carries two different facts:
 *   - `protocol`        — which selection INSTALLS the row (matched against the
 *                          requested set, incl. PROTOCOL_IMPLIES companions);
 *   - `recordProtocol`  — which protocol the records the row's hooks emit belong
 *                          to (defaults to `protocol`).
 *
 * The record protocol is bound ONCE, where the loaders run a row's executor
 * ({@link executeHookRow}): while the executor runs, every Interceptor listener
 * it attaches is bound to the row's record protocol, so whatever that listener
 * later sends is tagged with it — no per-call-site `protocol:` stamping.
 * `sendWithProtocol` reads the bound value via {@link activeRecordProtocol}.
 *
 * Scope limits (documented, not hidden): only listeners attached SYNCHRONOUSLY
 * by the executor are bound. Hooks installed later (after an `await`, from an
 * async Memory.scan callback) and Java `.implementation` swaps are not
 * Interceptor listeners; such sites wrap their callback with
 * {@link bindRecordProtocol} while still inside the executor, or fall back to
 * the default protocol.
 *
 * Kept free of Frida-only imports so it is unit-testable under Node.
 */
import type { HookRegistration } from "./registry.js";

/** Protocol of a record whose hook declared none (every TLS-family hook). */
export const DEFAULT_RECORD_PROTOCOL = "tls";

let active: string | undefined;

/** The record protocol of the hook currently executing (undefined outside any bound hook). */
export function activeRecordProtocol(): string | undefined {
    return active;
}

/** The record protocol of a registry row. */
export function recordProtocolOf(row: Pick<HookRegistration, "protocol" | "recordProtocol">): string {
    return row.recordProtocol ?? row.protocol;
}

/** Run `fn` with `protocol` as the active record protocol, restoring the previous one afterwards. */
export function runWithRecordProtocol<T>(protocol: string | undefined, fn: () => T): T {
    const previous = active;
    active = protocol;
    try {
        return fn();
    } finally {
        active = previous;
    }
}

/**
 * Bind `fn` to `protocol` (default: the protocol active right now), preserving
 * `this` — for callbacks that are not Interceptor listeners (Java
 * implementations, deferred continuations) but are created inside an executor.
 */
export function bindRecordProtocol<F extends (...args: any[]) => any>(fn: F, protocol: string | undefined = active): F {
    if (protocol === undefined) return fn;
    return function (this: any, ...args: any[]) {
        return runWithRecordProtocol(protocol, () => fn.apply(this, args));
    } as unknown as F;
}

/**
 * Bind the JS callbacks of an Interceptor.attach `callbacks` argument. A plain
 * function (onEnter shorthand) is wrapped; an object keeps its other members
 * (prototype-linked) and gets bound onEnter/onLeave. Native (CModule /
 * NativePointer) callbacks are passed through untouched.
 */
export function bindListenerCallbacks(callbacks: any, protocol: string): any {
    if (typeof callbacks === "function") return bindRecordProtocol(callbacks, protocol);
    if (callbacks === null || typeof callbacks !== "object") return callbacks;
    const { onEnter, onLeave } = callbacks;
    if (typeof onEnter !== "function" && typeof onLeave !== "function") return callbacks;
    const bound = Object.create(callbacks);
    if (typeof onEnter === "function") bound.onEnter = bindRecordProtocol(onEnter, protocol);
    if (typeof onLeave === "function") bound.onLeave = bindRecordProtocol(onLeave, protocol);
    return bound;
}

/**
 * A stand-in for the global Interceptor whose `attach` binds listeners to
 * `protocol`. Frida's `Interceptor.attach` is a read-only, non-configurable
 * property (so neither patching it nor a Proxy is possible); every other
 * member is forwarded to the real Interceptor with `this` bound to it.
 */
function bindingInterceptor(original: any, protocol: string): any {
    const facade: any = {};
    for (const key of Reflect.ownKeys(original)) {
        if (key === "attach") continue;
        Object.defineProperty(facade, key, {
            enumerable: true,
            get() {
                const value = original[key];
                return typeof value === "function" ? value.bind(original) : value;
            },
        });
    }
    facade.attach = (...args: any[]) => {
        args[1] = bindListenerCallbacks(args[1], protocol);
        return original.attach(...args);
    };
    return facade;
}

/**
 * Run a hook executor with `protocol` as its record protocol: the executor's
 * own synchronous sends see it, and every listener it attaches synchronously is
 * bound to it. TLS-family rows (the default) skip the Interceptor swap — an
 * unbound listener already falls back to the default protocol — so the hot TLS
 * read/write callbacks carry no wrapper.
 */
export function runHookExecutor<T>(protocol: string, fn: () => T, scope: any = globalThis): T {
    if (protocol === DEFAULT_RECORD_PROTOCOL || !scope.Interceptor) {
        return runWithRecordProtocol(protocol, fn);
    }
    const original = scope.Interceptor;
    scope.Interceptor = bindingInterceptor(original, protocol);
    try {
        return runWithRecordProtocol(protocol, fn);
    } finally {
        scope.Interceptor = original;
    }
}

/** Run a registry row's executor on `moduleName` under the row's record protocol. */
export function executeHookRow(match: HookRegistration, moduleName: string, isBaseHook: boolean): ReturnType<HookRegistration["hookFn"]> {
    return runHookExecutor(recordProtocolOf(match), () => match.hookFn(moduleName, isBaseHook));
}
