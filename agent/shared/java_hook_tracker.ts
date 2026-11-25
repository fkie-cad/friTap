/**
 * Records Java methods whose `.implementation` a hook swapped, and reverts them
 * on graceful detach / dispose (detach_teardown.ts) while the VM is attached.
 *
 * Left to frida-java-bridge's implicit dispose-time restore, a hot swapped
 * method (ClassLoader.loadClass) kept `script.unload()` from returning on a
 * Pixel 5: busy GSA processes called it constantly during dispose, and the
 * agent stayed loaded after friTap exited.
 */

import { registerDetachTeardown, revertJavaOverloads, DetachTeardownFn } from "./detach_teardown.js";

export interface JavaHookTracker {
    /** Record a swapped method (dispatcher or single overload); all its overloads are reverted. */
    track(method: any): void;
    /** Number of overloads waiting to be reverted (for tests). */
    pending(): number;
}

type Register = (label: string, fn: DetachTeardownFn) => void;

function overloadsOf(method: any): any[] {
    try {
        const overloads = method?.overloads;
        if (Array.isArray(overloads) && overloads.length > 0) return overloads;
    } catch (_e) {
        /* a wrapper without an overloads list: revert the method itself */
    }
    return method ? [method] : [];
}

/**
 * A tracker whose revert runs as detach step `teardown:<label>`. `getBridge`
 * returns the Java bridge at revert time (injected so tests need no Frida).
 */
export function makeJavaHookTracker(label: string, getBridge: () => any,
                                    register: Register = registerDetachTeardown): JavaHookTracker {
    const swapped: any[] = [];
    let registered = false;

    function revertAll(): void {
        registered = false;
        const overloads = swapped.splice(0);
        revertJavaOverloads(getBridge(), overloads, label);
    }

    return {
        track(method: any): void {
            for (const overload of overloadsOf(method)) {
                if (!swapped.includes(overload)) swapped.push(overload);
            }
            if (!registered && swapped.length > 0) {
                registered = true;
                register(label, revertAll);
            }
        },
        pending: () => swapped.length,
    };
}
