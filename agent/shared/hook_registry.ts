/**
 * Run-once registry of detach-time callbacks (pre-shutdown flushes, detach
 * teardowns). A run empties the registry first, so it is idempotent, and
 * isolates every callback: one failure cannot block the rest of detach.
 *
 * Each callback keeps the label it was registered with, so a caller-supplied
 * invoker (detach_teardown.ts) can report every callback as a named step.
 */

type HookFn = () => unknown;

/** Calls one registered callback; must isolate its failures itself. */
export type HookInvoker = (label: string, fn: HookFn) => void;

export interface HookRegistry {
    register(fn: HookFn, label?: string): void;
    /** Run and drop every registered callback; never throws. */
    run(invoke?: HookInvoker): void;
}

interface LabelledHook {
    label: string;
    fn: HookFn;
}

const UNLABELLED = "unlabelled";

function invokeIsolated(_label: string, fn: HookFn): void {
    try {
        fn();
    } catch (_e) {
        /* best-effort; detach must proceed regardless */
    }
}

export function makeHookRegistry(options: { reverse: boolean }): HookRegistry {
    let hooks: LabelledHook[] = [];
    return {
        register(fn, label = UNLABELLED) {
            hooks.push({ label, fn });
        },
        run(invoke = invokeIsolated) {
            const pending = hooks;
            hooks = [];
            if (options.reverse) pending.reverse();
            for (const hook of pending) {
                try {
                    invoke(hook.label, hook.fn);
                } catch (_e) {
                    /* a misbehaving invoker must not stop the remaining callbacks */
                }
            }
        },
    };
}
