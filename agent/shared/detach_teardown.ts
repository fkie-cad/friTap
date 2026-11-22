/**
 * Detach-teardown registry.
 *
 * Hooks that swap ART (Java) method entrypoints via `overload.implementation = …`
 * must revert them EXPLICITLY, while the Java VM is still attached, before the
 * script is disposed. The implicit deopt-restore that frida-java-bridge runs on
 * `dispose` races the app's own threads: a method called mid-teardown can jump
 * through a half-restored entrypoint into freed trampoline/agent memory and
 * SIGBUS the process. This was observed on Signal and Telegram detach.
 *
 * `Interceptor.detachAll()` only reverts NATIVE hooks, not `.implementation`
 * swaps, so those need their own teardown. Contributors register a revert here
 * when they install; `releaseAgentHooks()` runs them (best-effort, isolated)
 * before `Interceptor.detachAll()`. Kept generic (it imports only util/log) so the
 * shared agent core never needs to know which protocol installed a Java hook.
 */

import { devlog } from "../util/log.js";
import { makeHookRegistry } from "./hook_registry.js";
import { DetachReportBuilder, DetachSummary } from "./detach_report.js";

/**
 * A teardown may return a small summary (plain object of number|string|boolean,
 * e.g. NSS `{owned, toApp, toNull, stale, failed}`) that lands in the
 * DetachReport. Existing teardowns that return nothing stay valid.
 */
export type DetachTeardownFn = (() => void) | (() => DetachSummary | void);

const teardowns = makeHookRegistry({ reverse: true });

/** Register a revert to run on graceful detach / script dispose; `label` names its report step. */
export function registerDetachTeardown(label: string, fn: DetachTeardownFn): void {
    teardowns.register(fn, label);
}

/**
 * Run every registered teardown in reverse install order, isolating failures so
 * one bad revert cannot block the others or the native detach that follows.
 * Each runs as report step `teardown:<label>` (timed, error and summary kept).
 * Without a report the outcome is discarded. Idempotent (the registry is
 * emptied first); never throws.
 */
export function runDetachTeardowns(report: DetachReportBuilder = new DetachReportBuilder()): void {
    teardowns.run((label, fn) => report.step(`teardown:${label}`, fn));
}

// TODO: signal_java.ts has its own copy of this loop.
/** Revert swapped Java overloads inside `bridge.perform` while the VM is attached; best-effort, no-op without a bridge. */
export function revertJavaOverloads(bridge: any, overloads: readonly any[], label: string): void {
    if (overloads.length === 0) return;
    try {
        if (!bridge || !bridge.available) return;
        bridge.perform(() => {
            for (const overload of overloads) {
                try { overload.implementation = null; } catch (e) { devlog(`[${label}] revert failed: ${e}`); }
            }
        });
    } catch (e) {
        devlog(`[${label}] Java-hook teardown skipped: ${e}`);
    }
}
