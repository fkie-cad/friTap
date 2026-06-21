/**
 * hook_contributors.ts — generic registration seam for optional, separately
 * bundled hook units.
 *
 * The public agent bundle ships only the core hooks wired directly into each
 * platform agent. A FULL build additionally imports one or more private units
 * (e.g. a messenger E2E unit) BEFORE the agent entry; each such unit calls
 * `registerHookContributor(...)` at module-load time to add its hook rows, and
 * `registerProtocolImplication(...)` to declare companion-protocol implications
 * (e.g. "this protocol's traffic is TLS-wrapped, so selecting it also needs the
 * TLS hooks").
 *
 * The platform agent appends `...collectContributedHooks()` to the hook table it
 * registers, and the registry consults `contributedImplications()` when deciding
 * whether a hook should install for a requested protocol. In the public build no
 * unit registers, so both accessors return empty — the core behaves exactly as
 * before. The public core never names a private protocol; the contributor does.
 *
 * This module has NO import side effects and (by `import type`) no runtime
 * dependency on the registry, so importing it never triggers hook installation.
 */
import type { HookRegistry } from "./registry.js";

/**
 * A contributed hook row. Same shape the platform agents pass to
 * `hookRegistry.registerAll(...)`: `platform`/`pattern`/`hookFn`/`library` are
 * mandatory; `protocol` (default "tls") and `priority` (default 100) are filled
 * in by the registry.
 */
export type HookContribution = Parameters<HookRegistry["registerAll"]>[0][number];

const _contributedHooks: HookContribution[] = [];
const _protocolImplications: Record<string, string[]> = {};

/** Register one hook row, or several at once. */
export function registerHookContributor(rows: HookContribution | HookContribution[]): void {
    if (Array.isArray(rows)) {
        _contributedHooks.push(...rows);
    } else {
        _contributedHooks.push(rows);
    }
}

/** All contributed hook rows, in registration order. */
export function collectContributedHooks(): HookContribution[] {
    return _contributedHooks.slice();
}

/**
 * Declare that selecting `requested` should also install hooks registered for
 * the `implies` protocol (idempotent).
 */
export function registerProtocolImplication(requested: string, implies: string): void {
    const list = _protocolImplications[requested] ?? (_protocolImplications[requested] = []);
    if (!list.includes(implies)) {
        list.push(implies);
    }
}

/** Map of requested-protocol → list of implied protocols contributed so far. */
export function contributedImplications(): Record<string, string[]> {
    return _protocolImplications;
}
