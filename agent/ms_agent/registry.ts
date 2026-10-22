/*
 * Engine registry. Replaces the former if-chain in runEngineTiers() with an
 * open registration table: each engine module self-registers at import time
 * (a side-effecting barrel, mirroring the main agent's `import "./rc4/index.js"`
 * convention), so adding an engine is a new folder plus one import in the entry
 * file — no edit to a dispatch switch (Open/Closed).
 */
import { MemscanEngine } from "./types.js";

const engines: { [name: string]: MemscanEngine } = {};

/** Register (or replace) an engine under its `name`. Called by engine barrels. */
export function registerEngine(engine: MemscanEngine): void {
    engines[engine.name] = engine;
}

/** The engine registered under `name`, or null if none. */
export function getEngine(name: string): MemscanEngine | null {
    return Object.prototype.hasOwnProperty.call(engines, name) ? engines[name] : null;
}

/** Names of all registered engines (diagnostics/tests). */
export function engineNames(): string[] {
    return Object.keys(engines);
}

/**
 * Run every registered engine's optional stop() teardown. Called from the agent's
 * `dispose` RPC so an engine can release hooks it installed (e.g. boringssl's
 * needle-seed hooks on the hot SSL_read/SSL_write path) BEFORE frida's implicit
 * detach, whose synchronous rewrite of those hot prologues is what stalls unload.
 * Failures are isolated so one bad teardown cannot block the others or the unload.
 */
export function stopEngines(): void {
    for (const name of Object.keys(engines)) {
        const engine = engines[name];
        if (typeof engine.stop === "function") {
            try { engine.stop(); } catch (_e) { /* best-effort; unload must proceed */ }
        }
    }
}
