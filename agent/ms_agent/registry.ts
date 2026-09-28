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
