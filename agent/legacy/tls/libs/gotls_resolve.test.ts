// Unit tests for GoTLS.resolve_symbol_with_fallback in both hooker copies
// (agent/legacy/tls/libs/gotls.ts, agent/tls/libs/gotls.ts).
//
// Run: npm run test:agent
//
// WHY: the cascade started with Module.getGlobalExportByName, which THROWS for a missing
// name (Go symbols are almost never dynamic exports); the outer catch then returned null,
// so the module-export, mangled-variant, DebugSymbol and export-scan fallbacks never ran.
// The find* lookups return null instead. The last-resort export scan now needs a method-
// name boundary: a bare substring ("read" in "pthread_*") would hook an unrelated function.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
// Load the module graph from the agent entry, as Frida does (TDZ on the platform subclasses).
import "../../../fritap_agent.js";

import { GoTLS as LegacyGoTLS } from "./gotls.js";
import { GoTLS } from "../../../tls/libs/gotls.js";

const G = globalThis as any;
const P = (name: string): any => ({ name, isNull: () => false, toString: () => name });

interface World { globalExports?: Record<string, any>; moduleExports?: Record<string, any>; debugSymbols?: Record<string, any>; loaded?: boolean }
function world(w: World): void {
    const missing = (what: string) => { throw new Error(`unable to find ${what}`); };
    G.Module.getGlobalExportByName = (n: string) => w.globalExports?.[n] ?? missing(n);
    G.Module.findGlobalExportByName = (n: string) => w.globalExports?.[n] ?? null;
    const mod = {
        findExportByName: (n: string) => w.moduleExports?.[n] ?? null,
        getExportByName: (n: string) => w.moduleExports?.[n] ?? missing(n),
        enumerateExports: () => Object.entries(w.moduleExports ?? {}).map(([name, address]) => ({ name, address })),
    };
    G.Process.findModuleByName = () => (w.loaded === false ? null : mod);
    G.Process.getModuleByName = (n: string) => (w.loaded === false ? missing(n) : mod);
    G.DebugSymbol = { fromName: (n: string) => ({ address: w.debugSymbols?.[n] ?? { isNull: () => true } }) };
}

const WRL = "crypto/tls.(*Conn).writeRecordLocked";
for (const [label, Hooker] of [["legacy", LegacyGoTLS], ["tls/libs", GoTLS]] as const) {
    const hooker: any = Object.create(Hooker.prototype);
    hooker.module_name = "app";

    test(`${label}: a non-exported Go symbol resolves via DebugSymbol (the get* throw no longer aborts)`, () => {
        world({ debugSymbols: { [WRL]: P("wrl@debug") } });
        assert.equal(hooker.resolve_symbol_with_fallback(WRL)?.name, "wrl@debug");
    });

    test(`${label}: global export, then module export, then a mangled variant`, () => {
        world({ globalExports: { [WRL]: P("global") } });
        assert.equal(hooker.resolve_symbol_with_fallback(WRL)?.name, "global");
        world({ moduleExports: { [WRL]: P("module") } });
        assert.equal(hooker.resolve_symbol_with_fallback(WRL)?.name, "module");
        world({ moduleExports: { "crypto_tls_ptr_Conn_writeRecordLocked": P("mangled") } });
        assert.equal(hooker.resolve_symbol_with_fallback(WRL)?.name, "mangled");
    });

    test(`${label}: the last-resort export scan needs a method-name boundary`, () => {
        world({ moduleExports: { "pthread_create": P("pthread"), "x_Conn_Read": P("boundary") } });
        assert.equal(hooker.resolve_symbol_with_fallback("crypto/tls.(*Conn).Read")?.name, "boundary");
        world({ moduleExports: { "pthread_create": P("pthread"), "spreadsheet": P("s") } });
        assert.equal(hooker.resolve_symbol_with_fallback("crypto/tls.(*Conn).Read"), null);
    });

    test(`${label}: nothing anywhere (or module not loaded) -> null, no throw`, () => {
        world({});
        assert.equal(hooker.resolve_symbol_with_fallback(WRL), null);
        world({ loaded: false });
        assert.equal(hooker.resolve_symbol_with_fallback(WRL), null);
    });
}

// The constructor pushed found Go symbols onto library_method_mapping["*<module>*"], an entry
// it never created: the first found symbol threw (undefined.push) and aborted the executor.
// Unreachable while resolve_symbol_with_fallback always failed; hit as soon as it worked.
for (const [label, Hooker] of [["legacy", LegacyGoTLS], ["tls/libs", GoTLS]] as const) {
    test(`${label}: constructing the hooker records a DebugSymbol-resolved writeKeyLog`, () => {
        world({ debugSymbols: { "crypto/tls.(*Config).writeKeyLog": P("wkl@debug") } });
        const hooker: any = new (Hooker as any)("app.go1.21", "libc", false);
        assert.equal(hooker.addresses["app.go1.21"]["crypto/tls.(*Config).writeKeyLog"]?.name, "wkl@debug");
        assert.ok(hooker.library_method_mapping["*app.go1.21*"].includes("crypto/tls.(*Config).writeKeyLog"));
    });
}
