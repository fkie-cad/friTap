// Run: npm run test:agent
import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { findModuleExport } from "./module_exports.js";

const G = globalThis as any;

function withModule(module: any, legacyFind: any, fn: () => void): void {
    const savedFindModule = G.Process.findModuleByName;
    const savedLegacy = G.Module.findExportByName;
    G.Process.findModuleByName = (name: string) => (module && name === module.name ? module : null);
    G.Module.findExportByName = legacyFind;
    try { fn(); } finally {
        G.Process.findModuleByName = savedFindModule;
        G.Module.findExportByName = savedLegacy;
    }
}

test("findModuleExport: resolves through the Module instance (Frida 17, no static API)", () => {
    const addr = { tag: "kex" };
    const module = { name: "ssh", path: "/a/ssh", base: "0x1", findExportByName: (s: string) => (s === "kex_derive_keys" ? addr : null), enumerateExports: () => [] };
    withModule(module, undefined, () => {
        assert.equal(findModuleExport("ssh", "kex_derive_keys"), addr);
        assert.equal(findModuleExport("ssh", "missing"), null);
    });
});

test("findModuleExport: falls back to the module's export table when findExportByName misses", () => {
    const addr = { tag: "cipher_init" };
    let enumerations = 0;
    const module = { name: "ssh", path: "/b/ssh", base: "0x2", findExportByName: () => null,
        enumerateExports: () => { enumerations++; return [{ name: "cipher_init", address: addr }]; } };
    withModule(module, undefined, () => {
        assert.equal(findModuleExport("ssh", "cipher_init"), addr);
        assert.equal(findModuleExport("ssh", "cipher_init"), addr);
        assert.equal(enumerations, 1, "the export table is enumerated once per module");
    });
});

test("findModuleExport: unknown module never falls back to a global lookup", () => {
    withModule(null, undefined, () => assert.equal(findModuleExport("nope", "x"), null));
});

test("findModuleExport: pre-17 runtimes use the static Module.findExportByName", () => {
    const addr = { tag: "legacy" };
    withModule(null, (m: string, s: string) => (m === "libcharon.so" && s === "derive_ike_keys" ? addr : null), () => {
        assert.equal(findModuleExport("libcharon.so", "derive_ike_keys"), addr);
    });
});

// Minimal NativePointer over a number (add/compare/isNull) for the bounds check.
function P(v: number): any {
    return { v, isNull: () => v === 0, add: (o: number) => P(v + o), compare: (o: any) => (v === o.v ? 0 : v < o.v ? -1 : 1) };
}

function ownedModule(name: string, exportAt: number | null, rangeEnd = 0x2000): any {
    const base = P(0x1000);
    return {
        name, path: `/x/${name}`, base, size: 0x800,
        findExportByName: () => (exportAt === null ? null : P(exportAt)),
        enumerateRanges: () => [{ base, size: rangeEnd - 0x1000, protection: "r--" }],
        enumerateExports: () => { throw new Error("own-module lookups never enumerate the export table"); },
    };
}

test("findModuleExport ownModuleOnly: an address inside the module image (past Module.size) is kept", () => {
    const module = ownedModule("libown.so", 0x1c00);
    withModule(module, undefined, () => {
        assert.equal((findModuleExport("libown.so", "probe", { ownModuleOnly: true }) as any)?.v, 0x1c00);
    });
});

test("findModuleExport ownModuleOnly: a dependency's export (outside the image) is rejected", () => {
    withModule(ownedModule("libdep.so", 0x9000), undefined, () => {
        assert.equal(findModuleExport("libdep.so", "probe", { ownModuleOnly: true }), null);
    });
});

test("findModuleExport ownModuleOnly: a miss or an unresolved module is null without any fallback", () => {
    withModule(ownedModule("libnone.so", null), () => P(0x1100), () => {
        assert.equal(findModuleExport("libnone.so", "probe", { ownModuleOnly: true }), null);
        assert.equal(findModuleExport("libgone.so", "probe", { ownModuleOnly: true }), null);
    });
});
