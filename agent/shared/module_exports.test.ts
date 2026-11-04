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
