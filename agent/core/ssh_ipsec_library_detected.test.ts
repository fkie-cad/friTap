// SSH / IPsec executors must not send their own library_detected: the central
// loader (installHookRow in shared_functions.ts) is the single source and sends it
// exactly once per module, from the executor's installed verdict
// (ModuleHookingType). Covers the legacy executors (default path) and the modern
// definition wrappers (--modern), whose verdict arrives through executeFromDefinition.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
// Load the agent entry first so the loader's import cycle resolves in production order.
import "../fritap_agent.js";
import { HookRegistry } from "../shared/registry.js";
import { PLATFORM_LINUX } from "../shared/shared_structures.js";
import { ssl_library_loader } from "../shared/shared_functions.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { openssh_execute_modern } from "../ssh/platforms/linux/openssh_linux.js";
import { libssh_execute_modern } from "../ssh/platforms/linux/libssh_linux.js";
import { strongswan_execute_modern } from "../ipsec/platforms/linux/strongswan_linux.js";

const G = globalThis as any;
const sent: any[] = [];
G.send = (msg: any) => { sent.push(msg); };
// Distinct base per module: the loader's hooked-module guard keys on the image identity.
const bases = new Map<string, number>();
const baseOf = (name: string) => {
    if (!bases.has(name)) bases.set(name, 0x1000 * (bases.size + 1));
    const hex = `0x${bases.get(name)!.toString(16)}`;
    return Object.assign(G.ptr(), { toString: () => hex });
};
G.Process.getModuleByName = (name: string) => ({
    name, path: `/usr/lib/${name}`, base: baseOf(name),
    ensureInitialized: () => { },
    enumerateExports: () => [],
    getExportByName: () => G.ptr(1),
});

// Frida 17 shape: no static Module.findExportByName; exports resolve via the Module instance.
delete G.Module.findExportByName;

/** Make every module export only `symbols` (anything else: not exported). */
function exportOnly(symbols: string[]): void {
    G.Process.findModuleByName = (name: string) => ({
        name, path: `/usr/lib/${name}`, base: baseOf(name),
        ensureInitialized: () => { }, enumerateExports: () => [], enumerateSymbols: () => [],
        findExportByName: (symbol: string) => symbols.includes(symbol) ? G.ptr(1) : null,
    });
}

type Executor = (moduleName: string, isBaseHook: boolean) => unknown;

/** Run one SSH/IPsec registry row through the central loader; return its library_detected sends. */
async function libraryDetectedFor(moduleName: string, protocol: "ssh" | "ipsec", hookFn: Executor): Promise<any[]> {
    const reg = new HookRegistry();
    reg.registerAll([{ platform: PLATFORM_LINUX, pattern: new RegExp(moduleName.replace(/\./g, "\\.")),
        hookFn: hookFn as any, library: `test ${protocol}`, protocol }]);
    sent.length = 0;
    ssl_library_loader(PLATFORM_LINUX, reg, [moduleName], "Linux", true, protocol);
    // Modern wrappers settle after executeFromDefinition's pipeline await.
    for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));
    return sent.filter(m => m.contentType === "library_detected");
}

const SSH_SYMBOL = ["ssh_set_newkeys"];
const IPSEC_SYMBOL = ["derive_ike_keys"];

const CASES: Array<{ name: string; protocol: "ssh" | "ipsec"; hookFn: Executor; symbols: string[] }> = [
    { name: "legacy OpenSSH", protocol: "ssh", hookFn: ssh_detect_execute, symbols: SSH_SYMBOL },
    { name: "legacy strongSwan", protocol: "ipsec", hookFn: ipsec_detect_execute, symbols: IPSEC_SYMBOL },
    { name: "modern OpenSSH", protocol: "ssh", hookFn: openssh_execute_modern, symbols: SSH_SYMBOL },
    { name: "modern libssh", protocol: "ssh", hookFn: libssh_execute_modern, symbols: SSH_SYMBOL },
    { name: "modern strongSwan", protocol: "ipsec", hookFn: strongswan_execute_modern, symbols: IPSEC_SYMBOL },
];

for (const [index, { name, protocol, hookFn, symbols }] of CASES.entries()) {
    test(`${name}: exactly one library_detected per module, from the loader`, async () => {
        exportOnly(symbols);
        const moduleName = `libhooked_${index}.so`;
        const detected = await libraryDetectedFor(moduleName, protocol, hookFn);
        assert.equal(detected.length, 1, `expected one library_detected, got ${JSON.stringify(detected)}`);
        assert.deepEqual(detected[0], { contentType: "library_detected", library: moduleName,
            path: `/usr/lib/${moduleName}`, protocol });
    });

    test(`${name}: nothing hookable -> installed=false, no library_detected`, async () => {
        exportOnly([]);
        const detected = await libraryDetectedFor(`libempty_${index}.so`, protocol, hookFn);
        assert.equal(detected.length, 0);
    });
}

test("legacy executors report their installed verdict", () => {
    exportOnly([]);
    assert.equal(ssh_detect_execute("libssh_none.so", true), false);
    assert.equal(ipsec_detect_execute("libipsec_none.so", true), false);
    exportOnly([...SSH_SYMBOL, ...IPSEC_SYMBOL]);
    assert.equal(ssh_detect_execute("libssh_some.so", true), true);
    assert.equal(ipsec_detect_execute("libipsec_some.so", true), true);
});
