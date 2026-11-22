// Tests for the modern NSS definition delegating to the shared installer and the
// executor's handling of async custom installs.
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
// Load the agent graph first (nss -> fritap_agent -> legacy nss_* import cycle).
import "../../fritap_agent.js";

import { createNssDefinition, installNssKeylog } from "./nss.js";
import { installKeylogHook } from "../../core/executors/keylog_callback.js";

test("nss definition uses installNssKeylog as its custom keylog install", () => {
    const def = createNssDefinition();
    assert.equal(def.keylog.kind, "custom");
    assert.equal((def.keylog as any).install, installNssKeylog);
});

test("installNssKeylog resolves false when the module has no addresses", async () => {
    assert.equal(await installNssKeylog({}, "libnss3.so", {} as any, false), false);
});

test("installNssKeylog resolves false when nothing can be installed (delegates, never rejects)", async () => {
    const addrs = { "libnss3.so": {} };
    assert.equal(await installNssKeylog(addrs as any, "libnss3.so", {} as any, false), false);
});

test("a pending async custom install is not reported as installed", async () => {
    let settle!: (v: boolean) => void;
    const pending = new Promise<boolean>((r) => { settle = r; });
    const def: any = { keylog: { kind: "custom", install: () => pending } };
    assert.equal(installKeylogHook(def, {}, "m", {} as any, false), false);
    settle(false);
    await pending;
});

test("a rejecting async custom install does not throw", async () => {
    const def: any = { keylog: { kind: "custom", install: () => Promise.reject(new Error("x")) } };
    assert.equal(installKeylogHook(def, {}, "m", {} as any, false), false);
    await new Promise((r) => setImmediate(r));
});

test("a sync custom install keeps its boolean result", () => {
    const def: any = { keylog: { kind: "custom", install: () => true } };
    assert.equal(installKeylogHook(def, {}, "m", {} as any, false), true);
});

test("Windows definition: folded nss3.dll resolves SSL/PK11 in the module, no Linux aux globs", async () => {
    const { createNssWindowsDefinition } = await import("./nss.js");
    const def = createNssWindowsDefinition("nss3.dll");
    assert.ok(def.functions.librarySymbols.includes("SSL_ImportFD"));
    assert.ok(def.functions.librarySymbols.includes("PR_GetDescType"));
    assert.deepEqual(def.functions.auxiliaryLibraries, []);
    assert.equal((def.keylog as any).install, installNssKeylog);
});

test("Windows definition: unfolded nspr4.dll uses ssl3/nss3 DLL patterns, never *libssl*.so / *libnss*", async () => {
    const { createNssWindowsDefinition } = await import("./nss.js");
    const def = createNssWindowsDefinition("libnspr4.dll");
    const patterns = (def.functions.auxiliaryLibraries ?? []).map((a) => a.pattern);
    assert.deepEqual(patterns.sort(), ["*nss3.dll", "*ssl3.dll"]);
    assert.ok(!def.functions.librarySymbols.includes("SSL_ImportFD"));
    // Linux/Android/macOS definitions are unchanged.
    assert.deepEqual(createNssDefinition().functions.auxiliaryLibraries!.map((a) => a.pattern), ["*libnss*", "*libssl*.so"]);
});
