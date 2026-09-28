// Unit tests for the RC4 known-answer self-test and the makeRc4Executor gate
// (agent/rc4/libs/rc4_hooks.ts). The self-test must run lazily — only on the first
// executor call that passes the keylog_enabled gate — and at most once.
//
// Run: node --import tsx --test agent/rc4/libs/rc4_hooks.test.ts
//   (registered in package.json's "test:agent" list so it runs in the suite.)
//
// devlog()/log() emit via the Frida global send(), so a stubbed send() captures the
// "[rc4] RC4 self-test OK" line. A module in the import chain reads Process at load, so
// a minimal Process stub is installed too — both before the dynamic import.

import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";

let sentConsole: string[] = [];
(globalThis as any).Process = { platform: "linux", arch: "x64", pointerSize: 8, getCurrentThreadId: () => 0 };
(globalThis as any).send = (msg: any) => {
    if (msg && typeof msg.console_dev === "string") sentConsole.push(msg.console_dev);
    if (msg && typeof msg.console === "string") sentConsole.push(msg.console);
};

let hooks: any;
let setKeylogEnabled: (v: boolean) => void;
before(async () => {
    hooks = await import("./rc4_hooks.js");
    ({ setKeylogEnabled } = await import("../../shared/shared_structures.js"));
});
beforeEach(() => { sentConsole = []; });

const selfTestLines = () => sentConsole.filter(s => s.includes("RC4 self-test"));

test("selfTest() passes the RC4 known-answer vector", () => {
    assert.equal(hooks.selfTest(), true);
});

test("keylog disabled: installer never runs and the self-test does not run", () => {
    setKeylogEnabled(false);
    let installs = 0;
    const exec = hooks.makeRc4Executor("test", () => { installs++; return true; });
    exec("libcrypto.so", false);
    exec("libcrypto.so", false);
    assert.equal(installs, 0);
    assert.deepEqual(selfTestLines(), []);
});

test("keylog enabled: installer runs and the self-test runs exactly once", () => {
    setKeylogEnabled(true);
    const installed: string[] = [];
    const exec = hooks.makeRc4Executor("test", (m: string) => { installed.push(m); return true; });
    exec("libcrypto.so", false);
    exec("libssl.so", false);
    assert.deepEqual(installed, ["libcrypto.so", "libssl.so"]);
    assert.deepEqual(selfTestLines(), ["[rc4] RC4 self-test OK"]);
});
