// conscrypt_execute_modern: its ProviderInstaller block calls Java.perform from the
// native-library phase, so it must honour the arm32 linker-notifier gate
// (shared/rtld_notifier_probe.ts) exactly like the legacy "java" phase.
//
// Run: npm run test:agent

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
// Production import order: the platform files and the hookers import each other.
import "../../../fritap_agent.js";
import { conscrypt_execute_modern } from "./conscrypt.js";
import { isJavaBlockedByBrokenLinkerNotifier, resetJavaGateForTests } from "../../../shared/rtld_notifier_probe.js";

const G = globalThis as any;
const savedPerform = G.Java.perform;

afterEach(() => {
    G.Java.perform = savedPerform;
    resetJavaGateForTests();
});

/** Run the executor on a process without the module; resolve the number of Java.perform calls. */
async function javaPerformCallsOf(linkerNotifierBroken: boolean): Promise<number> {
    resetJavaGateForTests();
    isJavaBlockedByBrokenLinkerNotifier(() => linkerNotifierBroken, () => {});   // prime the verdict
    let calls = 0;
    G.Java.perform = () => { calls++; };
    conscrypt_execute_modern("libconscrypt_jni.so", false);   // fire-and-forget, as in production
    // The loader resolves asynchronously; settle well past the point the extra hooks run.
    for (let i = 0; i < 200 && calls === 0; i++) await new Promise((r) => setImmediate(r));
    return calls;
}

test("modern conscrypt: healthy linker notifier -> the ProviderInstaller Java block runs", async () => {
    assert.equal(await javaPerformCallsOf(false), 1);
});

test("modern conscrypt: broken arm32 linker notifier -> no Java.perform at all", async () => {
    assert.equal(await javaPerformCallsOf(true), 0);
});
