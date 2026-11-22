// Run: npm run test:agent
//
// A definition whose only hook is a "custom" keylog installer (Fizz, rustls, lsass,
// and NSS/gotls when their plaintext hooks are absent) must report the installer's
// verdict — sync or async — not "installed" regardless (a Promise is truthy).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
// Load the agent entry first so the loader's import cycle resolves in production order.
import "../fritap_agent.js";
import { executeFromDefinition } from "./loader.js";
import { keylog_enabled, setKeylogEnabled } from "../shared/shared_structures.js";

function customOnly(install: () => boolean | Promise<boolean>, extra?: () => boolean): any {
    return {
        libraryId: "custom_lib",
        libraryType: "test",
        offsetKey: "custom_lib",
        functions: { librarySymbols: [], socketSymbols: [] },
        nativeFunctions: [],
        keylog: { kind: "custom", install },
        extraHooks: extra ? [{ install: extra }] : undefined,
    };
}

async function verdictWithKeylog(def: any, enabled = true): Promise<boolean> {
    const saved = keylog_enabled;
    setKeylogEnabled(enabled);
    try {
        return await executeFromDefinition(def, "libcustom_test.so", "libc", false, false);
    } finally {
        setKeylogEnabled(saved);
    }
}

test("custom keylog: a sync true install reports installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => true)), true);
});

test("custom keylog: a sync false install reports nothing installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => false)), false);
});

test("custom keylog: an async install resolving true reports installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => Promise.resolve(true))), true);
});

test("custom keylog: an async install resolving false reports nothing installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => Promise.resolve(false))), false);
});

test("custom keylog: a throwing or rejecting install reports nothing installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => { throw new Error("boom"); })), false);
    assert.equal(await verdictWithKeylog(customOnly(() => Promise.reject(new Error("boom")))), false);
});

test("custom keylog: without -k the installer is not run and nothing is installed", async () => {
    let ran = false;
    assert.equal(await verdictWithKeylog(customOnly(() => { ran = true; return true; }), false), false);
    assert.equal(ran, false);
});

test("custom keylog: an extra hook that installed keeps the row installed", async () => {
    assert.equal(await verdictWithKeylog(customOnly(() => Promise.resolve(false), () => true)), true);
});

test("custom keylog: a definition with its own plaintext hook stays installed", async () => {
    const def = { ...customOnly(() => Promise.resolve(false)), readHook: { symbol: "SSL_read_missing" } };
    assert.equal(await verdictWithKeylog(def), true);
});
