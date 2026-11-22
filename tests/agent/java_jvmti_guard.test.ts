// Unit tests for shared/java_jvmti_guard.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ENSURE_PLUGIN_LOADED_SYMBOL,
    guardApiFind,
    installJvmtiPluginGuard,
} from "../../agent/shared/java_jvmti_guard.js";

/** Stand-in for frida-java-bridge's api object: find() resolves any name. */
function makeApi() {
    const lookups: string[] = [];
    const api: any = {
        module: "libart.so",
        artRuntime: "runtime",
        find(name: string) {
            lookups.push(name);
            return `addr:${this.module}!${name}`;
        },
    };
    return { api, lookups };
}

function makeLoader(result: boolean | Error = true) {
    const calls: Array<[any, any]> = [];
    const loader = (address: any, runtime: any) => {
        calls.push([address, runtime]);
        if (result instanceof Error) throw result;
        return result;
    };
    return { loader, calls };
}

const LOADER_ADDR = `addr:libart.so!${ENSURE_PLUGIN_LOADED_SYMBOL}`;

test("the plugin loader stays visible to the bridge, so JVMTI is not disabled", () => {
    const { api } = makeApi();
    const { loader } = makeLoader();
    assert.equal(guardApiFind(api, loader, () => {}), "installed");
    assert.equal(api.find(ENSURE_PLUGIN_LOADED_SYMBOL), LOADER_ADDR);
});

test("the first loader lookup preloads the plugin with the real address and runtime", () => {
    const { api } = makeApi();
    const { loader, calls } = makeLoader();
    const reports: string[] = [];
    guardApiFind(api, loader, msg => reports.push(msg));
    api.find(ENSURE_PLUGIN_LOADED_SYMBOL);
    api.find(ENSURE_PLUGIN_LOADED_SYMBOL);
    assert.deepEqual(calls, [[LOADER_ADDR, "runtime"]], "preloaded exactly once");
    assert.deepEqual(reports, ["JVMTI plugin preloaded"]);
});

test("other symbols are forwarded unchanged and never trigger the preload", () => {
    const { api, lookups } = makeApi();
    const { loader, calls } = makeLoader();
    guardApiFind(api, loader, () => {});
    assert.equal(api.find("ExecuteNterpImpl"), "addr:libart.so!ExecuteNterpImpl");
    assert.deepEqual(lookups, ["ExecuteNterpImpl"]);
    assert.deepEqual(calls, []);
});

test("a missing loader symbol is passed through without a preload", () => {
    const { api } = makeApi();
    api.find = () => null;
    const { loader, calls } = makeLoader();
    guardApiFind(api, loader, () => {});
    assert.equal(api.find(ENSURE_PLUGIN_LOADED_SYMBOL), null);
    assert.deepEqual(calls, []);
});

test("a failing or throwing preload is reported and the bridge still gets the address", () => {
    for (const [result, expected] of [
        [false, "JVMTI plugin preload returned false"],
        [new Error("boom"), "JVMTI plugin preload failed: Error: boom"],
    ] as const) {
        const { api } = makeApi();
        const { loader } = makeLoader(result);
        const reports: string[] = [];
        guardApiFind(api, loader, msg => reports.push(msg));
        assert.equal(api.find(ENSURE_PLUGIN_LOADED_SYMBOL), LOADER_ADDR);
        assert.deepEqual(reports, [expected]);
    }
});

test("installing twice wraps find only once", () => {
    const { api } = makeApi();
    const { loader } = makeLoader();
    assert.equal(guardApiFind(api, loader, () => {}), "installed");
    const wrapped = api.find;
    assert.equal(guardApiFind(api, loader, () => {}), "already-installed");
    assert.equal(api.find, wrapped);
});

test("installJvmtiPluginGuard reads Java.api and never throws", () => {
    const { api } = makeApi();
    const { loader, calls } = makeLoader();
    assert.equal(installJvmtiPluginGuard({ api }, () => {}, loader), "installed");
    api.find(ENSURE_PLUGIN_LOADED_SYMBOL);
    assert.equal(calls.length, 1);

    assert.equal(installJvmtiPluginGuard({ api: null }, () => {}, loader), "unavailable"); // no ART
    assert.equal(installJvmtiPluginGuard(undefined, () => {}, loader), "unavailable");
    assert.equal(installJvmtiPluginGuard({ api: { find: 42 } }, () => {}, loader), "unavailable");
    const throwing = { get api() { throw new Error("bridge init failed"); } };
    assert.equal(installJvmtiPluginGuard(throwing, () => {}, loader), "unavailable");
});

test("the pinned bridge still loads JVMTI through api.find(<this symbol>)", async () => {
    // If a bridge upgrade renames the lookup, the guard silently stops working.
    const { readFile } = await import("node:fs/promises");
    const source = await readFile(
        new URL("../../node_modules/frida-java-bridge/lib/android.js", import.meta.url), "utf8");
    assert.ok(source.includes(`getApi().find('${ENSURE_PLUGIN_LOADED_SYMBOL}')`),
        "tryGetEnvJvmti no longer resolves EnsurePluginLoaded via getApi().find");
});
