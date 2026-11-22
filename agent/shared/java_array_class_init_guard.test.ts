// Unit tests for shared/java_array_class_init_guard.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    guardEnvPrototype,
    installArrayClassInitGuard,
    isArrayClassName,
    isClassInitProbe,
    shouldSkipClassInitProbe,
} from "./java_array_class_init_guard.js";

const NULL_PTR = { isNull: () => true };

/** Minimal stand-in for frida-java-bridge's Env: class handles are class names. */
function makeEnvClass() {
    const calls: Array<[string, string, string]> = [];
    const nameLookups: string[] = [];
    class FakeEnv {
        getFieldId(klass: string, name: string, sig: string) {
            calls.push([klass, name, sig]);
            return `fid:${klass}.${name}`;
        }
        getClassName(klass: string) {
            nameLookups.push(klass);
            if (klass === "throws") throw new Error("boom");
            return klass;
        }
    }
    return { FakeEnv, calls, nameLookups };
}

test("isClassInitProbe matches only the bridge's ('x', 'Z') probe", () => {
    assert.equal(isClassInitProbe("x", "Z"), true);
    assert.equal(isClassInitProbe("x", "I"), false);
    assert.equal(isClassInitProbe("value", "Z"), false);
});

test("isArrayClassName recognises primitive and object arrays only", () => {
    assert.equal(isArrayClassName("[B"), true);
    assert.equal(isArrayClassName("[Ljava.security.Provider;"), true);
    assert.equal(isArrayClassName("[[I"), true);
    assert.equal(isArrayClassName("java.lang.String"), false);
    assert.equal(isArrayClassName(""), false);
    assert.equal(isArrayClassName(null), false);
});

test("shouldSkipClassInitProbe resolves the class name only for the probe", () => {
    let resolved = 0;
    const resolve = () => { resolved++; return "[B"; };
    assert.equal(shouldSkipClassInitProbe("mField", "I", resolve), false);
    assert.equal(resolved, 0);
    assert.equal(shouldSkipClassInitProbe("x", "Z", resolve), true);
    assert.equal(resolved, 1);
});

test("shouldSkipClassInitProbe does not skip when the name cannot be resolved", () => {
    assert.equal(shouldSkipClassInitProbe("x", "Z", () => { throw new Error("x"); }), false);
    assert.equal(shouldSkipClassInitProbe("x", "Z", () => null), false);
});

test("guarded getFieldId skips the probe on array classes and forwards the rest", () => {
    const { FakeEnv, calls, nameLookups } = makeEnvClass();
    assert.equal(guardEnvPrototype(FakeEnv.prototype, NULL_PTR), "installed");
    const env = new FakeEnv();

    assert.equal(env.getFieldId("[B", "x", "Z"), NULL_PTR);
    assert.equal(env.getFieldId("[Ljava.security.Provider;", "x", "Z"), NULL_PTR);
    assert.equal(env.getFieldId("java.lang.String", "x", "Z"), "fid:java.lang.String.x");
    assert.equal(env.getFieldId("[B", "length", "I"), "fid:[B.length");
    assert.equal(env.getFieldId("throws", "x", "Z"), "fid:throws.x");

    assert.deepEqual(calls.map((c) => c[0]), ["java.lang.String", "[B", "throws"]);
    // The real lookup for a non-probe field never pays for a class-name lookup.
    assert.deepEqual(nameLookups, ["[B", "[Ljava.security.Provider;", "java.lang.String", "throws"]);
});

test("guardEnvPrototype is idempotent", () => {
    const { FakeEnv, calls } = makeEnvClass();
    assert.equal(guardEnvPrototype(FakeEnv.prototype, NULL_PTR), "installed");
    assert.equal(guardEnvPrototype(FakeEnv.prototype, NULL_PTR), "already-installed");
    new FakeEnv().getFieldId("java.lang.Object", "x", "Z");
    assert.equal(calls.length, 1);
});

test("guardEnvPrototype reports unavailable for an unexpected Env shape", () => {
    assert.equal(guardEnvPrototype(null, NULL_PTR), "unavailable");
    assert.equal(guardEnvPrototype({}, NULL_PTR), "unavailable");
    assert.equal(guardEnvPrototype({ getFieldId() { return 1; } }, NULL_PTR), "unavailable");
});

test("installArrayClassInitGuard reaches the Env prototype through vm.perform", () => {
    const { FakeEnv } = makeEnvClass();
    const java = { vm: { perform: (fn: (env: unknown) => unknown) => fn(new FakeEnv()) } };
    assert.equal(installArrayClassInitGuard(java, NULL_PTR), "installed");
    assert.equal(new FakeEnv().getFieldId("[B", "x", "Z"), NULL_PTR);
    assert.equal(installArrayClassInitGuard(java, NULL_PTR), "already-installed");
});

test("installArrayClassInitGuard never throws", () => {
    assert.equal(installArrayClassInitGuard(undefined, NULL_PTR), "unavailable");
    assert.equal(installArrayClassInitGuard({}, NULL_PTR), "unavailable");
    const throwing = { vm: { perform: () => { throw new Error("no env"); } } };
    assert.equal(installArrayClassInitGuard(throwing, NULL_PTR), "unavailable");
});
