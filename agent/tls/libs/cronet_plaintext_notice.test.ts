// Run: npm run test:agent
//
// Stripped libcronet on Android gets TCP plaintext from the supplementary
// "BoringSSL plaintext (Cronet)" row (arm64 locator, or --offsets/learned on any
// arch), so the Cronet hooker must not claim plaintext is unavailable there;
// elsewhere (non-Android, exported SSL_*, no source) the old notice stays.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
// Entry first: the hooker modules sit in an import cycle with the platform tables.
import "../../fritap_agent.js";
import { Cronet } from "./cronet.js";
import { cronetPlaintextRowCovers } from "../shared/chromium_plaintext_coverage.js";
import { plaintextRowWillHandle, PlaintextResolverDeps } from "../shared/boringssl_plaintext_resolver.js";

const G = globalThis as any;

function fakeModule(name: string, exportsNames: string[] = []): any {
    return { name, base: { add: () => null }, size: 0x100000,
        findExportByName: (n: string) => (exportsNames.includes(n) ? {} : null) };
}

interface NoticeEnv { android?: boolean; exportsNames?: string[] }

function consoleNotices(moduleName: string, arch: string, { android = true, exportsNames = [] }: NoticeEnv = {}): string[] {
    const notices: string[] = [];
    const [originalSend, originalArch, originalFind, originalJava] =
        [G.send, G.Process.arch, G.Process.findModuleByName, G.Java.available];
    G.send = (m: any) => { if (m?.contentType === "console") notices.push(m.console); };
    G.Process.arch = arch;
    G.Process.findModuleByName = (n: string) => fakeModule(n, exportsNames);
    G.Java.available = android;
    try {
        const hooker: any = Object.create(Cronet.prototype);
        hooker.module_name = moduleName;
        hooker.noticePlaintext("SSL_Read", "missing");
    } finally {
        G.send = originalSend;
        G.Process.arch = originalArch;
        G.Process.findModuleByName = originalFind;
        G.Java.available = originalJava;
    }
    return notices;
}

test("cronetPlaintextRowCovers: arm64 libcronet builds only", () => {
    assert.equal(cronetPlaintextRowCovers("libcronet.143.0.7445.0.so", "arm64"), true);
    assert.equal(cronetPlaintextRowCovers("libcronet.so", "x64"), false);
    assert.equal(cronetPlaintextRowCovers("libmainlinecronet.150.so", "arm64"), false);
});

test("no misleading 'plaintext unavailable' notice when the plaintext row covers the module", () => {
    assert.deepEqual(consoleNotices("libcronet.157.0.8103.14.so", "arm64"), []);
});

test("the old notice stays where the plaintext row does not apply", () => {
    const [x64] = consoleNotices("libcronet.so", "x64");
    assert.match(x64, /plaintext capture unavailable/);
    const [other] = consoleNotices("libwarp_mobile.so", "arm64");
    assert.match(other, /plaintext capture unavailable/);
});

// Distinct module names: the notice is once per (module, action, reason).
test("the old notice stays off Android: the plaintext row is registered for Android only", () => {
    const [linux] = consoleNotices("libcronet.1.so", "arm64", { android: false });
    assert.match(linux, /plaintext capture unavailable/);
});

test("the old notice stays when the module exports SSL_read/SSL_write (the row skips it)", () => {
    const [exported] = consoleNotices("libcronet.2.so", "arm64", { exportsNames: ["SSL_write"] });
    assert.match(exported, /plaintext capture unavailable/);
});

function willHandle(name: string, over: Partial<PlaintextResolverDeps>, fn?: "SSL_read" | "SSL_write",
                    exportsNames: string[] = []): boolean {
    const deps: Partial<PlaintextResolverDeps> = { isAndroid: () => true, locatorRuns: () => false, arch: () => "x64",
        readOffsets: () => "{OFFSETS}", learned: { lookup: () => null }, hashPrologue: () => "aa".repeat(32), ...over };
    return plaintextRowWillHandle(fakeModule(name, exportsNames), fn, deps);
}

const WRITE_ONLY_OFFSETS = { "libcronet.so": { SSL_write: { address: "0x2001", absolute: true } } };

test("plaintextRowWillHandle: --offsets cover the module on any arch, per function", () => {
    const originalPtr = G.ptr;
    G.ptr = (v: any) => ({ value: Number(v), and: (m: number) => ({ isNull: () => (Number(v) & m) === 0 }) });
    try {
        assert.equal(willHandle("libcronet.so", { readOffsets: () => WRITE_ONLY_OFFSETS }), true);
        assert.equal(willHandle("libcronet.so", { readOffsets: () => WRITE_ONLY_OFFSETS }, "SSL_write"), true);
        assert.equal(willHandle("libcronet.so", { readOffsets: () => WRITE_ONLY_OFFSETS }, "SSL_read"), false);
        // Absolute addresses keep their parity; an even one on 32-bit ARM is refused by the row.
        const even = { "libcronet.so": { SSL_write: { address: "0x2000", absolute: true } } };
        assert.equal(willHandle("libcronet.so", { readOffsets: () => even, arch: () => "arm" }, "SSL_write"), false);
        const odd = { "libcronet.so": { SSL_write: { address: "0x2001", absolute: true } } };
        assert.equal(willHandle("libcronet.so", { readOffsets: () => odd, arch: () => "arm" }, "SSL_write"), true);
    } finally {
        G.ptr = originalPtr;
    }
});

test("plaintextRowWillHandle: a prologue-verified learned entry covers the module off arm64", () => {
    const entry = { rvas: { SSL_read: 0x100, SSL_write: 0x200 }, prologueSha256: { SSL_read: "aa".repeat(32), SSL_write: "aa".repeat(32) } };
    const mod = { name: "libcronet.so", base: { add: (n: number) => ({ value: n }) }, size: 0x100000, findExportByName: () => null };
    const deps: Partial<PlaintextResolverDeps> = { isAndroid: () => true, locatorRuns: () => false, arch: () => "x64",
        readOffsets: () => "{OFFSETS}", learned: { lookup: () => entry }, hashPrologue: () => "AA".repeat(32) };
    assert.equal(plaintextRowWillHandle(mod as any, "SSL_read", deps), true);
    assert.equal(plaintextRowWillHandle(mod as any, "SSL_read", { ...deps, hashPrologue: () => "bb".repeat(32) }), false);
});

test("plaintextRowWillHandle: arm64 locator, Android, module name and exports gate the row", () => {
    assert.equal(willHandle("libcronet.143.0.so", { locatorRuns: () => true }), true);
    assert.equal(willHandle("libcronet.so", {}), false);
    assert.equal(willHandle("libcronet.so", { locatorRuns: () => true, isAndroid: () => false }), false);
    assert.equal(willHandle("libmainlinecronet.so", { locatorRuns: () => true }), false);
    assert.equal(willHandle("libcronet.so", { locatorRuns: () => true }, undefined, ["SSL_read"]), false);
});

test("plaintextRowWillHandle: libsignal_jni.so is covered like Cronet (arm64 locator, no exports)", () => {
    assert.equal(willHandle("libsignal_jni.so", { locatorRuns: () => true }), true);
    assert.equal(willHandle("libsignal_jni.so", { locatorRuns: () => true }, "SSL_write"), true);
    assert.equal(willHandle("libsignal_jni.so", {}), false);
    assert.equal(willHandle("libsignal_jni.so", { locatorRuns: () => true, isAndroid: () => false }), false);
    assert.equal(willHandle("libsignal_jni.so", { locatorRuns: () => true }, undefined, ["SSL_read"]), false);
    assert.equal(willHandle("libsignal_jni_testing.so", { locatorRuns: () => true }), false);
});
