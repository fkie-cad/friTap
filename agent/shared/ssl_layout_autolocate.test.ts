// Unit tests for the generic ssl_st layout lookup trigger (shared/ssl_layout_autolocate.ts).
// Frida dependencies (arch, export lookup, the async locator) are injected.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    SslLayoutAutoLocateDeps, createSslLayoutAutoLocator, isKnownNonBoringSslModule, prefetchSslLayout,
    shouldLocateLayoutFor,
} from "./ssl_layout_autolocate.js";
import {
    hasLayoutLocatorStarted, isLayoutLocatorSettled, isSslLayoutUsable, markLayoutLocatorStarted,
    readSslClientRandom, resetSslIdentityState, setClientRandomMissObserver, sslLayoutFor,
} from "./ssl_identity.js";

interface FakeDeps extends SslLayoutAutoLocateDeps {
    located: string[];
    exporting: Set<string>;
    arm64: boolean;
    scans: boolean;
    result: { s3Off: number; crOff: number } | null | Error;
}

function fakeDeps(): FakeDeps {
    const deps: FakeDeps = {
        located: [], exporting: new Set(), arm64: true, scans: true, result: { s3Off: 0x30, crOff: 0x30 },
        isArm64: () => deps.arm64,
        scansAllowed: () => deps.scans,
        hasClientRandomExport: (module) => deps.exporting.has(module),
        locate: async (module) => {
            deps.located.push(module);
            if (deps.result instanceof Error) throw deps.result;
            return deps.result;
        },
        log: () => { /* quiet */ },
    };
    return deps;
}

const HTTPENGINE = "libhttpengine.so";

beforeEach(() => resetSslIdentityState());

test("first miss starts one lookup, installs the decoded layout and settles", async () => {
    const deps = fakeDeps();
    const autoLocate = createSslLayoutAutoLocator(deps);
    const pending = autoLocate(HTTPENGINE);
    assert.ok(pending, "a lookup was started");
    assert.equal(hasLayoutLocatorStarted(HTTPENGINE), true);
    assert.equal(isLayoutLocatorSettled(HTTPENGINE), false);
    await pending;
    assert.deepEqual(sslLayoutFor(HTTPENGINE), { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    assert.equal(isSslLayoutUsable(HTTPENGINE), true);
    assert.equal(isLayoutLocatorSettled(HTTPENGINE), true);
});

test("the lookup runs at most once per module", async () => {
    const deps = fakeDeps();
    const autoLocate = createSslLayoutAutoLocator(deps);
    await autoLocate(HTTPENGINE);
    assert.equal(autoLocate(HTTPENGINE), null);
    assert.deepEqual(deps.located, [HTTPENGINE]);
});

test("a module exporting SSL_get_client_random never triggers (and is decided once)", () => {
    const deps = fakeDeps();
    let exportChecks = 0;
    deps.hasClientRandomExport = () => { exportChecks++; return true; };
    const autoLocate = createSslLayoutAutoLocator(deps);
    assert.equal(autoLocate("libboringssl_with_exports.so"), null);
    assert.equal(autoLocate("libboringssl_with_exports.so"), null);
    assert.equal(exportChecks, 1);
    assert.deepEqual(deps.located, []);
    assert.equal(hasLayoutLocatorStarted("libboringssl_with_exports.so"), false);
});

test("known non-BoringSSL libraries, non-arm64 and --pairip-safe never trigger", () => {
    for (const name of ["libssl.so.3", "libcrypto.so.1.1", "libgnutls.so.30", "libnss3.so", "libwolfssl.so", "libmbedtls.so.14"]) {
        assert.equal(isKnownNonBoringSslModule(name), true, name);
    }
    assert.equal(isKnownNonBoringSslModule(HTTPENGINE), false);
    const deps = fakeDeps();
    assert.equal(shouldLocateLayoutFor("libssl.so.3", deps), false);
    assert.equal(shouldLocateLayoutFor("", deps), false);
    deps.arm64 = false;
    assert.equal(shouldLocateLayoutFor(HTTPENGINE, deps), false);
    deps.arm64 = true;
    deps.scans = false;
    assert.equal(shouldLocateLayoutFor(HTTPENGINE, deps), false);
    deps.scans = true;
    assert.equal(shouldLocateLayoutFor(HTTPENGINE, deps), true);
});

test("a throwing export lookup is treated as 'do not trigger'", () => {
    const deps = fakeDeps();
    deps.hasClientRandomExport = () => { throw new Error("no module"); };
    assert.equal(shouldLocateLayoutFor(HTTPENGINE, deps), false);
});

test("an undecoded or failing lookup settles with no layout", async () => {
    for (const result of [null, new Error("scan failed")]) {
        resetSslIdentityState();
        const deps = fakeDeps();
        deps.result = result;
        await createSslLayoutAutoLocator(deps)(HTTPENGINE);
        assert.equal(sslLayoutFor(HTTPENGINE), null);
        assert.equal(isLayoutLocatorSettled(HTTPENGINE), true);
        assert.equal(hasLayoutLocatorStarted(HTTPENGINE), true);
    }
});

test("wired as the miss observer: a cr-less record read triggers exactly one lookup", async () => {
    const deps = fakeDeps();
    const autoLocate = createSslLayoutAutoLocator(deps);
    const lookups: Promise<void>[] = [];
    setClientRandomMissObserver((module) => { const p = autoLocate(module); if (p) lookups.push(p); });
    try {
        const ssl: any = { isNull: () => false, toString: () => "0x5000" };
        assert.equal(readSslClientRandom(ssl, HTTPENGINE), "");
        assert.equal(readSslClientRandom(ssl, HTTPENGINE), "");
        await Promise.all(lookups);
        assert.deepEqual(deps.located, [HTTPENGINE]);
        assert.equal(sslLayoutFor(HTTPENGINE)?.source, "decoded");
    } finally {
        setClientRandomMissObserver(null);
    }
});

// ---- hook-install prefetch (early trigger) ----------------------------------

test("prefetch at hook install starts the lookup before any record", async () => {
    const deps = fakeDeps();
    const messages: string[] = [];
    deps.log = (message) => { messages.push(message); };
    const autoLocate = createSslLayoutAutoLocator(deps);
    const pending = autoLocate(HTTPENGINE, "hook-install");
    assert.ok(pending, "a lookup was started");
    await pending;
    assert.deepEqual(deps.located, [HTTPENGINE]);
    assert.equal(sslLayoutFor(HTTPENGINE)?.source, "decoded");
    assert.ok(messages.some((m) => m.includes("plaintext hooks installed")), messages.join("\n"));
});

test("prefetch then a client_random miss: still exactly one lookup", async () => {
    const deps = fakeDeps();
    const autoLocate = createSslLayoutAutoLocator(deps);
    const pending = autoLocate(HTTPENGINE, "hook-install");
    assert.equal(autoLocate(HTTPENGINE, "hook-install"), null, "second install of the same module");
    assert.equal(autoLocate(HTTPENGINE, "client-random-miss"), null, "lazy trigger after the prefetch");
    await pending;
    assert.deepEqual(deps.located, [HTTPENGINE]);
});

test("prefetch honours the same gating as the lazy trigger", () => {
    const cases: [string, (deps: FakeDeps) => void][] = [
        ["non-arm64", (deps) => { deps.arm64 = false; }],
        ["--pairip-safe", (deps) => { deps.scans = false; }],
        ["exports SSL_get_client_random", (deps) => { deps.exporting.add(HTTPENGINE); }],
    ];
    for (const [what, configure] of cases) {
        resetSslIdentityState();
        const deps = fakeDeps();
        configure(deps);
        assert.equal(createSslLayoutAutoLocator(deps)(HTTPENGINE, "hook-install"), null, what);
        assert.equal(hasLayoutLocatorStarted(HTTPENGINE), false, what);
    }
    const deps = fakeDeps();
    assert.equal(createSslLayoutAutoLocator(deps)("libssl.so.3", "hook-install"), null, "denylisted library");
    assert.deepEqual(deps.located, []);
});

test("chromium install under --pairip-safe starts no scan", () => {
    const deps = fakeDeps();
    deps.scans = false;
    const autoLocate = createSslLayoutAutoLocator(deps);
    assert.equal(autoLocate("libmonochrome_64.so", "chromium-install"), null);
    assert.equal(autoLocate("libmonochrome_64.so", "client-random-miss"), null);
    assert.deepEqual(deps.located, []);
    assert.equal(hasLayoutLocatorStarted("libmonochrome_64.so"), false);
});

test("chromium install on arm64 starts the one shared lookup", async () => {
    const deps = fakeDeps();
    const autoLocate = createSslLayoutAutoLocator(deps);
    await autoLocate("libmonochrome_64.so", "chromium-install");
    assert.equal(autoLocate("libmonochrome_64.so", "hook-install"), null);
    assert.deepEqual(deps.located, ["libmonochrome_64.so"]);
    assert.equal(sslLayoutFor("libmonochrome_64.so")?.source, "decoded");
});

test("prefetch defers to a locator another path already started", () => {
    const deps = fakeDeps();
    markLayoutLocatorStarted("libmonochrome_64.so"); // a lookup some other path already started
    assert.equal(createSslLayoutAutoLocator(deps)("libmonochrome_64.so", "hook-install"), null);
    assert.deepEqual(deps.located, []);
});

test("the Frida-wired prefetchSslLayout never throws", () => {
    assert.doesNotThrow(() => prefetchSslLayout(HTTPENGINE));
    assert.doesNotThrow(() => prefetchSslLayout(""));
});
