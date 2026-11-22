// Tests for the Fizz wiring: the registry row's content filter (cheap prefilter,
// RTTI confirmation, per-path cache), deriveSecret dedupe across modules, the
// single detach-teardown summary, and the ONE executor both agent trees run (the
// shared installer, agent/shared/fizz_install.ts).
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
// Load the agent graph first (android.ts <-> fritap_agent import cycle).
import "../fritap_agent.js";

import {
    classifyFizzModulePath, isFizzCandidateModule, installFizzKeylog, resetFizzInstallStateForTests,
} from "./fizz_install.js";
import { installFizzKeyHooks, resetFizzKeylogStateForTests, FIZZ_PROBE_EXPORT } from "./fizz_keylog.js";
import { runDetachTeardowns } from "./detach_teardown.js";
import { DetachReportBuilder } from "./detach_report.js";
import { fizzAndroidRow, FIZZ_MODULE_PATTERN } from "../platforms/android.js";

const G = globalThis as any;

/** Minimal NativePointer over a JS number (enough for add/sub/toString/compare). */
function P(v: number): any {
    return {
        v,
        isNull: () => v === 0,
        add: (o: any) => P(v + Number(typeof o === "object" ? o.v : o)),
        sub: (o: any) => P(v - Number(typeof o === "object" ? o.v : o)),
        toString: (radix?: number) => (radix === 16 ? v.toString(16) : "0x" + v.toString(16)),
        compare: (o: any) => (v === o.v ? 0 : v < o.v ? -1 : 1),
        equals: (o: any) => v === o.v,
    };
}

interface FakeModuleOpts { name: string; path: string; base?: number; exports?: Record<string, number>; }

function fakeModule(o: FakeModuleOpts): any {
    const base = P(o.base ?? 0x7000000000);
    return {
        name: o.name, path: o.path, base, size: 0x1000000,
        findExportByName: (n: string) => (o.exports && n in o.exports ? base.add(o.exports[n]) : null),
        // r-- at the base, r-x (text, and .rodata on builds without -z separate-code) after it, then rw- data.
        enumerateRanges: () => [
            { base, size: 0x100000, protection: "r--" }, { base: base.add(0x100000), size: 0x100000, protection: "r-x" },
            { base: base.add(0x200000), size: 0x100000, protection: "rw-" },
        ],
        enumerateExports: () => [],
    };
}

let modules: any[] = [];
let scans = 0;
/** Module name -> the range holding its Fizz RTTI name. */
let rttiIn = new Map<string, "r--" | "r-x">();
let attaches: string[] = [];

beforeEach(() => {
    resetFizzInstallStateForTests();
    resetFizzKeylogStateForTests();
    runDetachTeardowns(); // drop teardowns registered by an earlier test
    modules = [];
    scans = 0;
    rttiIn = new Map();
    attaches = [];
    G.Process.arch = "arm64";
    G.Process.findModuleByName = (n: string) => modules.find((m) => m.name === n) ?? null;
    G.Memory.scanSync = (base: any) => {
        scans++;
        if (modules.some((x) => x.base.add(0x200000).v === base.v)) throw new Error("writable data must never be scanned");
        const inRodata = modules.find((x) => x.base.v === base.v && rttiIn.get(x.name) === "r--");
        const inText = modules.find((x) => x.base.add(0x100000).v === base.v && rttiIn.get(x.name) === "r-x");
        return inRodata || inText ? [{ address: base, size: 4 }] : [];
    };
    G.Interceptor.attach = (at: any) => { attaches.push(at.toString()); return { detach: () => {} }; };
});

// ---- path classification (pure) ----------------------------------------------------

test("system/APEX images and unknown paths are rejected without any work", () => {
    for (const p of ["/system/lib64/libssl.so", "/apex/com.android.conscrypt/lib64/libssl.so", "/vendor/lib64/x.so",
                     "/product/lib64/x.so", "/system_ext/lib64/x.so", ""]) {
        assert.equal(classifyFizzModulePath("libx.so", p), "reject", p);
    }
});

test("app-private libs (Meta lib-compressed) and known Meta host names may be scanned; other app libs get the export check only", () => {
    assert.equal(classifyFizzModulePath("libcoldstart.so", "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so"), "scan");
    assert.equal(classifyFizzModulePath("libfoo.so", "/data/user/0/com.instagram.android/lib-compressed/libfoo.so"), "scan");
    assert.equal(classifyFizzModulePath("libstartup.so", "/data/app/~~a/com.instagram.android-b/lib/arm64/libstartup.so"), "scan");
    assert.equal(classifyFizzModulePath("libfoo.so", "/data/app/~~a/com.example-b/lib/arm64/libfoo.so"), "export-only");
});

test("the row's name pattern admits any shared object; the content filter decides", () => {
    const row = fizzAndroidRow();
    assert.equal(row.pattern, FIZZ_MODULE_PATTERN);
    assert.ok(FIZZ_MODULE_PATTERN.test("libcoldstart.so"));
    assert.equal(row.contentFilter, isFizzCandidateModule);
    assert.equal(row.libraryType, "fizz");
    assert.equal(row.protocol, "tls");
});

// ---- content filter ---------------------------------------------------------------

test("filter: an app-private lib is a candidate by path alone, without any memory scan", () => {
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so" }));
    rttiIn.set("libcoldstart.so", "r--");
    assert.equal(isFizzCandidateModule("libcoldstart.so"), true);
    assert.equal(scans, 0);
});

test("filter: an app-private lib without the RTTI name is still accepted cheaply; the verdict is cached per path", () => {
    modules.push(fakeModule({ name: "libhatch.so", path: "/data/data/com.facebook.katana/lib-compressed/libhatch.so" }));
    assert.equal(isFizzCandidateModule("libhatch.so"), true);
    assert.equal(isFizzCandidateModule("libhatch.so"), true);
    assert.equal(scans, 0);
});

test("installer: the RTTI check runs only after yielding; a lib without Fizz RTTI resolves false and hooks nothing", async () => {
    modules.push(fakeModule({ name: "libhatch.so", path: "/data/data/com.facebook.katana/lib-compressed/libhatch.so" }));
    const pending = installFizzKeylog("libhatch.so");
    assert.equal(scans, 0);                                        // nothing scanned synchronously
    assert.equal(await pending, false);
    assert.equal(scans, 2);                                        // r-- then r-x, never rw-
    assert.equal(attaches.length, 0);
});

/** console lines the agent sends while `fn` runs. */
async function sentConsole(fn: () => Promise<unknown>): Promise<string[]> {
    const lines: string[] = [];
    const saved = G.send;
    G.send = (m: any) => { if (m?.contentType === "console") lines.push(m.console); };
    try { await fn(); } finally { G.send = saved; }
    return lines;
}

test("installer: RTTI name in r-- .rodata is confirmed by the first scan (no export needed)", async () => {
    G.Process.arch = "x64"; // the locator then misses at once with one line: proof that confirmation passed
    modules.push(fakeModule({ name: "libsep.so", path: "/data/data/p/lib-compressed/libsep.so" }));
    rttiIn.set("libsep.so", "r--");
    const lines = await sentConsole(() => installFizzKeylog("libsep.so"));
    assert.equal(scans, 1);
    assert.ok(lines.some((l) => l.includes("libsep.so: Fizz deriveSecret not located")), lines.join("\n"));
});

test("installer: RTTI name in the r-x segment (Meta builds keep .rodata there) is still confirmed", async () => {
    // Regression: the data-ranges-only check skipped libcoldstart's .rodata (first PT_LOAD is r-x).
    G.Process.arch = "x64";
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/p/lib-compressed/libcoldstart.so" }));
    rttiIn.set("libcoldstart.so", "r-x");
    const lines = await sentConsole(() => installFizzKeylog("libcoldstart.so"));
    assert.equal(scans, 2);
    assert.ok(lines.some((l) => l.includes("libcoldstart.so: Fizz deriveSecret not located")), lines.join("\n"));
});

test("installer: a lib whose data ranges carry the Fizz RTTI proceeds to locate", async () => {
    G.Process.arch = "x64"; // locator misses at once after the RTTI confirmation
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/p/lib-compressed/libcoldstart.so",
                               exports: { [FIZZ_PROBE_EXPORT]: 0x40 } }));
    rttiIn.set("libcoldstart.so", "r--");
    assert.equal(await installFizzKeylog("libcoldstart.so"), true);
    assert.deepEqual(attaches, ["0x7000000040"]);
});

test("filter: the probe export accepts at once (no scan), even outside app-private dirs", () => {
    modules.push(fakeModule({ name: "libscroll.so", path: "/data/app/~~a/com.x-b/lib/arm64/libscroll.so", exports: { [FIZZ_PROBE_EXPORT]: 0x40 } }));
    assert.equal(isFizzCandidateModule("libscroll.so"), true);
    assert.equal(scans, 0);
});

test("filter: other app libs without the export are never scanned", () => {
    modules.push(fakeModule({ name: "libfoo.so", path: "/data/app/~~a/com.x-b/lib/arm64/libfoo.so" }));
    rttiIn.set("libfoo.so", "r--");
    assert.equal(isFizzCandidateModule("libfoo.so"), false);
    assert.equal(scans, 0);
});

test("filter: a judged path answers from the cache before any module lookup", () => {
    modules.push(fakeModule({ name: "libfoo.so", path: "/data/app/~~a/com.x-b/lib/arm64/libfoo.so" }));
    assert.equal(isFizzCandidateModule("libfoo.so", "/data/app/~~a/com.x-b/lib/arm64/libfoo.so"), false);
    let lookups = 0;
    G.Process.findModuleByName = () => { lookups++; return null; };
    assert.equal(isFizzCandidateModule("libfoo.so", "/data/app/~~a/com.x-b/lib/arm64/libfoo.so"), false);
    assert.equal(lookups, 0);
    assert.equal(scans, 0);
});

test("filter: system paths are rejected before the module is even resolved", () => {
    let lookups = 0;
    G.Process.findModuleByName = () => { lookups++; return null; };
    assert.equal(isFizzCandidateModule("libssl.so", "/system/lib64/libssl.so"), false);
    assert.equal(lookups, 0);
});

test("filter: non-arm64 processes and unresolvable modules fail closed", () => {
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/p/lib-compressed/libcoldstart.so" }));
    rttiIn.set("libcoldstart.so", "r--");
    G.Process.arch = "arm";
    assert.equal(isFizzCandidateModule("libcoldstart.so"), false);
    G.Process.arch = "arm64";
    assert.equal(isFizzCandidateModule("libgone.so"), false);
});

// ---- deriveSecret dedupe + teardown -------------------------------------------------

function located(derive: number, append: number): any {
    return { deriveSecret: P(derive), appendToTranscript: P(append), slot: 0x14, source: "scan" };
}

test("deriveSecret is hooked once per address across modules; the second module adds nothing", () => {
    const a = fakeModule({ name: "libstartup.so", path: "/data/data/p/lib-compressed/libstartup.so", base: 0x1000000 });
    const b = fakeModule({ name: "libstartup_copy.so", path: "/data/data/p/lib-compressed/libstartup_copy.so", base: 0x2000000 });
    assert.equal(installFizzKeyHooks(a, located(0x1356da0, 0x13617c0)), true);
    assert.equal(installFizzKeyHooks(b, located(0x1356da0, 0x13617c0)), false);
    assert.deepEqual(attaches, ["0x13617c0", "0x1356da0"]);
});

test("a module with only the probe export hooks it next to another module's deriveSecret; one teardown summary", () => {
    const core = fakeModule({ name: "libstartup.so", path: "/data/data/p/lib-compressed/libstartup.so", base: 0x1000000 });
    const scroll = fakeModule({ name: "libscrollmerged.so", path: "/data/data/p/lib-compressed/libscrollmerged.so",
                                base: 0x3000000, exports: { [FIZZ_PROBE_EXPORT]: 0x6691c0 } });
    modules.push(core, scroll);
    assert.equal(installFizzKeyHooks(core, located(0x1356da0, 0x13617c0)), true);
    assert.equal(installFizzKeyHooks(scroll, null), true);
    assert.equal(attaches.length, 3);
    const report = new DetachReportBuilder();
    runDetachTeardowns(report);
    const steps = report.finish().steps.filter((s) => s.name === "teardown:fizz-keylog");
    assert.equal(steps.length, 1);
    assert.equal(steps[0].summary?.modules, 2);
    assert.equal(steps[0].summary?.deriveSecretHooks, 1);
    assert.equal(steps[0].summary?.lines, 0);
    assert.equal(steps[0].summary?.contexts, 0);
    assert.equal(steps[0].summary?.handshakes, 0);
});

test("a module with neither a location nor the probe export installs nothing", () => {
    const m = fakeModule({ name: "libstreamingmerged.so", path: "/data/data/p/lib-compressed/libstreamingmerged.so" });
    assert.equal(installFizzKeyHooks(m, null), false);
    assert.equal(attaches.length, 0);
});

// ---- both trees -> one executor ---------------------------------------------------

test("both trees run the shared installer itself as the row's executor", () => {
    assert.equal(fizzAndroidRow().hookFn, installFizzKeylog);
});

test("the row's executor resolves the shared installer's verdict", async () => {
    G.Process.arch = "x64"; // locator misses at once; the probe export still hooks
    modules.push(fakeModule({ name: "libprobe.so", path: "/data/data/p/lib-compressed/libprobe.so", base: 0x1000000,
                               exports: { [FIZZ_PROBE_EXPORT]: 0x40 } }));
    modules.push(fakeModule({ name: "libnone.so", path: "/data/data/p/lib-compressed/libnone.so", base: 0x3000000 }));
    const hookFn = fizzAndroidRow().hookFn;
    assert.equal(await hookFn("libprobe.so"), true);
    assert.equal(await hookFn("libnone.so"), false);
    assert.deepEqual(attaches, ["0x1000040"]);
});

test("the installer runs at most once per mapping", async () => {
    G.Process.arch = "x64";
    modules.push(fakeModule({ name: "libonce.so", path: "/data/data/p/lib-compressed/libonce.so", exports: { [FIZZ_PROBE_EXPORT]: 0x40 } }));
    const first = installFizzKeylog("libonce.so");
    assert.equal(installFizzKeylog("libonce.so"), first);
    assert.equal(await first, true);
    assert.equal(attaches.length, 1);
});

test("registry: the Fizz row matches a Fizz host and is filtered out for other libraries", async () => {
    const { HookRegistry } = await import("./registry.js");
    const reg = new HookRegistry();
    reg.registerAll([fizzAndroidRow() as any]);
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so", base: 0x1000000 }));
    modules.push(fakeModule({ name: "libfoo.so", path: "/data/app/~~a/com.x-b/lib/arm64/libfoo.so", base: 0x2000000 }));
    rttiIn.set("libcoldstart.so", "r--");
    const lib = (name: string, path?: string) => reg.findAllMatches("linux", name, path, "tls").map((h) => h.library);
    assert.deepEqual(lib("libcoldstart.so"), ["Fizz (Meta)"]);
    assert.deepEqual(lib("libfoo.so"), []);
    assert.deepEqual(lib("libssl.so", "/system/lib64/libssl.so"), []);
});

test("an export dlsym finds in a DEPENDENCY (address outside the module) is not the module's own", async () => {
    // Facebook: every small lib-compressed lib linking libcoldstart.so resolves the probe.
    modules.push(fakeModule({ name: "libclocksync.so", path: "/data/app/~~a/com.x-b/lib/arm64/libclocksync.so", base: 0x1000000,
                               exports: { [FIZZ_PROBE_EXPORT]: 0x5000000 } /* beyond size 0x1000000 */ }));
    assert.equal(isFizzCandidateModule("libclocksync.so"), false);
    assert.equal(installFizzKeyHooks(modules[0], null), false);
    // App-private copy: accepted cheaply by path, but the installer finds no own export and no RTTI.
    modules.push(fakeModule({ name: "libclock2.so", path: "/data/data/p/lib-compressed/libclock2.so", base: 0x3000000,
                               exports: { [FIZZ_PROBE_EXPORT]: 0x5000000 } }));
    assert.equal(isFizzCandidateModule("libclock2.so"), true);
    assert.equal(await installFizzKeylog("libclock2.so"), false);
    assert.equal(attaches.length, 0);
});

test("the Fizz row is supplementary: a Fizz-accepted module stays eligible for the primary BoringSSL / library-scan paths", async () => {
    const { HookRegistry } = await import("./registry.js");
    const { installTagFor } = await import("./library_scanner.js");
    const row = fizzAndroidRow();
    assert.equal(row.supplementary, true);
    assert.notEqual(installTagFor(row as any, "tls"), "tls");      // never marks the module hooked for tls
    const reg = new HookRegistry();
    reg.registerAll([row as any]);
    modules.push(fakeModule({ name: "libcoldstart.so", path: "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so" }));
    const path = "/data/data/com.facebook.katana/lib-compressed/libcoldstart.so";
    assert.deepEqual(reg.findAllMatches("linux", "libcoldstart.so", path, "tls").map((h) => h.library), ["Fizz (Meta)"]);
    // --library-scan and the tlsLibHunter pre-scan filter with findPrimaryMatch: Fizz alone does not hide it.
    assert.equal(reg.findPrimaryMatch("linux", "libcoldstart.so", path, "tls"), undefined);
    reg.register({ platform: "linux", pattern: /.*libcoldstart\.so/, hookFn: () => true, library: "BoringSSL (auto-detected)",
                   libraryType: "boringssl", protocol: "tls" } as any);
    assert.equal(reg.findPrimaryMatch("linux", "libcoldstart.so", path, "tls")?.library, "BoringSSL (auto-detected)");
    assert.deepEqual(reg.findAllMatches("linux", "libcoldstart.so", path, "tls").map((h) => h.library).sort(),
                     ["BoringSSL (auto-detected)", "Fizz (Meta)"]);
});

test("the probe export is hooked once per address even if two module views report it", () => {
    const a = fakeModule({ name: "libscrollmerged.so", path: "/data/data/p/lib-compressed/libscrollmerged.so", base: 0x1000000,
                           exports: { [FIZZ_PROBE_EXPORT]: 0x40 } });
    const b = { ...a, name: "libscrollmerged_alias.so", base: P(0x1000000), size: 0x1000000 };
    modules.push(a, b);
    assert.equal(installFizzKeyHooks(a, null), true);
    assert.equal(installFizzKeyHooks(b, null), false);
    assert.equal(attaches.length, 1);
});
