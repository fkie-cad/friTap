// Dual-tree parity for NSS key extraction.
//
// The legacy platform hookers (agent/legacy/tls/platforms/<os>/nss_<os>.ts: the DEFAULT
// tree) and the modern definitions (agent/tls/platforms/<os>/nss_<os>.ts: --modern) must
// both reach the ONE shared installer (agent/tls/libs/nss_install.ts) for the same
// module, with equivalent addresses, in the same tier order.
//
// Each case runs the exact executor a platform registry row references (nss_execute /
// nss_execute_modern) against one fake process: modules and their exports, served
// through ApiResolver, Process.* and Module.findExportByName. Module.findGlobalExportByName
// finds nothing, as on Android, where the app's linker namespace is invisible to it.
// Tier 1 (the keylog-writer locator) misses on these images (none is a readable ELF,
// which also covers the PE / Mach-O case), so both trees go on to tiers 2/3;
// NSS.installFallbackKeyHooks is spied to record exactly what reaches them.
//
// Run: npm run test:agent

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { setPlatform } from "../../../shared/frida-test-stubs.js";
// Production import order: the platform files and the hookers import each other.
import "../../../fritap_agent.js";
import { setPcapEnabled } from "../../../shared/shared_structures.js";
import { NSS } from "../../../tls/libs/nss.js";
import { nss_execute as legacyAndroid, NSS_Android } from "./android/nss_android.js";
import { nss_execute as legacyLinux, NSS_Linux } from "./linux/nss_linux.js";
import { nss_execute as legacyMacos, NSS_MacOS } from "./macos/nss_macos.js";
import { nss_execute as legacyWindows, NSS_Windows } from "./windows/nss_windows.js";
import { nss_execute_modern as modernAndroid } from "../../../tls/platforms/android/nss_android.js";
import { nss_execute_modern as modernLinux } from "../../../tls/platforms/linux/nss_linux.js";
import { nss_execute_modern as modernMacos } from "../../../tls/platforms/macos/nss_macos.js";
import { nss_execute_modern as modernWindows } from "../../../tls/platforms/windows/nss_windows.js";

const G = globalThis as any;
const N: any = NSS;

type Executor = (moduleName: string, isBaseHook: boolean) => unknown;
type Exports = { [module: string]: string[] };

const NSPR = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName",
              "PR_GetNameForIdentity", "PR_GetDescType", "PR_Close"];
const SSL = ["SSL_ImportFD", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI"];
const PK11 = ["PK11_ExtractKeyValue", "PK11_GetKeyData", "PK11_GenerateRandom", "NSSSSL_GetVersion"];
const SOCKETS = ["getpeername", "getsockname", "ntohs", "ntohl"];

/** Every address the fallback tiers consume (installFallbackKeyHooks and bindNativeHelpers). */
const TIER_INPUTS = ["SSL_ImportFD", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI", "PR_Close", "PK11_GenerateRandom",
                     "PR_GetDescType", "PR_GetNameForIdentity", "PK11_ExtractKeyValue", "PK11_GetKeyData"];

interface Case {
    label: string;
    os: string;              // Process.platform
    hooked: string;          // the module the platform row matches
    sslModule: string;       // the module owning SSL_ImportFD
    exports: Exports;
    legacy: Executor;
    modern: Executor;
}

const CASES: Case[] = [
    {   // Firefox for Android: NSPR/NSS/SSL folded into libnss3.so; the system libssl.so is BoringSSL.
        label: "Android (folded libnss3.so)", os: "linux", hooked: "libnss3.so", sslModule: "libnss3.so",
        exports: { "libnss3.so": [...NSPR, ...SSL, ...PK11], "libc.so": SOCKETS, "libssl.so": ["SSL_new", "SSL_read", "SSL_write"] },
        legacy: legacyAndroid, modern: modernAndroid,
    },
    {   // Linux distro NSS: libnspr4.so + libssl3.so + libnss3.so.
        label: "Linux (libnspr4.so + libssl3.so + libnss3.so)", os: "linux", hooked: "libnspr4.so", sslModule: "libssl3.so",
        exports: { "libnspr4.so": NSPR, "libssl3.so": [...SSL, "SSL_GetSessionID"], "libnss3.so": PK11, "libc.so.6": SOCKETS },
        legacy: legacyLinux, modern: modernLinux,
    },
    {   // Firefox for macOS: everything in libnss3.dylib.
        label: "macOS (libnss3.dylib)", os: "darwin", hooked: "libnss3.dylib", sslModule: "libnss3.dylib",
        exports: { "libnss3.dylib": [...NSPR, ...SSL, ...PK11], "libSystem.B.dylib": SOCKETS },
        legacy: legacyMacos, modern: modernMacos,
    },
    {   // Firefox / Thunderbird for Windows: folded nss3.dll (MOZ_FOLD_LIBS).
        label: "Windows (folded nss3.dll)", os: "windows", hooked: "nss3.dll", sslModule: "nss3.dll",
        exports: { "nss3.dll": [...NSPR, ...SSL, ...PK11], "WS2_32.dll": SOCKETS },
        legacy: legacyWindows, modern: modernWindows,
    },
    {   // Unfolded Windows NSS: libnspr4.dll + ssl3.dll + nss3.dll.
        label: "Windows (libnspr4.dll + ssl3.dll + nss3.dll)", os: "windows", hooked: "libnspr4.dll", sslModule: "ssl3.dll",
        exports: { "libnspr4.dll": NSPR, "ssl3.dll": SSL, "nss3.dll": PK11, "WS2_32.dll": SOCKETS },
        legacy: legacyWindows, modern: modernWindows,
    },
];

// ---- fake process ------------------------------------------------------------------

/** An export address, identified as "<module>!<symbol>". */
function exportPtr(module: string, symbol: string): any {
    const id = `${module}!${symbol}`;
    return { id, isNull: () => false, toString: () => id, equals: (o: any) => String(o) === id };
}

let nextBase = 0x100000;

/** A loaded module whose image is unreadable (size 0): tier 1 sees no ELF and misses. */
function fakeModule(name: string, symbols: string[]): any {
    nextBase += 0x100000;
    const v = nextBase;
    const base = { isNull: () => false, toString: () => `0x${v.toString(16)}`, add: () => base };
    return {
        name, path: `/fake/${name}`, base, size: 0,
        findExportByName: (s: string) => symbols.includes(s) ? exportPtr(name, s) : null,
        enumerateExports: () => symbols.map((s) => ({ type: "function", name: s, address: exportPtr(name, s) })),
        enumerateRanges: () => [], enumerateSymbols: () => [], enumerateImports: () => [],
    };
}

function globToRegExp(glob: string): RegExp {
    return new RegExp("^" + glob.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$");
}

const saved = { process: { ...G.Process }, resolver: G.ApiResolver, globalExport: G.Module.findGlobalExportByName,
                send: G.send, attach: G.Interceptor.attach,
                fallback: N.installFallbackKeyHooks, scope: N.setExportScope, bind: N.bindNativeHelpers };

/** Serve `exports` as the loaded modules of the process (a fresh mapping each call). */
function loadProcess(os: string, exports: Exports): void {
    const modules = Object.entries(exports).map(([name, symbols]) => fakeModule(name, symbols));
    setPlatform(os);
    G.Process.enumerateModules = () => modules;
    G.Process.findModuleByName = (n: string) => modules.find((m) => m.name === n) ?? null;
    G.Process.getModuleByName = (n: string) => modules.find((m) => m.name === n) ?? null;
    G.Process.findModuleByAddress = (p: any) => modules.find((m) => String(p).startsWith(`${m.name}!`)) ?? null;
    G.Module.findGlobalExportByName = () => null;
    G.ApiResolver = function () {
        return {
            enumerateMatches: (query: string) => {
                const [glob, symbol] = query.replace(/^exports:/, "").split("!");
                return modules.filter((m) => globToRegExp(glob).test(m.name) && exports[m.name].includes(symbol))
                    .map((m) => ({ name: `${m.name}!${symbol}`, address: exportPtr(m.name, symbol) }));
            },
        };
    };
}

afterEach(() => {
    Object.assign(G.Process, saved.process);
    G.ApiResolver = saved.resolver;
    G.Module.findGlobalExportByName = saved.globalExport;
    G.send = saved.send;
    G.Interceptor.attach = saved.attach;
    N.installFallbackKeyHooks = saved.fallback;
    N.setExportScope = saved.scope;
    N.bindNativeHelpers = saved.bind;
    setPcapEnabled(false);
    setPlatform("linux");
});

// ---- one executor run --------------------------------------------------------------

interface TreeRun {
    events: string[];                    // "tier1-miss" / "fallback", in order
    scope: string[];                     // NSS.setExportScope modules of the install
    tierInputs: { [fn: string]: string | null } | null;   // what reached tiers 2/3
    logs: string[];
}

async function until(done: () => boolean): Promise<void> {
    for (let i = 0; i < 500 && !done(); i++) await new Promise((r) => setImmediate(r));
}

/**
 * Run `executor` on `c.hooked` in a freshly loaded process. With `spyFallback`, tiers 2/3
 * are replaced by a recorder; without it they run for real (they install nothing here).
 */
async function runTree(c: Case, executor: Executor, spyFallback = true): Promise<TreeRun> {
    loadProcess(c.os, c.exports);
    const run: TreeRun = { events: [], scope: [], tierInputs: null, logs: [] };
    G.send = (m: any) => {
        const line = m?.console ?? m?.console_dev;
        if (typeof line !== "string") return;
        run.logs.push(line);
        if (line.includes(`${c.sslModule}: NSS keylog writer not located`)) run.events.push("tier1-miss");
    };
    N.setExportScope = (mods: any[]) => {
        run.scope = mods.filter(Boolean).map((m) => m.name);
        saved.scope.call(NSS, mods);
    };
    if (spyFallback) {
        N.installFallbackKeyHooks = (fnAddrs: any) => {
            run.events.push("fallback");
            run.tierInputs = Object.fromEntries(TIER_INPUTS.map((fn) => [fn, fnAddrs[fn] ? String(fnAddrs[fn]) : null]));
            return true;
        };
    }
    executor(c.hooked, false);
    await until(() => run.events.includes("fallback") || run.logs.some(isNothingInstalledVerdict));
    return run;
}

/** The "no key tier installed" verdict line of either tree. */
function isNothingInstalledVerdict(line: string): boolean {
    return line.includes("NSS key extraction: no tier could be installed")    // legacy (nss_key_extraction.ts)
        || line.includes("custom keylog install settled: nothing installed");  // modern (core/loader.ts)
}

// ---- tests -------------------------------------------------------------------------

test("every legacy NSS hooker is a subclass of the shared (modern) NSS class", () => {
    for (const Hooker of [NSS_Android, NSS_Linux, NSS_MacOS, NSS_Windows]) {
        assert.ok(Hooker.prototype instanceof NSS, `${Hooker.name} does not extend tls/libs/nss.ts NSS`);
    }
});

for (const c of CASES) {
    test(`${c.label}: legacy and modern reach tiers 2/3 with identical addresses, after tier 1`, async () => {
        const legacy = await runTree(c, c.legacy);
        const modern = await runTree(c, c.modern);

        for (const [tree, run] of [["legacy", legacy], ["modern", modern]] as const) {
            assert.deepEqual(run.events, ["tier1-miss", "fallback"], `${tree}: tier order`);
            assert.equal(run.scope[0], c.sslModule, `${tree}: export scope starts at the SSL module`);
            assert.ok(run.scope.includes(c.hooked), `${tree}: export scope includes the hooked module`);
            assert.equal(run.tierInputs!["SSL_ImportFD"], `${c.sslModule}!SSL_ImportFD`, `${tree}: SSL_ImportFD`);
        }
        assert.deepEqual(legacy.scope, modern.scope);
        assert.deepEqual(legacy.tierInputs, modern.tierInputs);
        for (const fn of TIER_INPUTS) assert.notEqual(legacy.tierInputs![fn], null, `${fn} unresolved`);
    });

    test(`${c.label}: without SSL_ImportFD both trees settle "nothing installed" the same way`, async () => {
        const noImportFd: Exports = Object.fromEntries(Object.entries(c.exports)
            .map(([m, syms]) => [m, syms.filter((s) => s !== "SSL_ImportFD")]));
        const variant = { ...c, exports: noImportFd, sslModule: c.hooked };
        const legacy = await runTree(variant, c.legacy, false);
        const modern = await runTree(variant, c.modern, false);
        for (const [tree, run] of [["legacy", legacy], ["modern", modern]] as const) {
            assert.deepEqual(run.events, ["tier1-miss"], `${tree}: tier 1 tried first`);
            assert.ok(run.logs.some((l) => l.includes("NSS: SSL_ImportFD not resolved")), `${tree}: tier 2/3 refused`);
            assert.ok(run.logs.some(isNothingInstalledVerdict), `${tree}: verdict`);
        }
    });
}

/** The PR_Read / PR_Write addresses `executor` attaches to with -p (pcap_enabled). */
async function plaintextHookTargets(c: Case, executor: Executor): Promise<string[]> {
    const prIo = [`${c.hooked}!PR_Read`, `${c.hooked}!PR_Write`];
    const targets: string[] = [];
    loadProcess(c.os, c.exports);
    G.Interceptor.attach = (target: any) => { targets.push(String(target)); return { detach: () => {} }; };
    N.installFallbackKeyHooks = () => true;
    setPcapEnabled(true);
    executor(c.hooked, false);
    await until(() => prIo.every((t) => targets.includes(t)));   // modern resolves asynchronously
    return targets.filter((t) => prIo.includes(t)).sort();
}

// Every platform, Android included: the legacy NSS_Android hooker installs the plaintext
// hooks too (they were commented out until 2026-11-22), resolving PR_Read / PR_Write from
// the folded libnss3.so and the socket helpers from libc, like the modern definition.
for (const c of CASES) {
    test(`${c.label}: the legacy hooker installs the PR_Read / PR_Write plaintext hooks, like modern`, async () => {
        const expected = [`${c.hooked}!PR_Read`, `${c.hooked}!PR_Write`].sort();
        assert.deepEqual(await plaintextHookTargets(c, c.legacy), expected);
        assert.deepEqual(await plaintextHookTargets(c, c.modern), expected);
    });
}

test("Android (folded libnss3.so): the legacy plaintext hooks bind NSPR's socket helpers and libc's", async () => {
    const c = CASES.find((x) => x.label.startsWith("Android"))!;
    loadProcess(c.os, c.exports);
    G.Interceptor.attach = () => ({ detach: () => {} });
    N.installFallbackKeyHooks = () => true;
    setPcapEnabled(true);
    const hooker = new NSS_Android(c.hooked, "libc", false);
    const nspr = hooker.addresses[c.hooked];
    for (const fn of ["PR_Read", "PR_Write", "PR_GetPeerName", "PR_GetSockName", "PR_GetDescType",
                      "PR_FileDesc2NativeHandle", "PR_GetNameForIdentity"]) {
        assert.equal(String(nspr[fn]), `${c.hooked}!${fn}`, fn);
    }
    // readAddresses merges every library's symbols into the hooked module's map, which is
    // where getPortsAndAddressesFromNSS reads ntohs / ntohl.
    for (const fn of SOCKETS) assert.equal(String(nspr[fn]), `libc.so!${fn}`, fn);
});
