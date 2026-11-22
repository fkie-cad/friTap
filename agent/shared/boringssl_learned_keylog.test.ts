// Run: npm run test:agent
//
// The libchrome keylog pattern scan reuses the ssl_log_secret tier 4 (or an
// earlier pattern match) stored in the learned-offsets cache: a decodable cache
// hit hooks it directly, skips the scan and the 1 s symbol-fallback timer, and
// tier 4 never hooks the same function a second time. An undecodable entry is
// rejected and the scan runs; a pattern match is reported once it decodes.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
// Entry first: the hooker modules sit in an import cycle with the platform tables.
import "../fritap_agent.js";
import { Cronet_Android, cronet_execute } from "../legacy/tls/platforms/android/cronet_android.js";
import { installBoringSSLKeylogChain } from "./boringssl_hook_chain.js";
import {
    LearnedSslLogSecretDeps, hookLearnedSslLogSecret, hookLearnedSslLogSecretByName, reportPatternMatchedSslLogSecret,
} from "./boringssl_learned_keylog.js";
import {
    LEARNED_SSL_LOG_SECRET, locateSslLogSecretCached, runAnchorLocatorTier4,
} from "./boringssl_anchor_locator.js";
import { installLearnedModuleCache } from "./learned_module_cache.js";
import {
    _resetKeylogOutcomeReportsForTests, attachPatternEntryHook, attachSslLogSecretOnce, guardKeylogDumpKeys,
    isSslLogSecretHooked, keylogHookOwner, registerBoringSSLTier4, sslLogSecretHookTier, startTier4Once,
} from "./boringssl_keylog_outcome.js";
import { mappingAddressKey } from "./module_mapping.js";
import { setKeylogEnabled } from "./shared_structures.js";
import { attachSslLogSecretHook } from "./boringssl_symbol_hook.js";

const G = globalThis as any;

class FakePtr {
    constructor(readonly value: number) {}
    add(n: any): FakePtr { return new FakePtr(this.value + Number(n?.value ?? n)); }
    sub(other: any): FakePtr { return new FakePtr(this.value - Number(other?.value ?? other)); }
    and(n: any): FakePtr { return new FakePtr(this.value & Number(n?.value ?? n)); }
    equals(other: any): boolean { return Number(other?.value ?? other) === this.value; }
    isNull(): boolean { return this.value === 0; }
    toString(): string { return "0x" + this.value.toString(16); }
}

const MODULE = "libchrome.so";
const RVA = 0x1234;
const HASH = "aa".repeat(32);
const IDENTITY = { buildId: "c0ffee", size: 0x100000, arch: "arm64" };
const KEY = "c0ffee|1048576|arm64";
let nextBase = 0x7000_0000;

function fakeModule(): any {
    nextBase += 0x1000_0000;
    return { name: MODULE, base: new FakePtr(nextBase), size: IDENTITY.size };
}

/** Host cache holding ssl_log_secret at RVA (or nothing when `empty`); records reports. */
function installCache(empty = false): any[] {
    const reported: any[] = [];
    installLearnedModuleCache(empty ? {} : {
        [KEY]: { module: MODULE, functions: { [LEARNED_SSL_LOG_SECRET]: { rva: RVA, prologue_sha256: HASH } }, layout: {} },
    }, {
        identify: () => IDENTITY, hashPrologue: () => HASH,
        emit: (p) => { if (p.cache_hit !== true) reported.push(p); }, schedule: (flush) => flush(),
    });
    return reported;
}

interface Attach { at: number; module: string }

function deps(attached: Attach[], over: Partial<LearnedSslLogSecretDeps> = {}): LearnedSslLogSecretDeps {
    return {
        arch: () => "arm64",
        decodes: () => true,
        attach: (addr: any, _tier, _cb, moduleName) => { attached.push({ at: addr.value, module: moduleName }); return true; },
        ...over,
    };
}

const noDump = () => { };

beforeEach(() => {
    _resetKeylogOutcomeReportsForTests();
    setKeylogEnabled(true);
});

// ---- the helper -------------------------------------------------------------

test("a decodable cache hit hooks ssl_log_secret once and claims the module", () => {
    const mod = fakeModule();
    installCache();
    const attached: Attach[] = [];
    assert.equal(hookLearnedSslLogSecret(mod, noDump, deps(attached)), true);
    assert.deepEqual(attached, [{ at: mod.base.value + RVA, module: MODULE }]);
    assert.equal(keylogHookOwner(MODULE), "pattern");
});

test("an undecodable cache entry is rejected and the caller scans", () => {
    const mod = fakeModule();
    installCache();
    const attached: Attach[] = [];
    assert.equal(hookLearnedSslLogSecret(mod, noDump, deps(attached, { decodes: () => false })), false);
    assert.deepEqual(attached, []);
    assert.equal(keylogHookOwner(MODULE), undefined);
});

test("no cache entry, or a non-arm64 process, leaves the pattern path to run", () => {
    const attached: Attach[] = [];
    installCache(true);
    assert.equal(hookLearnedSslLogSecret(fakeModule(), noDump, deps(attached)), false);
    installCache();
    assert.equal(hookLearnedSslLogSecret(fakeModule(), noDump, deps(attached, { arch: () => "x64" })), false);
    assert.deepEqual(attached, []);
});

test("a pattern match is reported only when its prologue decodes", () => {
    const mod = fakeModule();
    const reported = installCache(true);
    const at = mod.base.add(0x5678);
    assert.equal(reportPatternMatchedSslLogSecret(mod, at as any, deps([], { decodes: () => false })), false);
    assert.deepEqual(reported, []);
    assert.equal(reportPatternMatchedSslLogSecret(mod, at as any, deps([])), true);
    assert.deepEqual(reported.map((p) => p.functions?.[LEARNED_SSL_LOG_SECRET]?.rva), [0x5678]);
    assert.equal(reportPatternMatchedSslLogSecret(mod, null, deps([])), false);
});

const USER_PATTERNS = JSON.stringify({ modules: { [MODULE]: { linux: { arm64: { "Dump-Keys": { primary: "AA BB CC DD" } } } } } });

test("by name: user Dump-Keys patterns for the module win over the cache", () => {
    const mod = fakeModule();
    installCache();
    const attached: Attach[] = [];
    const user = { json: USER_PATTERNS, fallbackModuleName: "libcronet.so" };
    const none = { json: undefined, fallbackModuleName: "libcronet.so" };
    // The user-pattern lookup is keyed by the process's platform/arch.
    withLoadedModule(mod, () => {
        assert.equal(hookLearnedSslLogSecretByName(MODULE, noDump, user, () => mod, deps(attached)), false);
        assert.deepEqual(attached, []);
        assert.equal(hookLearnedSslLogSecretByName(MODULE, noDump, none, () => mod, deps(attached)), true);
        assert.equal(hookLearnedSslLogSecretByName(MODULE, noDump, none, () => null, deps(attached)), false);
    });
    assert.deepEqual(attached, [{ at: mod.base.value + RVA, module: MODULE }]);
});

// ---- one hook per ssl_log_secret --------------------------------------------

/** Run `fn` with every address resolving to the mapping `name`@`base`. */
function withMappingAt(name: string, base: number, fn: () => void): void {
    const prev = G.Process.findModuleByAddress;
    G.Process.findModuleByAddress = () => ({ name, base: new FakePtr(base) });
    try { fn(); } finally { G.Process.findModuleByAddress = prev; }
}

test("mappingAddressKey: qualifies the address by its mapping, or an explicit one", () => {
    withMappingAt("liba.so", 0x1000, () => {
        assert.equal(mappingAddressKey(new FakePtr(0x1010) as any), "liba.so@0x1000#0x1010");
        assert.equal(mappingAddressKey(new FakePtr(0x1010) as any, "libb.so@0x2000"), "libb.so@0x2000#0x1010");
    });
});

test("attachSslLogSecretOnce: attaches once, marks only a successful attach", () => {
    let attaches = 0;
    const at = new FakePtr(0x1010) as any;
    withMappingAt("liba.so", 0x1000, () => {
        assert.equal(attachSslLogSecretOnce(at, "pattern", () => false), false);
        assert.equal(isSslLogSecretHooked(at), false);
        assert.equal(attachSslLogSecretOnce(at, "pattern", () => { attaches++; return true; }), true);
        assert.equal(attachSslLogSecretOnce(at, "pattern", () => { attaches++; return true; }), true);
        assert.equal(attaches, 1);
        assert.equal(isSslLogSecretHooked(at), true);
    });
});

test("attachSslLogSecretOnce: another library mapped later at the same address attaches again", () => {
    let attaches = 0;
    const at = new FakePtr(0x2020) as any;
    withMappingAt("libold.so", 0x2000, () => {
        assert.equal(attachSslLogSecretOnce(at, "pattern", () => { attaches++; return true; }), true);
    });
    withMappingAt("libnew.so", 0x2000, () => {
        assert.equal(isSslLogSecretHooked(at), false);
        assert.equal(attachSslLogSecretOnce(at, "pattern", () => { attaches++; return true; }), true);
    });
    assert.equal(attaches, 2);
});

test("the real ssl_log_secret attach marks the address: a second tier does not attach again", () => {
    const mod = fakeModule();
    installCache();
    const prev = { attach: G.Interceptor.attach, byAddr: G.Process.findModuleByAddress };
    let attaches = 0;
    G.Interceptor.attach = () => { attaches++; return { detach: () => { } }; };
    G.Process.findModuleByAddress = () => mod;
    try {
        assert.equal(hookLearnedSslLogSecret(mod, noDump, deps([], { attach: attachSslLogSecretHook })), true);
        assert.equal(isSslLogSecretHooked(mod.base.add(RVA) as any), true);
        assert.equal(attachSslLogSecretHook(mod.base.add(RVA) as any, "symbol", noDump, MODULE), true);
        assert.equal(attaches, 1);
    } finally {
        G.Interceptor.attach = prev.attach;
        G.Process.findModuleByAddress = prev.byAddr;
    }
});

// ---- tier 4 does not double-hook -------------------------------------------

test("tier 4 on an already-hooked ssl_log_secret installs nothing", async () => {
    const mod = fakeModule();
    installCache();
    // Seed tier 4's per-mapping lookup with the same cached address.
    await locateSslLogSecretCached(mod, MODULE, { decodes: () => true, scan: async () => ({ found: null, missIsReliable: false }) });
    const prev = { arch: G.Process.arch, find: G.Process.findModuleByName, byAddr: G.Process.findModuleByAddress, attach: G.Interceptor.attach };
    let attaches = 0;
    G.Process.arch = "arm64";
    G.Process.findModuleByName = () => mod;
    G.Process.findModuleByAddress = () => mod;
    G.Interceptor.attach = () => { attaches++; return { detach: () => { } }; };
    try {
        assert.equal(hookLearnedSslLogSecret(mod, noDump, deps([], { attach: attachSslLogSecretHook })), true);
        assert.equal(await runAnchorLocatorTier4(MODULE, noDump), true);
        assert.equal(attaches, 1, "only the learned hook");
    } finally {
        G.Process.arch = prev.arch;
        G.Process.findModuleByName = prev.find;
        G.Process.findModuleByAddress = prev.byAddr;
        G.Interceptor.attach = prev.attach;
    }
});

// ---- a deduplicated attach never mutes the live hook -------------------------

/** Run `body` with tier 4 able to locate `mod`'s cached ssl_log_secret; collects the live interceptors. */
async function withTier4Ready(mod: any, body: (hooks: any[]) => Promise<void>): Promise<void> {
    await locateSslLogSecretCached(mod, MODULE, { decodes: () => true, scan: async () => ({ found: null, missIsReliable: false }) });
    registerBoringSSLTier4(runAnchorLocatorTier4);
    const prev = { arch: G.Process.arch, find: G.Process.findModuleByName, byAddr: G.Process.findModuleByAddress, attach: G.Interceptor.attach };
    const hooks: any[] = [];
    G.Process.arch = "arm64";
    G.Process.findModuleByName = () => mod;
    G.Process.findModuleByAddress = () => mod;
    G.Interceptor.attach = (_at: any, cbs: any) => { hooks.push(cbs); return { detach: () => { } }; };
    try {
        await body(hooks);
    } finally {
        G.Process.arch = prev.arch;
        G.Process.findModuleByName = prev.find;
        G.Process.findModuleByAddress = prev.byAddr;
        G.Interceptor.attach = prev.attach;
    }
}

/** Fire every live interceptor as one ssl_log_secret(ssl, label, data, len) call, under any ABI. */
function fireSecret(hooks: any[]): void {
    const arg = (v: number): any => Object.assign(new FakePtr(v), { toUInt32: () => v });
    const [ssl, label, data, len] = [arg(0x10), arg(0x20), arg(0x30), arg(32)];
    const context = { x0: ssl, x1: label, x2: data, x3: len, rdi: ssl, rsi: label, rdx: data, rcx: len };
    for (const h of hooks) h.onEnter.call({ context }, [ssl, label, data, len]);
}

test("tier 4 finding the pattern tier's unclaimed hook leaves the module to the pattern tier", async () => {
    const mod = fakeModule();
    installCache();
    const emitted: string[] = [];
    await withTier4Ready(mod, async (hooks) => {
        const at = mod.base.add(RVA) as any;
        const patternDumpKeys = guardKeylogDumpKeys(MODULE, "pattern", () => { emitted.push("pattern"); });
        assert.equal(attachPatternEntryHook(at, (args: any[]) => patternDumpKeys(args[1], args[0], args[2], 32), true), true);
        assert.equal(keylogHookOwner(MODULE), undefined, "no handshake yet");
        assert.equal(await startTier4Once(MODULE, () => { emitted.push("anchor"); }), true);
        assert.equal(hooks.length, 1, "tier 4 attached nothing");
        assert.equal(keylogHookOwner(MODULE), "pattern");
        fireSecret(hooks);
    });
    assert.deepEqual(emitted, ["pattern"]);
});

test("a pattern match after tier 4 installed leaves the module to tier 4", async () => {
    const mod = fakeModule();
    installCache();
    const { memoizedCtxKeylogOffsets } = await import("./boringssl_anchor_locator.js");
    memoizedCtxKeylogOffsets(mod, mod.base.add(RVA) as any, () => ({ ctxOff: 0x68, cbOff: 0x110 }));
    const emitted: string[] = [];
    await withTier4Ready(mod, async (hooks) => {
        const at = mod.base.add(RVA) as any;
        assert.equal(await startTier4Once(MODULE, () => { emitted.push("anchor"); }), true);
        assert.equal(sslLogSecretHookTier(at), "anchor");
        const patternDumpKeys = guardKeylogDumpKeys(MODULE, "pattern", () => { emitted.push("pattern"); });
        assert.equal(attachPatternEntryHook(at, () => { }, true), true);
        assert.equal(hooks.length, 1, "the pattern match attached nothing");
        assert.equal(keylogHookOwner(MODULE), "anchor");
        patternDumpKeys(new FakePtr(0x20) as any, new FakePtr(0x10) as any, new FakePtr(0x30) as any, 32);
    });
    assert.deepEqual(emitted, [], "the pattern guard stays silent; tier 4's ctx-write emits");
});

test("a learned hit on the symbol tier's hook claims the module for the symbol tier", async () => {
    const mod = fakeModule();
    installCache();
    const emitted: string[] = [];
    await withTier4Ready(mod, async (hooks) => {
        const at = mod.base.add(RVA) as any;
        assert.equal(attachSslLogSecretHook(at, "symbol", guardKeylogDumpKeys(MODULE, "symbol", () => { emitted.push("symbol"); }), MODULE), true);
        assert.equal(hookLearnedSslLogSecret(mod, () => { emitted.push("learned"); }, deps([], { attach: attachSslLogSecretHook })), true);
        assert.equal(hooks.length, 1, "learned tier attached nothing");
        assert.equal(keylogHookOwner(MODULE), "symbol");
        fireSecret(hooks);
    });
    assert.deepEqual(emitted, ["symbol"]);
});

test("a symbol hook after a learned hit stays silent; the learned hook emits", async () => {
    const mod = fakeModule();
    installCache();
    const emitted: string[] = [];
    await withTier4Ready(mod, async (hooks) => {
        const at = mod.base.add(RVA) as any;
        assert.equal(hookLearnedSslLogSecret(mod, () => { emitted.push("learned"); }, deps([], { attach: attachSslLogSecretHook })), true);
        assert.equal(attachSslLogSecretHook(at, "symbol", guardKeylogDumpKeys(MODULE, "symbol", () => { emitted.push("symbol"); }), MODULE), true);
        assert.equal(hooks.length, 1);
        assert.equal(keylogHookOwner(MODULE), "pattern");
        fireSecret(hooks);
    });
    assert.deepEqual(emitted, ["learned"]);
});

// ---- callers: no scan, no fallback timer ------------------------------------

/** Run `body` on an arm64 process where `mod` is loaded; counts scans, attaches and timers. */
function withLoadedModule(mod: any, body: () => void): { scans: number; attaches: number; timers: number[] } {
    const seen = { scans: 0, attaches: 0, timers: [] as number[] };
    const prev = {
        arch: G.Process.arch, find: G.Process.findModuleByName, scan: G.Memory.scan,
        attach: G.Interceptor.attach, setTimeout: G.setTimeout,
    };
    G.Process.arch = "arm64";
    G.Process.findModuleByName = (name: string) => (name === MODULE ? mod : null);
    G.Memory.scan = () => { seen.scans++; };
    G.Interceptor.attach = () => { seen.attaches++; return { detach: () => { } }; };
    G.setTimeout = (_fn: () => void, ms: number) => { seen.timers.push(ms); return 0; };
    try {
        body();
    } finally {
        G.Process.arch = prev.arch;
        G.Process.findModuleByName = prev.find;
        G.Memory.scan = prev.scan;
        G.Interceptor.attach = prev.attach;
        G.setTimeout = prev.setTimeout;
    }
    return seen;
}

/** Plaintext hooks are out of scope here; only the keylog wiring is exercised. */
function stubPlaintextHooks(): () => void {
    const proto = Cronet_Android.prototype as any;
    const saved = { read: proto.install_plaintext_read_hook, write: proto.install_plaintext_write_hook };
    proto.install_plaintext_read_hook = () => { };
    proto.install_plaintext_write_hook = () => { };
    return () => { proto.install_plaintext_read_hook = saved.read; proto.install_plaintext_write_hook = saved.write; };
}

test("legacy Cronet: a learned hit skips the pattern scan and the 1 s symbol fallback", async () => {
    const mod = fakeModule();
    installCache();
    // Pre-validate the entry so the real decode (which cannot read fake code) is not consulted.
    const { memoizedCtxKeylogOffsets } = await import("./boringssl_anchor_locator.js");
    memoizedCtxKeylogOffsets(mod, mod.base.add(RVA) as any, () => ({ ctxOff: 0x68, cbOff: 0x110 }));
    const restore = stubPlaintextHooks();
    try {
        const seen = withLoadedModule(mod, () => cronet_execute(MODULE, false));
        assert.equal(seen.scans, 0, "no pattern scan");
        assert.deepEqual(seen.timers, [], "no deferred symbol fallback / tier 4");
        assert.equal(seen.attaches, 1, "ssl_log_secret hooked once");
        assert.equal(keylogHookOwner(MODULE), "pattern");
    } finally {
        restore();
    }
});

test("legacy Cronet: an undecodable entry falls back to the pattern scan", () => {
    const mod = fakeModule();  // fresh mapping: no memoized decode, fake code never decodes
    installCache();
    const restore = stubPlaintextHooks();
    try {
        const seen = withLoadedModule(mod, () => cronet_execute(MODULE, false));
        assert.ok(seen.scans >= 1, "pattern scan started");
        assert.deepEqual(seen.timers.filter((ms) => ms === 1000), [1000], "symbol fallback scheduled");
        assert.equal(keylogHookOwner(MODULE), undefined);
    } finally {
        restore();
    }
});

test("modern chain: a learned hit returns before tier 3 scans", async () => {
    const mod = fakeModule();
    installCache();
    const { memoizedCtxKeylogOffsets } = await import("./boringssl_anchor_locator.js");
    memoizedCtxKeylogOffsets(mod, mod.base.add(RVA) as any, () => ({ ctxOff: 0x68, cbOff: 0x110 }));
    const def: any = { keylog: { kind: "none" }, keylogPriority: "symbol-first", libraryType: "boringssl" };
    let outcome = "";
    const seen = withLoadedModule(mod, () => { outcome = installBoringSSLKeylogChain(def, {}, MODULE, {} as any, false); });
    assert.equal(outcome, "pattern");
    assert.equal(seen.scans, 0);
    assert.equal(seen.attaches, 1);
});

// ---- user-supplied patterns take precedence ---------------------------------

test("modern chain: user patterns for the module bypass the learned cache and scan", async () => {
    const mod = fakeModule();
    installCache();
    const { memoizedCtxKeylogOffsets } = await import("./boringssl_anchor_locator.js");
    memoizedCtxKeylogOffsets(mod, mod.base.add(RVA) as any, () => ({ ctxOff: 0x68, cbOff: 0x110 }));
    const def: any = { keylog: { kind: "none" }, keylogPriority: "symbol-first", libraryType: "boringssl" };
    let outcome = "";
    const seen = withLoadedModule(mod, () => { outcome = installBoringSSLKeylogChain(def, {}, MODULE, {} as any, false, USER_PATTERNS); });
    assert.equal(outcome, "pattern");
    assert.ok(seen.scans >= 1, "user pattern scanned");
    assert.equal(keylogHookOwner(MODULE), undefined, "learned hook not installed");
});

test("legacy Cronet: user patterns for the module bypass the learned cache", async () => {
    const mod = fakeModule();
    installCache();
    const { memoizedCtxKeylogOffsets } = await import("./boringssl_anchor_locator.js");
    memoizedCtxKeylogOffsets(mod, mod.base.add(RVA) as any, () => ({ ctxOff: 0x68, cbOff: 0x110 }));
    const proto = Cronet_Android.prototype as any;
    const savedUserPatterns = proto.user_dump_keys_patterns;
    proto.user_dump_keys_patterns = () => ({ json: USER_PATTERNS, fallbackModuleName: "libcronet.so" });
    // hook_DumpKeys would parse the (absent) JSON; only the cache bypass is under test.
    const savedPatternHook = proto.install_key_extraction_pattern_hook;
    let patternHookRuns = 0;
    proto.install_key_extraction_pattern_hook = () => { patternHookRuns++; return null; };
    const restore = stubPlaintextHooks();
    try {
        const seen = withLoadedModule(mod, () => cronet_execute(MODULE, false));
        assert.equal(patternHookRuns, 1, "pattern path taken");
        assert.equal(seen.attaches, 0, "learned hook not installed");
        assert.equal(keylogHookOwner(MODULE), undefined);
    } finally {
        restore();
        proto.user_dump_keys_patterns = savedUserPatterns;
        proto.install_key_extraction_pattern_hook = savedPatternHook;
    }
});
