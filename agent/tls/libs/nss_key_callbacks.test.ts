// Unit tests for the NSS key-extraction tiers 2/3 bookkeeping in agent/tls/libs/nss.ts:
// version gate of the struct table, secret-callback call-through, re-registration over
// the app's callback, PR_Close bookkeeping, detach restore, handshake-callback dedupe.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { stubRanges } from "../../shared/frida-test-stubs.js";
// Load the agent graph first: importing nss.ts directly enters the
// nss -> fritap_agent -> legacy nss_* (extends NSS) import cycle from the wrong end.
import "../../fritap_agent.js";

import { NSS, copyPointer } from "./nss.js";
import { installLearnedModuleCache } from "../../shared/learned_module_cache.js";
import { LEARNED_NSS_CLIENT_RANDOM_OFF } from "../../shared/nss_client_random_learner.js";

const G = globalThis as any;
const N: any = NSS;

/** Minimal pointer with identity by name. */
function p(name: string): any {
    const self: any = {
        name,
        and: () => self,   // untag() in safe_memory
        add: () => self,   // range end arithmetic
        isNull: () => name === "NULL",
        toString: () => name,
        equals: (o: any) => o !== null && o !== undefined && String(o) === name,
    };
    return self;
}
const NULLP = p("NULL");

let secretCbCalls: any[][] = [];
let attached: Array<{ at: string; cbs: any }> = [];

beforeEach(() => {
    G.NULL = NULLP;
    G.Interceptor = { attach: (at: any, cbs: any) => { attached.push({ at: String(at), cbs }); return { detach() {} }; } };
    G.NativeFunction = function (target: any) { return (...a: any[]) => { secretCbCalls.push([String(target), ...a]); }; };
    secretCbCalls = [];
    attached = [];
    stubRanges(null);
    N.ownedSecretCallbackFds.clear();
    N.ownedHandshakeCallbackFds.clear();
    N.originalSecretCallbacks.clear();
    N.ownedSocketByFd.clear();
    N.hookedAppHandshakeCallbacks.clear();
    N.secret_callback = p("friTapSecretCb");
    N.keylog_callback = p("friTapHandshakeCb");
    // fd "fdX" -> sslSocket "ssX"
    N.findSslSocketUncached = (fd: any) => p(String(fd).replace(/^fd/, "ss"));
    N.SSL_SecretCallback_fn = (fd: any, cb: any, arg: any) => { secretCbCalls.push(["SSL_SecretCallback", String(fd), String(cb), String(arg)]); return 0; };
    N.isSameLiveSocket = () => true;
    N.echDualEmissions = 0;
});

function withVersion(version: number, fn: () => void): void {
    N.cachedVersion = version;
    N.tableDisabledLogged = true;
    try { fn(); } finally { N.cachedVersion = null; }
}

test("struct table reads are allowed only below NSS 3.115", () => {
    withVersion(3114, () => assert.equal(NSS.structReadsAllowed(), true));
    withVersion(3115, () => assert.equal(NSS.structReadsAllowed(), false));
    withVersion(3132, () => assert.equal(NSS.structReadsAllowed(), false));
});

test("register_secret_callback uses the API and tracks the socket; a stale original is dropped", () => {
    NSS.originalSecretCallbacks.set("ssA", { cb: p("stale"), arg: p("x"), fn: (() => {}) as any });
    assert.equal(NSS.register_secret_callback(p("fdA")), true);
    assert.deepEqual(secretCbCalls, [["SSL_SecretCallback", "fdA", "friTapSecretCb", "NULL"]]);
    assert.equal(NSS.ownedSecretCallbackFds.has("ssA"), true);
    assert.equal(NSS.originalSecretCallbacks.has("ssA"), false);
});

test("an app registration on an owned socket becomes the call-through target and ours is re-registered", () => {
    NSS.register_secret_callback(p("fdA"));
    secretCbCalls = [];
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    assert.equal(String(NSS.originalSecretCallbacks.get("ssA")!.cb), "neqoCb");
    assert.deepEqual(secretCbCalls, [["SSL_SecretCallback", "fdA", "friTapSecretCb", "NULL"]]);
});

test("an app registration on a socket friTap does not own is left alone", () => {
    NSS.adoptAppSecretCallback(p("fdB"), p("appCb"), p("appArg"));
    assert.equal(NSS.originalSecretCallbacks.size, 0);
    assert.deepEqual(secretCbCalls, []);
});

test("secret callback calls through to the original even for epochs it does not log", () => {
    NSS.register_secret_callback(p("fdA"));
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    secretCbCalls = [];
    N.get_SSL_Socket = () => p("ssA");
    NSS.onSecretCallback(p("layerA"), 4, 1, p("secret")); // key update: no keylog label
    assert.deepEqual(secretCbCalls.map((c) => c.map(String)), [["neqoCb", "layerA", "4", "1", "secret", "neqoArg"]]);
});

test("secret callback still calls through when logging throws", () => {
    NSS.register_secret_callback(p("fdA"));
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    secretCbCalls = [];
    N.get_SSL_Socket = () => p("ssA");
    const logSecret = N.logSecret;
    N.logSecret = () => { throw new Error("boom"); };
    try {
        NSS.onSecretCallback(p("layerA"), 3, 2, p("secret"));
    } finally {
        N.logSecret = logSecret;
    }
    assert.equal(secretCbCalls.length, 1);
    assert.equal(String(secretCbCalls[0][0]), "neqoCb");
});

test("PR_Close of an owned socket clears all its entries", () => {
    NSS.register_secret_callback(p("fdA"));
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    N.installCloseHook(p("PR_Close"));
    const close = attached.find((a) => a.at === "PR_Close")!.cbs;
    close.onEnter([p("fdA")]);
    assert.equal(NSS.ownedSecretCallbackFds.size, 0);
    assert.equal(NSS.originalSecretCallbacks.size, 0);
});

test("detach restores the app's callback, or NULL where the app had none", () => {
    NSS.register_secret_callback(p("fdA"));
    NSS.register_secret_callback(p("fdB"));
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    secretCbCalls = [];
    NSS.restoreAppCallbacks();
    assert.deepEqual(secretCbCalls.sort(), [
        ["SSL_SecretCallback", "fdA", "neqoCb", "neqoArg"],
        ["SSL_SecretCallback", "fdB", "NULL", "NULL"],
    ]);
    assert.equal(NSS.ownedSecretCallbackFds.size + NSS.originalSecretCallbacks.size, 0);
});

test("detach restore reports owned / toApp / toNull / stale / failed and handshake clears", () => {
    for (const fd of ["fdA", "fdB", "fdC", "fdD", "fdE"]) NSS.register_secret_callback(p(fd));
    NSS.adoptAppSecretCallback(p("fdA"), p("neqoCb"), p("neqoArg"));
    N.ownedHandshakeCallbackFds.set("ssA", p("fdA"));
    N.ownedHandshakeCallbackFds.set("ssC", p("fdC"));
    N.ownedHandshakeCallbackFds.set("ssE", p("fdE"));
    const hsCalls: string[] = [];
    N.get_SSL_Callback = (fd: any) => {
        if (String(fd) === "fdE") throw new Error("hs boom");
        hsCalls.push(String(fd));
        return 0;
    };
    N.isSameLiveSocket = (_fd: any, key: string) => key !== "ssC";            // C is stale
    N.SSL_SecretCallback_fn = (fd: any) => {
        if (String(fd) === "fdD") return -1;                                     // D: negative rv
        if (String(fd) === "fdE") throw new Error("boom");                       // E: threw
        return 0;
    };
    try {
        const summary = NSS.restoreAppCallbacks();
        assert.deepEqual(summary, { owned: 5, toApp: 1, toNull: 1, stale: 1, failed: 2, hsOwned: 3, hsCleared: 1, echDual: 0 });
        assert.deepEqual(hsCalls, ["fdA"]);
        assert.equal(NSS.ownedSecretCallbackFds.size + NSS.ownedHandshakeCallbackFds.size, 0);
    } finally {
        N.get_SSL_Callback = undefined;
    }
});

test("detach restore with nothing owned reports all zeros", () => {
    assert.deepEqual(NSS.restoreAppCallbacks(), { owned: 0, toApp: 0, toNull: 0, stale: 0, failed: 0, hsOwned: 0, hsCleared: 0, echDual: 0 });
});

test("app handshake callbacks: NULL skipped, each address attached once, non-executable not attached", () => {
    NSS.hookAppHandshakeCallback(NULLP);
    NSS.hookAppHandshakeCallback(p("appHs"));
    NSS.hookAppHandshakeCallback(p("appHs"));
    assert.deepEqual(attached.map((a) => a.at), ["appHs"]);

    stubRanges(["noExec"]);
    NSS.hookAppHandshakeCallback(p("noExec"));
    NSS.hookAppHandshakeCallback(p("noExec"));
    assert.deepEqual(attached.map((a) => a.at), ["appHs"]);
});

// Regression (Phase 5c device run): the SSL_ImportFD onLeave stored Frida's InvocationReturnValue
// itself; it is only valid inside the callback, so at detach every tracked fd read as unmapped and
// the app's callbacks were never restored. Hook values must be copied before they are kept.
test("copyPointer takes the value through add(0), which in Frida always allocates a new NativePointer", () => {
    const calls: number[] = [];
    const fresh = ptr("0x7a48cb4230");
    const hookValue: any = { add: (n: number) => { calls.push(n); return fresh; } };
    assert.equal(copyPointer(hookValue), fresh);
    assert.deepEqual(calls, [0]);
});

// ---- tier 2 client_random source: learner / learned cache --------------------------------

/** 32-byte blocks of fake target memory by address; everything else reads as zero. */
let memory = new Map<bigint, string>();
function byteAt(a: bigint): number {
    for (const [base, hex] of memory) {
        if (a >= base && a < base + 32n) return parseInt(hex.substr(Number(a - base) * 2, 2), 16);
    }
    return 0;
}
/** Pointer with real address arithmetic over `memory` (the learner computes offsets). */
function hp(v: bigint): any {
    const self: any = {
        v,
        add: (n: any) => hp(v + BigInt(typeof n === "object" ? n.v : n)),
        and: () => self,
        isNull: () => v === 0n,
        compare: (o: any) => (v < o.v ? -1 : v > o.v ? 1 : 0),
        toString: () => "0x" + v.toString(16),
        equals: (o: any) => String(o) === self.toString(),
        readByteArray: (n: number) => new Uint8Array(Array.from({ length: n }, (_x, i) => byteAt(v + BigInt(i)))).buffer,
        readU8: () => byteAt(v),
    };
    return self;
}
const rnd = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

const TIER2_STATICS = ["resolveExperimentalAPI", "detectVersionOffsets", "findSslSocketUncached", "get_SSL_Socket",
    "get_Secret_As_HexString", "get_Keylog_Dump"];

/** Run `fn` with tier 2 installable on NSS 3.132 (no table) and the hooks' inputs stubbed. */
function withTier2(fn: (ctx: { keylogs: string[]; detached: string[] }) => void): void {
    const saved = TIER2_STATICS.map((name) => N[name]);
    const savedFindModule = G.Process.findModuleByAddress;
    const ctx = { keylogs: [] as string[], detached: [] as string[] };
    memory = new Map();
    G.Interceptor = {
        attach: (at: any, cbs: any) => {
            attached.push({ at: String(at), cbs });
            return { detach() { ctx.detached.push(String(at)); } };
        },
    };
    N.fallbackInstalledFor.clear();
    N.clientRandomLearner = null;
    N.randomObserverHook = null;
    N.randomTrackedSockets = null;
    N.echRecorder = null;
    N.echDualEmissions = 0;
    N.echDualLinesSent = new N.echDualLinesSent.constructor(4096);
    N.learnedClientRandomOffset = null;
    N.clientRandomLearnerDisagreed = false;
    N.resolveExperimentalAPI = () => { N.SSL_SecretCallback_ptr = p("SSL_SecretCallback"); return true; };
    N.detectVersionOffsets = () => {};
    // fd "fd:0x..." -> sslSocket 0x...; the SSL layer passed to the secret callback is the sslSocket itself here.
    N.findSslSocketUncached = (fd: any) => hp(BigInt(String(fd).replace(/^fd:/, "")));
    N.get_SSL_Socket = (layer: any) => layer;
    N.get_Secret_As_HexString = () => "ee".repeat(32);
    N.get_Keylog_Dump = (label: string, cr: string) => { ctx.keylogs.push(`${label} ${cr}`); return `${label} ${cr}`; };
    try {
        withVersion(3132, () => fn(ctx));
    } finally {
        TIER2_STATICS.forEach((name, i) => { N[name] = saved[i]; });
        G.Process.findModuleByAddress = savedFindModule;
        N.clientRandomLearner = null;
        N.randomObserverHook = null;
    N.randomTrackedSockets = null;
        N.echRecorder = null;
        N.learnedClientRandomOffset = null;
        N.clientRandomLearnerDisagreed = false;
        N.fallbackInstalledFor.clear();
        installLearnedModuleCache({});
    }
}

const TIER2_ADDRS = () => ({
    SSL_ImportFD: p("SSL_ImportFD"), PR_Close: p("PR_Close"), PK11_GenerateRandom: p("PK11_GenerateRandom"),
});
const hook = (at: string) => attached.find((a) => a.at === at)!.cbs;

/** SSL_ImportFD returns the socket whose sslSocket is `ss`. */
function importSocket(ss: bigint): void {
    hook("SSL_ImportFD").onLeave({ isNull: () => false, add: () => p("fd:0x" + ss.toString(16)) });
}

/** PK11_GenerateRandom(data, 32) fills `data` with `hex` and returns SECSuccess. */
function generate(data: bigint, hex: string): void {
    const cbs = hook("PK11_GenerateRandom");
    const self: any = {};
    cbs.onEnter.call(self, [hp(data), { toInt32: () => 32 }]);
    memory.set(data, hex);
    cbs.onLeave.call(self, { toInt32: () => 0 });
}

/** One CLIENT_HANDSHAKE_TRAFFIC_SECRET callback on `ss`. */
function secretCallback(ss: bigint): void {
    NSS.onSecretCallback(hp(ss), 2, 2, p("secret"));
}

test("tier 2 installs with the learner when no client_random offset is known (NSS >= 3.115)", () => {
    withTier2(() => {
        assert.equal(NSS.installFallbackKeyHooks(TIER2_ADDRS()), true);
        const at = attached.map((a) => a.at);
        assert.ok(at.includes("PK11_GenerateRandom"), at.join(","));
        assert.ok(at.includes("SSL_ImportFD"));
        assert.notEqual(N.clientRandomLearner, null);
    });
});

test("tier 2 without the learner's export and without any offset stays skipped", () => {
    withTier2(() => {
        const addrs: any = TIER2_ADDRS();
        delete addrs.PK11_GenerateRandom;
        assert.equal(NSS.installFallbackKeyHooks(addrs), false);
        assert.equal(N.clientRandomLearner, null);
    });
});

test("tier 2 emits only for sockets the learner validated, with the bytes read live", () => {
    withTier2((ctx) => {
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        importSocket(0x1000000n);                                  // A: validated
        generate(0x1000650n, rnd(1));
        importSocket(0x2000000n);                                  // B: random attributed, then overwritten
        generate(0x2000650n, rnd(2));
        memory.set(0x2000650n, rnd(9));
        secretCallback(0x1000000n);
        secretCallback(0x2000000n);
        secretCallback(0x3000000n);                                // C: existed before attach
        assert.deepEqual(ctx.keylogs, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(1)]);
        memory.set(0x1000650n, rnd(3));                            // ECH: inner copied over client_random
        secretCallback(0x1000000n);
        assert.equal(ctx.keylogs[1], "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(3));
    });
});

test("3 agreeing sockets: offset accepted, reported to the learned cache, observer stays on for ECH", () => {
    withTier2((ctx) => {
        const reports: any[] = [];
        const mod = { name: "libnss3.so", base: hp(0x7000000000n), size: 0x400000 };
        G.Process.findModuleByAddress = () => mod;
        installLearnedModuleCache({}, {
            identify: () => ({ buildId: "b1", size: mod.size, arch: "arm64" }),
            emit: (payload: any) => reports.push(payload), schedule: (flush: () => void) => flush(),
        });
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        for (const ss of [0x1000000n, 0x2000000n, 0x3000000n]) {
            importSocket(ss);
            generate(ss + 0x650n, rnd(Number(ss >> 24n)));
            secretCallback(ss);
        }
        assert.equal(N.learnedClientRandomOffset, 0x650);
        // Learning is done, but tier 2 keeps the read-only hook to record ECH randoms.
        assert.deepEqual(ctx.detached, []);
        assert.notEqual(N.echRecorder, null);
        assert.deepEqual(reports.map((r) => r.layout), [{ [LEARNED_NSS_CLIENT_RANDOM_OFF]: 0x650 }]);
        memory.set(0x9000650n, rnd(7));                            // pre-attach socket, now readable
        secretCallback(0x9000000n);
        assert.equal(ctx.keylogs.length, 4);
        assert.equal(ctx.keylogs[3], "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(7));
    });
});

test("a cached offset is used directly: no learner (ECH recorder only), pre-attach sockets emit", () => {
    withTier2((ctx) => {
        const mod = { name: "libnss3.so", base: hp(0x7000000000n), size: 0x400000 };
        G.Process.findModuleByAddress = () => mod;
        installLearnedModuleCache({ "b1|4194304|arm64": { module: "libnss3.so", layout: { [LEARNED_NSS_CLIENT_RANDOM_OFF]: 0x650 } } },
            { identify: () => ({ buildId: "b1", size: mod.size, arch: "arm64" }), emit: () => {}, schedule: (f: () => void) => f() });
        assert.equal(NSS.installFallbackKeyHooks(TIER2_ADDRS()), true);
        assert.equal(attached.some((a) => a.at === "PK11_GenerateRandom"), true); // the ECH recorder's hook
        assert.equal(N.clientRandomLearner, null);
        assert.notEqual(N.echRecorder, null);
        memory.set(0x5000650n, rnd(5));
        secretCallback(0x5000000n);
        assert.deepEqual(ctx.keylogs, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(5)]);
    });
});

// ---- tier 2 ECH: inner + outer client_random -------------------------------------------

/** A socket that offered ECH: outer random at +0x650, inner random at +0x670. */
function echHandshake(ss: bigint, outer: number, inner: number): void {
    importSocket(ss);
    generate(ss + 0x650n, rnd(outer));
    generate(ss + 0x670n, rnd(inner));
}

/** Learned-cache stub with +0x650 cached for the libnss3 build. */
function withCachedOffset(): void {
    const mod = { name: "libnss3.so", base: hp(0x7000000000n), size: 0x400000 };
    G.Process.findModuleByAddress = () => mod;
    installLearnedModuleCache({ "b1|4194304|arm64": { module: "libnss3.so", layout: { [LEARNED_NSS_CLIENT_RANDOM_OFF]: 0x650 } } },
        { identify: () => ({ buildId: "b1", size: mod.size, arch: "arm64" }), emit: () => {}, schedule: (f: () => void) => f() });
}

test("ECH accepted with a cached offset: every secret is emitted for the inner and the outer random", () => {
    withTier2((ctx) => {
        withCachedOffset();
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        echHandshake(0x1000000n, 1, 2);
        memory.set(0x1000650n, rnd(2));                            // NSS copies inner over client_random
        secretCallback(0x1000000n);
        NSS.onSecretCallback(hp(0x1000000n), 3, 1, p("secret"));
        assert.deepEqual(ctx.keylogs, [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(2), "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(1),
            "SERVER_TRAFFIC_SECRET_0 " + rnd(2), "SERVER_TRAFFIC_SECRET_0 " + rnd(1),
        ]);
        assert.equal(N.echDualEmissions, 2);
        assert.equal(NSS.restoreAppCallbacks().echDual, 2);
    });
});

test("non-ECH and ECH-rejected sockets keep one line each", () => {
    withTier2((ctx) => {
        withCachedOffset();
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        importSocket(0x1000000n);                                  // no ECH
        generate(0x1000650n, rnd(1));
        echHandshake(0x2000000n, 3, 4);                            // ECH offered, rejected: outer stays
        secretCallback(0x1000000n);
        secretCallback(0x2000000n);
        assert.deepEqual(ctx.keylogs, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(1), "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(3)]);
        assert.equal(N.echDualEmissions, 0);
    });
});

test("ECH-dual lines are deduplicated when a callback repeats", () => {
    withTier2(() => {
        withCachedOffset();
        const sent: string[] = [];
        N.get_Keylog_Dump = (label: string, cr: string) => `${label} ${cr}`;
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        echHandshake(0x1000000n, 1, 2);
        memory.set(0x1000650n, rnd(2));
        const dedupe = N.echDualLinesSent;
        const realAdd = dedupe.add.bind(dedupe);
        dedupe.add = (line: string) => { sent.push(line); realAdd(line); }; // add() runs only for lines that are sent
        secretCallback(0x1000000n);
        secretCallback(0x1000000n);
        assert.deepEqual(sent, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(2), "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(1)]);
    });
});

test("learner path: learning and ECH recording share one hook; the ECH socket emits both randoms", () => {
    withTier2((ctx) => {
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        assert.equal(attached.filter((a) => a.at === "PK11_GenerateRandom").length, 1);
        echHandshake(0x1000000n, 1, 2);                            // learning phase, ECH accepted
        memory.set(0x1000650n, rnd(2));
        secretCallback(0x1000000n);
        assert.deepEqual(ctx.keylogs, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(2), "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(1)]);
        for (const ss of [0x2000000n, 0x3000000n]) {               // quorum reached
            importSocket(ss);
            generate(ss + 0x650n, rnd(Number(ss >> 24n) + 4));
            secretCallback(ss);
        }
        assert.equal(N.learnedClientRandomOffset, 0x650);
        echHandshake(0x4000000n, 8, 9);                            // after acceptance: still recorded
        memory.set(0x4000650n, rnd(9));
        secretCallback(0x4000000n);
        assert.deepEqual(ctx.keylogs.slice(-2), ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(9), "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(8)]);
        assert.equal(N.echDualEmissions, 2);
    });
});

test("a repeated ECH callback counts one dual emission (only lines actually sent count)", () => {
    withTier2(() => {
        withCachedOffset();
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        echHandshake(0x1000000n, 1, 2);
        memory.set(0x1000650n, rnd(2));
        secretCallback(0x1000000n);
        secretCallback(0x1000000n);                                // both lines deduplicated
        assert.equal(N.echDualEmissions, 1);
    });
});

const TIER2_ADDRS_B = () => ({
    SSL_ImportFD: p("SSL_ImportFD_B"), PR_Close: p("PR_Close_B"), PK11_GenerateRandom: p("PK11_GenerateRandom_B"),
});

test("a second NSS copy shares the live observer and its tracked-socket store", () => {
    withTier2(() => {
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        const store = N.randomTrackedSockets;
        const learner = N.clientRandomLearner;
        NSS.installFallbackKeyHooks(TIER2_ADDRS_B());
        assert.equal(attached.some((a) => a.at === "PK11_GenerateRandom_B"), false);
        assert.equal(N.randomTrackedSockets, store);
        assert.equal(N.clientRandomLearner, learner);
    });
});

test("after a learner disagreement a second NSS copy never starts learning again (fail closed)", () => {
    withTier2((ctx) => {
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        importSocket(0x1000000n);
        generate(0x1000650n, rnd(1));
        secretCallback(0x1000000n);
        importSocket(0x2000000n);
        generate(0x2000660n, rnd(2));                              // a different offset
        secretCallback(0x2000000n);
        assert.equal(N.clientRandomLearnerDisagreed, true);
        assert.deepEqual(ctx.detached, ["PK11_GenerateRandom"]);
        const failedLearner = N.clientRandomLearner;

        NSS.installFallbackKeyHooks(TIER2_ADDRS_B());
        assert.equal(attached.some((a) => a.at === "PK11_GenerateRandom_B"), false);
        assert.equal(N.clientRandomLearner, failedLearner);
        assert.equal(N.clientRandomLearner.disagreed, true);
        for (const ss of [0x3000000n, 0x4000000n, 0x5000000n]) {   // would reach quorum on a fresh learner
            hook("SSL_ImportFD_B").onLeave({ isNull: () => false, add: () => p("fd:0x" + ss.toString(16)) });
            memory.set(ss + 0x650n, rnd(Number(ss >> 24n)));
            secretCallback(ss);
        }
        assert.equal(N.learnedClientRandomOffset, null);
        assert.equal(ctx.keylogs.filter((l) => l.startsWith("CLIENT_HANDSHAKE")).length, 1); // socket 1 only
    });
});

test("detach teardown detaches the observer and drops the ECH recorder", () => {
    withTier2((ctx) => {
        withCachedOffset();
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        echHandshake(0x1000000n, 1, 2);
        NSS.restoreAppCallbacks();
        assert.deepEqual(ctx.detached, ["PK11_GenerateRandom"]);
        assert.equal(N.echRecorder, null);
        memory.set(0x1000650n, rnd(2));
        secretCallback(0x1000000n);                                // a late callback: live random only
        assert.deepEqual(ctx.keylogs, ["CLIENT_HANDSHAKE_TRAFFIC_SECRET " + rnd(2)]);
    });
});

test("PR_Close of an owned socket drops its ECH record", () => {
    withTier2((ctx) => {
        withCachedOffset();
        NSS.installFallbackKeyHooks(TIER2_ADDRS());
        echHandshake(0x1000000n, 1, 2);
        assert.equal(N.echRecorder.trackedSockets, 1);
        const savedPtr = G.ptr;
        G.ptr = (v: string) => hp(BigInt(v));                       // the stub ptr() carries no value
        try {
            hook("PR_Close").onEnter([p("fd:0x1000000")]);
        } finally {
            G.ptr = savedPtr;
        }
        assert.equal(N.echRecorder.trackedSockets, 0);
        assert.equal(ctx.keylogs.length, 0);
    });
});
