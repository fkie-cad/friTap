// Unit tests for the BoringSSL engine's Tier B needle SEED from live SSL_read /
// SSL_write (agent/ms_agent/engines/boringssl/index.ts, seedNeedleFromSsl).
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/engines/boringssl/index.test.ts)
//
// Tier A can only derive the Tier B needle from a live SSL_HANDSHAKE, which never
// appears for a TLS session opened BEFORE friTap attached. seedNeedleFromSsl reads
// ssl->method (field 0) off an SSL* captured at SSL_read/SSL_write entry — those
// fire on any active session — so Tier B works with no handshake. These tests pin
// the pure extraction + validation + keep-first guard; the Interceptor wiring
// around it is a thin, side-effect-only shell (installNeedleSeedHooks).

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Module/Interceptor/etc. BEFORE the engine
// module loads (mirrors driver.test.ts / rc4 index.test.ts).
import "../../../shared/frida-test-stubs.js";
import { state } from "../../state.js";
import {
    seedNeedleFromSsl,
    installNeedleSeedHooks,
    needleSeedListenerCount,
    BoringsslEngine,
    buildIdleS3Anchors,
    validateIdleS3,
    sslFromS3,
    runTierB0,
    emitSecretBundle,
    shouldRunTierB0,
    nextTierB0ProfileScan,
} from "./index.js";
import { pointerToScanPattern, pointerToTagAgnosticScanPattern } from "../../core/memory.js";

// ---------------------------------------------------------------------------
// A BigInt-backed fake NativePointer with a SHARED memory map, so that
// ssl.add(off).readPointer() can return a value written at that address. Only
// the surface seedNeedleFromSsl / looksLikeHeapPointer / untag touch is modelled:
// add, sub, and, equals, compare, isNull, toString(radix), readPointer.
// ---------------------------------------------------------------------------
function toBig(o: any): bigint {
    return o && typeof o._a === "bigint" ? o._a : BigInt(o);
}
function P(addr: bigint, mem: Map<bigint, any>): any {
    return {
        _a: addr,
        add: (n: any) => P(addr + toBig(n), mem),
        sub: (o: any) => P(addr - toBig(o), mem),
        and: (o: any) => P(addr & toBig(o), mem),
        equals: (o: any) => !!o && typeof o._a === "bigint" && o._a === addr,
        compare: (o: any) => (addr < o._a ? -1 : addr > o._a ? 1 : 0),
        isNull: () => addr === 0n,
        // Frida semantics: no radix -> "0x"-prefixed hex; toString(16) -> bare hex
        // (rememberNeedle/seedNeedleFromSsl rely on the bare form for rva).
        toString: (radix?: number) => (radix === undefined ? "0x" + addr.toString(16) : addr.toString(radix)),
        readPointer: () => (mem.has(addr) ? mem.get(addr) : P(0n, mem)),
    };
}

// Full 64-bit mask (no ARM64 tag stripped in these tests) and a low pointer floor.
function installValidators(mem: Map<bigint, any>): void {
    state.validators = { tagMask: P(0xffffffffffffffffn, mem), pointerMin: P(0x1000n, mem) };
}

function resetState(mem: Map<bigint, any>): void {
    state.needle = null;
    state.mappedRanges = null;               // -> looksLikeHeapPointer uses Process.findRangeByAddress (stub: all mapped)
    state.profiles = null;
    state.profile = { struct_offsets: { SSL: { method: 0 } } };
    installValidators(mem);
}

// Build an SSL* at `sslAddr` whose method field (offset 0) holds a pointer to
// `methodAddr`, and return {ssl, method}.
function makeSslWithMethod(mem: Map<bigint, any>, sslAddr: bigint, methodAddr: bigint) {
    const method = P(methodAddr, mem);
    mem.set(sslAddr, method);                // *(ssl + 0) == method
    return { ssl: P(sslAddr, mem), method };
}

test("seedNeedleFromSsl: derives the needle from a live SSL* (method at offset 0)", () => {
    const mem = new Map<bigint, any>();
    resetState(mem);
    const { ssl, method } = makeSslWithMethod(mem, 0x5000n, 0x400000n);

    assert.equal(seedNeedleFromSsl(ssl, "ssl_io"), true);
    assert.notEqual(state.needle, null);
    assert.equal(state.needle.value.equals(method), true);
    assert.equal(state.needle.source, "ssl_io");
    // The default Process.findModuleByAddress stub returns null, so module/rva are null.
    assert.equal(state.needle.module, null);
    assert.equal(state.needle.rva, null);
});

test("seedNeedleFromSsl: records module + rva when the method resolves to a module", () => {
    const mem = new Map<bigint, any>();
    resetState(mem);
    const { ssl } = makeSslWithMethod(mem, 0x6000n, 0x400010n);

    const G = globalThis as any;
    const saved = G.Process.findModuleByAddress;
    G.Process.findModuleByAddress = () => ({ name: "libsignal_jni.so", base: P(0x400000n, mem) });
    try {
        assert.equal(seedNeedleFromSsl(ssl, "ssl_io"), true);
    } finally {
        G.Process.findModuleByAddress = saved;
    }
    assert.equal(state.needle.module, "libsignal_jni.so");
    assert.equal(state.needle.rva, "0x10");     // 0x400010 - 0x400000
});

test("seedNeedleFromSsl: ignores a NULL SSL* and a NULL/garbage method (needle stays null)", () => {
    const mem = new Map<bigint, any>();
    resetState(mem);

    // NULL SSL*.
    assert.equal(seedNeedleFromSsl(P(0n, mem), "ssl_io"), false);
    assert.equal(state.needle, null);

    // SSL* whose method field is NULL (reads back 0).
    const { ssl } = makeSslWithMethod(mem, 0x7000n, 0n);
    assert.equal(seedNeedleFromSsl(ssl, "ssl_io"), false);
    assert.equal(state.needle, null);

    // SSL* whose method is below the pointer floor (not a plausible pointer).
    const { ssl: ssl2 } = makeSslWithMethod(mem, 0x7100n, 0x10n);
    assert.equal(seedNeedleFromSsl(ssl2, "ssl_io"), false);
    assert.equal(state.needle, null);

    // null argument must not throw.
    assert.equal(seedNeedleFromSsl(null, "ssl_io"), false);
    assert.equal(state.needle, null);
});

test("seedNeedleFromSsl: keep-first guard — never overwrites an existing needle", () => {
    const mem = new Map<bigint, any>();
    resetState(mem);

    // A good needle already exists (e.g. derived by Tier A).
    const existing = P(0xAAAA00n, mem);
    state.needle = { value: existing, module: null, rva: null, source: "A" };

    // A DIFFERENT method value must NOT overwrite it, and reports false.
    const { ssl } = makeSslWithMethod(mem, 0x8000n, 0x400000n);
    assert.equal(seedNeedleFromSsl(ssl, "ssl_io"), false);
    assert.equal(state.needle.value.equals(existing), true);
    assert.equal(state.needle.source, "A");     // untouched

    // The SAME method value confirms (returns true) without mutating the record.
    const { ssl: sslSame } = makeSslWithMethod(mem, 0x8100n, 0xAAAA00n);
    assert.equal(seedNeedleFromSsl(sslSame, "ssl_io"), true);
    assert.equal(state.needle.source, "A");     // still the Tier A record
});

// ---------------------------------------------------------------------------
// Needle-seed hook lifetime: install once, and ALWAYS detach at engine stop.
//
// The device hang (iteration 4): on a target where the needle never seeds
// (stripped Cronet), the Interceptor listeners on the hot SSL_read/SSL_write
// path never self-detach — onSslIoEnter only calls detachNeedleSeedHooks() once
// state.needle is set — so frida's implicit detach had to quiesce them at unload,
// stalling the host thread for minutes. BoringsslEngine.stop() (run from the
// agent's `dispose` RPC) must release them regardless of whether a needle was
// ever found, and installNeedleSeedHooks() must stay a one-shot install.
// ---------------------------------------------------------------------------

/** Enable Tier B seeding and make the four SSL I/O exports resolve to a fake,
 *  non-null address so installNeedleSeedHooks() actually attaches. */
function stubSeedInstall(mem: Map<bigint, any>) {
    const G = globalThis as any;
    resetState(mem);
    state.profile.tiers = { B_ssl_method_ptr: {} };   // seed_from_ssl_io absent => ON
    state.profiles = null;                             // candidateModules() -> [state.profile]

    const savedAttach = G.Interceptor.attach;
    const savedGlobal = G.Module.findGlobalExportByName;
    let attachCount = 0;
    const detached: boolean[] = [];

    G.Interceptor.attach = (_addr: any, _cb: any) => {
        const idx = detached.length;
        detached.push(false);
        attachCount++;
        return { detach: () => { detached[idx] = true; } };
    };
    // A distinct, non-null address per export name so resolution succeeds.
    G.Module.findGlobalExportByName = (name: string) => ({
        isNull: () => false,
        toString: () => "0xexport_" + name,
    });

    return {
        get attachCount() { return attachCount; },
        detached,
        restore() {
            G.Interceptor.attach = savedAttach;
            G.Module.findGlobalExportByName = savedGlobal;
        },
    };
}

test("needle-seed hooks: install attaches, is idempotent, and stop() detaches all even with no needle", () => {
    const mem = new Map<bigint, any>();
    const h = stubSeedInstall(mem);
    try {
        // No needle has ever been seeded on this target.
        assert.equal(state.needle, null);

        installNeedleSeedHooks();
        const firstAttachCount = h.attachCount;
        // SSL_read + SSL_write + SSL_read_ex + SSL_write_ex, one listener each.
        assert.equal(firstAttachCount, 4);
        assert.equal(needleSeedListenerCount(), 4);

        // Idempotent: the one-shot latch means a second call attaches nothing.
        installNeedleSeedHooks();
        assert.equal(h.attachCount, firstAttachCount);
        assert.equal(needleSeedListenerCount(), 4);

        // Teardown must release the hot-path hooks although no needle ever seeded.
        assert.equal(state.needle, null);
        BoringsslEngine.stop!();

        assert.equal(needleSeedListenerCount(), 0);
        assert.equal(h.detached.length, 4);
        assert.ok(h.detached.every((d) => d === true), "every seed listener detached");

        // stop() is idempotent — a second call over an empty list is a no-op.
        BoringsslEngine.stop!();
        assert.equal(needleSeedListenerCount(), 0);
    } finally {
        h.restore();
    }
});

// ===========================================================================
// Tier B0 — idle-SSL bootstrap (heap-scanned SSL3_STATE recovery).
//
// A pre-existing, post-handshake TLS socket on a STRIPPED libssl (modern Signal
// APEX Cronet libhttpengine.so: SSL_read/SSL_write have no symbols) leaves the
// needle seed nothing to fire on and Tier A no handshake to catch. Tier B0 scans
// the heap for a live SSL3_STATE by its three stride-49 traffic-secret length
// bytes, validates it, and emits the secret bundle STRAIGHT from SSL3_STATE — no
// hook, no needle — optionally reverse-linking the SSL* to seed Tier B.
// ===========================================================================

// A byte-addressable memory model: readU8 / readByteArray / readPointer over a
// shared Map<address, byte>, so validateIdleS3 / emitSecretBundle / sslFromS3 can
// read real bytes. Richer than the pointer-only P() above.
function makeByteMem() {
    const bytes = new Map<bigint, number>();
    function PB(addr: bigint): any {
        return {
            _a: addr,
            add: (n: any) => PB(addr + toBig(n)),
            sub: (o: any) => PB(addr - toBig(o)),
            and: (o: any) => PB(addr & toBig(o)),
            equals: (o: any) => !!o && typeof o._a === "bigint" && o._a === addr,
            compare: (o: any) => (addr < o._a ? -1 : addr > o._a ? 1 : 0),
            isNull: () => addr === 0n,
            toString: (radix?: number) => (radix === undefined ? "0x" + addr.toString(16) : addr.toString(radix)),
            readU8: () => (bytes.has(addr) ? (bytes.get(addr) as number) : 0),
            readByteArray: (len: number) => {
                const u = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    const a = addr + BigInt(i);
                    u[i] = bytes.has(a) ? (bytes.get(a) as number) : 0;
                }
                return u.buffer;
            },
            readPointer: () => {
                let v = 0n;
                for (let i = 7; i >= 0; i--) {
                    const a = addr + BigInt(i);
                    const b = bytes.has(a) ? BigInt(bytes.get(a) as number) : 0n;
                    v = (v << 8n) | b;
                }
                return PB(v);
            },
        };
    }
    function writeBytes(addr: bigint, arr: number[] | Uint8Array): void {
        for (let i = 0; i < arr.length; i++) bytes.set(addr + BigInt(i), arr[i] & 0xff);
    }
    function writePtr(addr: bigint, value: bigint): void {
        for (let i = 0; i < 8; i++) bytes.set(addr + BigInt(i), Number((value >> BigInt(8 * i)) & 0xffn));
    }
    function writeU8(addr: bigint, v: number): void { bytes.set(addr, v & 0xff); }
    return { PB, writeBytes, writePtr, writeU8 };
}

function highEntropy(n: number): number[] {
    const a: number[] = [];                       // 32 distinct bytes => 5.0 bits, no zero byte
    for (let i = 0; i < n; i++) a.push((i * 97 + 31) & 0xff);
    return a;
}
function bytesToHex(arr: number[]): string {
    return arr.map((b) => (b < 16 ? "0" : "") + b.toString(16)).join("");
}

function tierB0Profile(): any {
    return {
        struct_offsets: {
            SSL: { method: 0, s3: 48, session: 88, ctx: 104 },
            SSL3_STATE: {
                server_random: 16, client_random: 48, hs: 280,
                write_traffic_secret: 288, write_traffic_secret_len: 336,
                read_traffic_secret: 337, read_traffic_secret_len: 385,
                exporter_secret: 386, exporter_secret_len: 434, established_session: 464,
            },
        },
        constants: {
            ssl_max_md_size: 48, inplace_vector_stride: 49, ssl3_random_size: 32,
            valid_hash_lens: [32, 48],
        },
        tiers: { B0_idle_ssl: { enabled: true }, B_ssl_method_ptr: { emit_secret_bundle: true } },
    };
}

function setTierB0State(m: any): void {
    state.needle = null;
    state.mappedRanges = null;                     // looksLikeHeapPointer -> findRangeByAddress (stub: all mapped)
    state.profiles = null;
    state.scanIndex = 0;                            // scan 0 => shouldRunTierB0() runs
    state.recordedBundles = {};                    // isolate emitSecretBundle cross-scan dedup
    state.b0ProfileScans = {};                      // isolate the per-profile Tier B0 counter
    state.profile = tierB0Profile();
    state.validators = {
        maxZeroFraction: 0.5, minEntropyBits: 4.0, minSecretLen: 32, maxSecretLen: 48,
        pointerMin: m.PB(0x10000n), tagMask: m.PB(0xffffffffffffn),
    } as any;
}

// Lay down a valid, IDLE SSL3_STATE at `s3Addr` (hs == NULL, three 32-byte
// hash-length secrets with 0x20 length bytes, CSPRNG client/server randoms).
function layIdleS3(m: any, s3Addr: bigint): void {
    const off = tierB0Profile().struct_offsets.SSL3_STATE;
    m.writeBytes(s3Addr + BigInt(off.server_random), highEntropy(32));
    m.writeBytes(s3Addr + BigInt(off.client_random), highEntropy(32));
    m.writePtr(s3Addr + BigInt(off.hs), 0n);       // hs == NULL => idle
    m.writeBytes(s3Addr + BigInt(off.write_traffic_secret), highEntropy(32));
    m.writeU8(s3Addr + BigInt(off.write_traffic_secret_len), 0x20);
    m.writeBytes(s3Addr + BigInt(off.read_traffic_secret), highEntropy(32));
    m.writeU8(s3Addr + BigInt(off.read_traffic_secret_len), 0x20);
    m.writeBytes(s3Addr + BigInt(off.exporter_secret), highEntropy(32));
    m.writeU8(s3Addr + BigInt(off.exporter_secret_len), 0x20);
}

test("buildIdleS3Anchors: one masked stride-49 pattern per valid hash length", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const anchors = buildIdleS3Anchors();

    assert.equal(anchors.length, 2);
    assert.deepEqual(anchors.map((a: any) => a.hashLen), [32, 48]);

    const a32 = anchors[0];
    assert.equal(a32.anchorOffset, 336);            // hit address == write_traffic_secret_len
    const toks = a32.pattern.split(" ");
    assert.equal(toks.length, 99);                  // 434 - 336 + 1
    // 0x20 (=32) at the three length-byte positions, wildcard everywhere else.
    assert.equal(toks[0], "20");
    assert.equal(toks[49], "20");                   // one inplace_vector_stride on
    assert.equal(toks[98], "20");                   // two strides on
    for (let i = 0; i < 99; i++) {
        if (i === 0 || i === 49 || i === 98) continue;
        assert.equal(toks[i], "??", "position " + i + " must be a wildcard");
    }
    // The 48-byte anchor uses 0x30 at the same three positions.
    const toks48 = anchors[1].pattern.split(" ");
    assert.equal(toks48[0], "30");
    assert.equal(toks48[49], "30");
    assert.equal(toks48[98], "30");
});

test("validateIdleS3: accepts a valid idle SSL3_STATE", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3 = 0x100000n;
    layIdleS3(m, s3);
    assert.equal(validateIdleS3(m.PB(s3)), true);
});

test("validateIdleS3: rejects a mostly-zero secret", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3 = 0x110000n;
    layIdleS3(m, s3);
    // Overwrite the write traffic secret with zeros (fails zero-fraction gate).
    m.writeBytes(s3 + 288n, new Array(32).fill(0));
    assert.equal(validateIdleS3(m.PB(s3)), false);
});

test("validateIdleS3: rejects a non-hash length byte", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3 = 0x120000n;
    layIdleS3(m, s3);
    m.writeU8(s3 + 336n, 0x28);                     // 40 is not in valid_hash_lens [32,48]
    assert.equal(validateIdleS3(m.PB(s3)), false);
});

test("validateIdleS3: rejects a non-NULL hs (a live handshake is Tier A's case)", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3 = 0x130000n;
    layIdleS3(m, s3);
    m.writePtr(s3 + 280n, 0x900000n);               // hs != NULL => not idle
    assert.equal(validateIdleS3(m.PB(s3)), false);
});

test("runTierB0: emits a bundle straight from idle SSL3_STATE and seeds the needle from the SSL*", () => {
    const m = makeByteMem();
    setTierB0State(m);

    const s3Addr = 0x100000n;
    const sslAddr = 0x200000n;
    const sessionAddr = 0x300000n;
    const ctxAddr = 0x310000n;
    const methodAddr = 0x400000n;

    layIdleS3(m, s3Addr);
    // SSL* whose fields point at the idle s3 and plausible heap objects.
    m.writePtr(sslAddr + 0n, methodAddr);           // ssl->method (the Tier B needle)
    m.writePtr(sslAddr + 48n, s3Addr);              // ssl->s3 (two-way close)
    m.writePtr(sslAddr + 88n, sessionAddr);         // ssl->session
    m.writePtr(sslAddr + 104n, ctxAddr);            // ssl->ctx

    const G = globalThis as any;
    const saved = {
        send: G.send, scanSync: G.Memory.scanSync, alloc: G.Memory.alloc,
        findModuleByAddress: G.Process.findModuleByAddress,
    };
    const sent: any[] = [];
    G.send = (msg: any) => sent.push(msg);
    // method resolves to a loaded module => acceptsAsSsl + needle recording succeed.
    G.Process.findModuleByAddress = () => ({ name: "libhttpengine.so", base: m.PB(0x400000n) });
    // pointerToScanPattern needs a tiny writable/readable scratch buffer.
    G.Memory.alloc = (_size: number) => {
        let stored = 0n;
        const buf: any = {
            isNull: () => false,
            writePointer: (p: any) => { stored = toBig(p); return buf; },
            readByteArray: (len: number) => {
                const u = new Uint8Array(len);
                for (let i = 0; i < len; i++) u[i] = Number((stored >> BigInt(8 * i)) & 0xffn);
                return u.buffer;
            },
        };
        return buf;
    };
    // Pattern-aware scan. The idle anchor scan starts with the 0x20 hash-length
    // byte and finds s3; the reverse-link scan encodes the s3 pointer and finds the
    // ssl->s3 slot. NB the reverse-link pattern is now TAG-AGNOSTIC, so it too
    // carries '??' in the top tag bytes — distinguish by the first byte (0x20 = the
    // anchor's length byte) rather than by the presence of a wildcard.
    G.Memory.scanSync = (_base: any, _len: number, pattern: string) => {
        const first = pattern.split(" ")[0];
        if (first === "20") return [{ address: m.PB(s3Addr + 336n) }];  // 32B-secret anchor -> s3
        if (first === "30") return [];                                  // 48B-secret anchor: no hit here
        return [{ address: m.PB(sslAddr + 48n) }];                      // reverse-link -> ssl->s3 slot
    };

    const ranges = [{ base: m.PB(0x500000n), size: 0x1000 }];
    const stats: any = { emitted: 0, tierB0: { candidates: 0, validated: 0, emitted: 0 } };
    const errors: string[] = [];
    try {
        runTierB0(ranges, stats, errors);
    } finally {
        G.send = saved.send; G.Memory.scanSync = saved.scanSync; G.Memory.alloc = saved.alloc;
        G.Process.findModuleByAddress = saved.findModuleByAddress;
    }

    assert.deepEqual(errors, []);
    assert.equal(stats.tierB0.candidates, 1);
    assert.equal(stats.tierB0.validated, 1);
    assert.equal(stats.tierB0.emitted, 1);

    const bundle = sent.find((m2) => m2.type === "tls_secret_bundle");
    assert.ok(bundle, "a tls_secret_bundle must be emitted");
    assert.equal(bundle.ssl, "0x200000");           // provenance from the recovered SSL*
    assert.equal(bundle.client_random, bytesToHex(highEntropy(32)));
    assert.equal(bundle.server_random, bytesToHex(highEntropy(32)));
    assert.equal(bundle.client_traffic_secret_0, bytesToHex(highEntropy(32)));
    assert.equal(bundle.server_traffic_secret_0, bytesToHex(highEntropy(32)));
    assert.equal(bundle.exporter_secret, bytesToHex(highEntropy(32)));

    // The SSL* was reverse-linked and used to seed the Tier B needle.
    assert.notEqual(state.needle, null);
    assert.equal(state.needle.source, "heap_idle_s3");
    assert.equal(state.needle.value.equals(m.PB(methodAddr)), true);
});

test("pointerToTagAgnosticScanPattern: tag-independent, wildcards only the tag bytes", () => {
    const mem = new Map<bigint, any>();
    const G = globalThis as any;
    const savedAlloc = G.Memory.alloc;
    G.Memory.alloc = (_size: number) => {
        let stored = 0n;
        const buf: any = {
            isNull: () => false,
            writePointer: (p: any) => { stored = toBig(p); return buf; },
            readByteArray: (len: number) => {
                const u = new Uint8Array(len);
                for (let i = 0; i < len; i++) u[i] = Number((stored >> BigInt(8 * i)) & 0xffn);
                return u.buffer;
            },
        };
        return buf;
    };
    try {
        const mask48 = P(0xffffffffffffn, mem);
        const tagged = P(0xb400007451954538n, mem);     // scudo/MTE tag in the top byte
        const untagged = P(0x00007451954538n, mem);     // same object, canonical VA
        const pat = pointerToTagAgnosticScanPattern(tagged, mask48);
        // The stored (tagged) pointer and the scanned (untagged) address must yield
        // the SAME pattern, and it must wildcard exactly the 2 tag bytes above the
        // 48-bit mask while matching the 6 canonical-address bytes.
        assert.equal(pat, pointerToTagAgnosticScanPattern(untagged, mask48));
        assert.equal(pat, "38 45 95 51 74 00 ?? ??");
        // A full 64-bit mask leaves no tag bytes -> exact, wildcard-free pattern,
        // identical to pointerToScanPattern (so non-tagged allocators are unaffected).
        const mask64 = P(0xffffffffffffffffn, mem);
        assert.equal(pointerToTagAgnosticScanPattern(untagged, mask64), pointerToScanPattern(untagged));
    } finally {
        G.Memory.alloc = savedAlloc;
    }
});

test("sslFromS3: recovers the SSL* from an idle s3 via the pointer scan", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3Addr = 0x100000n;
    const sslAddr = 0x200000n;
    layIdleS3(m, s3Addr);
    m.writePtr(sslAddr + 0n, 0x400000n);
    m.writePtr(sslAddr + 48n, s3Addr);
    m.writePtr(sslAddr + 88n, 0x300000n);
    m.writePtr(sslAddr + 104n, 0x310000n);

    const G = globalThis as any;
    const saved = { scanSync: G.Memory.scanSync, alloc: G.Memory.alloc, fmba: G.Process.findModuleByAddress };
    G.Process.findModuleByAddress = () => ({ name: "libhttpengine.so", base: m.PB(0x400000n) });
    G.Memory.alloc = (_size: number) => {
        let stored = 0n;
        const buf: any = {
            isNull: () => false,
            writePointer: (p: any) => { stored = toBig(p); return buf; },
            readByteArray: (len: number) => {
                const u = new Uint8Array(len);
                for (let i = 0; i < len; i++) u[i] = Number((stored >> BigInt(8 * i)) & 0xffn);
                return u.buffer;
            },
        };
        return buf;
    };
    G.Memory.scanSync = () => [{ address: m.PB(sslAddr + 48n) }];

    const ranges = [{ base: m.PB(0x500000n), size: 0x1000 }];
    try {
        const ssl = sslFromS3(m.PB(s3Addr), ranges, []);
        assert.notEqual(ssl, null);
        assert.equal(ssl.equals(m.PB(sslAddr)), true);
    } finally {
        G.Memory.scanSync = saved.scanSync; G.Memory.alloc = saved.alloc; G.Process.findModuleByAddress = saved.fmba;
    }
});

test("acceptsAsSsl: profile-driven extra check — default (Chrome) rejects a bad ssl->session; signal ([]) accepts it", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const s3Addr = 0x100000n, sslAddr = 0x200000n;
    layIdleS3(m, s3Addr);
    m.writePtr(sslAddr + 0n, 0x400000n);     // ssl->method -> resolves to a module (mock below)
    m.writePtr(sslAddr + 48n, s3Addr);       // ssl->s3 -> round-trip closes
    m.writePtr(sslAddr + 104n, 0x310000n);   // ssl->ctx valid
    // ssl->session (ssl+88) is deliberately left UNSET -> reads 0x0 -> not a heap
    // pointer: exactly the libsignal mid-stream case that used to reject the real SSL.
    const G = globalThis as any;
    const saved = { scanSync: G.Memory.scanSync, alloc: G.Memory.alloc, fmba: G.Process.findModuleByAddress };
    G.Process.findModuleByAddress = () => ({ name: "libsignal_jni.so", base: m.PB(0x400000n) });
    G.Memory.alloc = (_size: number) => {
        let stored = 0n;
        const buf: any = { isNull: () => false, writePointer: (p: any) => { stored = toBig(p); return buf; },
            readByteArray: (len: number) => { const u = new Uint8Array(len); for (let i = 0; i < len; i++) u[i] = Number((stored >> BigInt(8 * i)) & 0xffn); return u.buffer; } };
        return buf;
    };
    G.Memory.scanSync = () => [{ address: m.PB(sslAddr + 48n) }];
    const ranges = [{ base: m.PB(0x500000n), size: 0x1000 }];
    const tier = (state.profile as any).tiers.B_ssl_method_ptr;
    try {
        // Default (key absent) == the historical Chrome/Cronet guard ['session','ctx']:
        // the unset ssl->session fails, so the candidate is rejected — unchanged behavior.
        delete tier.reverse_link_require_heap_fields;
        assert.equal(sslFromS3(m.PB(s3Addr), ranges, []), null);
        // Signal profile opts out with [] — round-trip + method-in-module alone accepts.
        tier.reverse_link_require_heap_fields = [];
        const ssl = sslFromS3(m.PB(s3Addr), ranges, []);
        assert.notEqual(ssl, null);
        assert.equal(ssl.equals(m.PB(sslAddr)), true);
    } finally {
        G.Memory.scanSync = saved.scanSync; G.Memory.alloc = saved.alloc; G.Process.findModuleByAddress = saved.fmba;
        delete tier.reverse_link_require_heap_fields;
    }
});

// ---------------------------------------------------------------------------
// emitSecretBundle cross-scan dedup (the ANR fix). Without it, Tier B0 re-emits
// the SAME idle bundle every scan, so the poll loop's emitted>0 backoff never
// grows and the heavy full-heap scan runs continuously -> device-confirmed ANR.
// A SECOND identical call must stay quiet; a KeyUpdate (same client_random,
// rotated secrets) must still re-emit.
// ---------------------------------------------------------------------------

// A second, distinct high-entropy fill (odd multiplier coprime to 256 => 32
// distinct non-zero bytes) for the KeyUpdate case.
function highEntropy2(n: number): number[] {
    const a: number[] = [];
    for (let i = 0; i < n; i++) a.push((i * 53 + 7) & 0xff);
    return a;
}

test("emitSecretBundle: dedups an unchanged bundle across scans, re-emits on KeyUpdate", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const off = tierB0Profile().struct_offsets.SSL3_STATE;
    const s3 = 0x140000n;
    layIdleS3(m, s3);
    const clientRandom = bytesToHex(highEntropy(32));

    const G = globalThis as any;
    const savedSend = G.send;
    const sent: any[] = [];
    G.send = (msg: any) => sent.push(msg);
    const stats: any = { emitted: 0 };
    try {
        // First call for this (client_random, secrets): emits + counts.
        assert.equal(emitSecretBundle(null, m.PB(s3), clientRandom, stats), true);
        assert.equal(stats.emitted, 1);
        assert.equal(sent.length, 1);
        assert.equal(sent[0].type, "tls_secret_bundle");

        // Second IDENTICAL call: returns false, no send(), no stats.emitted bump.
        assert.equal(emitSecretBundle(null, m.PB(s3), clientRandom, stats), false);
        assert.equal(stats.emitted, 1);
        assert.equal(sent.length, 1);

        // KeyUpdate: SAME client_random, DIFFERENT secrets => must re-emit.
        m.writeBytes(s3 + BigInt(off.write_traffic_secret), highEntropy2(32));
        assert.equal(emitSecretBundle(null, m.PB(s3), clientRandom, stats), true);
        assert.equal(stats.emitted, 2);
        assert.equal(sent.length, 2);
        assert.equal(sent[1].client_traffic_secret_0, bytesToHex(highEntropy2(32)));

        // And the rotated bundle is itself now deduped.
        assert.equal(emitSecretBundle(null, m.PB(s3), clientRandom, stats), false);
        assert.equal(stats.emitted, 2);
        assert.equal(sent.length, 2);
    } finally {
        G.send = savedSend;
    }
});

// server_random is provenance only (the offline decrypter recovers keys from the
// traffic secrets, never from server_random). A long-idle post-handshake SSL3_STATE
// can scrub/reuse server_random, so a bad server_random must NOT drop a bundle whose
// three traffic secrets are valid — it is emitted as '' instead. Regression guard for
// the "Tier B0 emitted nothing on an idle socket" device finding.
test("emitSecretBundle: scrubbed server_random still emits the bundle with server_random=''", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const off = tierB0Profile().struct_offsets.SSL3_STATE;
    const s3 = 0x150000n;
    layIdleS3(m, s3);
    // Scrub server_random (all zeros => fails looksLikeRandom) while the three
    // traffic secrets and client_random stay valid.
    m.writeBytes(s3 + BigInt(off.server_random), new Uint8Array(32));
    const clientRandom = bytesToHex(highEntropy(32));

    const G = globalThis as any;
    const savedSend = G.send;
    const sent: any[] = [];
    G.send = (msg: any) => sent.push(msg);
    const stats: any = { emitted: 0 };
    try {
        assert.equal(emitSecretBundle(null, m.PB(s3), clientRandom, stats), true);
        assert.equal(stats.emitted, 1);
        assert.equal(sent.length, 1);
        assert.equal(sent[0].server_random, "");                          // omitted, not dropped
        assert.ok(sent[0].client_traffic_secret_0.length > 0);            // secrets still present
        assert.ok(sent[0].server_traffic_secret_0.length > 0);
    } finally {
        G.send = savedSend;
    }
});

// ---------------------------------------------------------------------------
// Tier B0 throttle: shouldRunTierB0(profileScanCount) runs on that profile's
// eligible scan 0, skips non-multiples of rescan_every, and runs again on each
// multiple. runTiers gates the heavy heap scan on this AND resolveNeedleValue()
// ===null, so on stripped Cronet (needle never seeds) this is what stops the scan
// from running every poll cycle. The counter is now PER PROFILE, so the predicate
// is a pure function of that profile's own eligible-scan count.
// ---------------------------------------------------------------------------
test("shouldRunTierB0: runs on profile scan 0, skips non-multiples, runs on the rescan_every multiple", () => {
    const m = makeByteMem();
    setTierB0State(m);
    state.profile.tiers.B0_idle_ssl.rescan_every = 8;

    const cases: Array<[number, boolean]> = [
        [0, true], [1, false], [3, false], [7, false],
        [8, true], [9, false], [15, false], [16, true],
    ];
    for (const [count, expected] of cases) {
        assert.equal(shouldRunTierB0(count), expected, "profileScanCount " + count);
    }

    // Missing / bad rescan_every falls back to the default cadence (8), never OFF.
    delete state.profile.tiers.B0_idle_ssl.rescan_every;
    assert.equal(shouldRunTierB0(0), true);
    assert.equal(shouldRunTierB0(8), true);
    assert.equal(shouldRunTierB0(5), false);
});

// nextTierB0ProfileScan() keys the counter on the ACTIVE profile's id and returns
// the PRE-increment count, so each profile advances on its OWN scans starting at 0.
test("nextTierB0ProfileScan: independent per-profile counters keyed on profile id", () => {
    const m = makeByteMem();
    setTierB0State(m);

    state.profile.id = "generic";
    assert.equal(nextTierB0ProfileScan(), 0);       // generic's first eligible scan
    assert.equal(nextTierB0ProfileScan(), 1);
    assert.equal(nextTierB0ProfileScan(), 2);

    // Switching to a DIFFERENT profile starts that profile at its own 0.
    state.profile.id = "scudo";
    assert.equal(nextTierB0ProfileScan(), 0);
    assert.equal(nextTierB0ProfileScan(), 1);

    // generic's counter is untouched by scudo's advances.
    state.profile.id = "generic";
    assert.equal(nextTierB0ProfileScan(), 3);

    // A profile with no id falls back to the shared 'default' bucket.
    delete state.profile.id;
    assert.equal(nextTierB0ProfileScan(), 0);
    assert.equal(nextTierB0ProfileScan(), 1);
});

// ---------------------------------------------------------------------------
// REGRESSION (device-confirmed): under the default `--protocol signal` command TWO
// boringssl profiles run each scanOnce in order, sharing the GLOBAL state.scanIndex
// which the driver increments ONCE PER PROFILE-SCAN. So profile[0] sees even indices
// and the ONLY Signal-matching profile (scudo, profile[1]) always sees ODD indices —
// and a `scanIndex % 8 === 0` gate NEVER fires for odd numbers, starving scudo's
// Tier B0. The per-profile counter must make scudo's Tier B0 fire on ITS OWN first
// eligible scan and every 8th of its scans, regardless of ordering/parity.
// ---------------------------------------------------------------------------
test("Tier B0 per-profile counter: scudo profile is NOT starved by two-profile parity", () => {
    const m = makeByteMem();
    setTierB0State(m);
    const RESCAN = 8;
    state.profile.tiers.B0_idle_ssl.rescan_every = RESCAN;

    // Reproduce the two-profile scan loop: for each scanOnce, profile "generic" runs
    // then profile "scudo" runs, and the driver increments the shared global
    // scanIndex once per profile-scan. Only "scudo" matches Signal, so only its Tier
    // B0 decisions matter. We record, per profile, the shared scanIndex it saw and
    // whether its Tier B0 fired under the NEW per-profile gate.
    const profiles = ["generic", "scudo"];
    const scudoFired: Array<{ scudoScan: number; sharedIndex: number; fired: boolean }> = [];
    let scudoScan = 0;

    for (let scanOnce = 0; scanOnce < 24; scanOnce++) {
        for (const id of profiles) {
            state.profile.id = id;
            // The predicate that runTiers evaluates for this profile-scan.
            const fired = shouldRunTierB0(nextTierB0ProfileScan());
            if (id === "scudo") {
                scudoFired.push({ scudoScan: scudoScan++, sharedIndex: state.scanIndex, fired });
            }
            state.scanIndex++;                       // driver.ts: once per profile-scan
        }
    }

    // The shared global scanIndex seen by scudo is ALWAYS ODD (the old bug: 1,3,5,…),
    // so the old `scanIndex % 8 === 0` gate would have fired ZERO times.
    assert.ok(scudoFired.every((r) => r.sharedIndex % 2 === 1), "scudo always saw odd shared indices");
    assert.equal(scudoFired.filter((r) => r.sharedIndex % RESCAN === 0).length, 0,
        "old shared-index gate would never fire for scudo");

    // The NEW per-profile gate fires on scudo's OWN scans 0, 8, 16, … — never starved.
    for (const r of scudoFired) {
        const expected = r.scudoScan % RESCAN === 0;
        assert.equal(r.fired, expected, "scudo own-scan " + r.scudoScan);
    }
    // Concretely: it DID fire on scudo's first eligible scan and its 8th and 16th.
    assert.equal(scudoFired[0].fired, true, "scudo Tier B0 fires on its own first scan");
    assert.equal(scudoFired[RESCAN].fired, true, "scudo Tier B0 fires on its own 8th scan");
    assert.equal(scudoFired[2 * RESCAN].fired, true, "scudo Tier B0 fires on its own 16th scan");
    assert.ok(scudoFired.filter((r) => r.fired).length >= 3, "scudo Tier B0 fires repeatedly, not starved");
});

// Single-profile behaviour is preserved: with one profile, Tier B0 still runs on
// scan 0 then every 8th of its scans (the pre-regression contract).
test("Tier B0 per-profile counter: single profile still runs on scan 0 then every 8th", () => {
    const m = makeByteMem();
    setTierB0State(m);
    state.profile.tiers.B0_idle_ssl.rescan_every = 8;
    state.profile.id = "only";

    const fired: boolean[] = [];
    for (let i = 0; i < 17; i++) fired.push(shouldRunTierB0(nextTierB0ProfileScan()));

    assert.equal(fired[0], true);
    assert.equal(fired[8], true);
    assert.equal(fired[16], true);
    assert.equal(fired.filter((f) => f).length, 3);      // exactly 0, 8, 16 in 0..16
    for (let i = 0; i < 17; i++) {
        if (i === 0 || i === 8 || i === 16) continue;
        assert.equal(fired[i], false, "scan " + i + " throttled");
    }
});
