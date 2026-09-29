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
import { seedNeedleFromSsl } from "./index.js";

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
