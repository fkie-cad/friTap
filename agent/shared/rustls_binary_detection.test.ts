// Unit tests for content-based rustls detection (agent/shared/rustls_binary_detection.ts) and
// the registry/platform wiring built on it.
//
// Run: npm run test:agent
//
// WHY: rustls is linked into the application image (the main executable under any name, or an
// arbitrarily named .so), so /.*rustls.*/ never matches a plain Rust binary like `myapp`.
// Detection keys on the "rustls-0.2" crate-path marker that panic-location metadata keeps in
// .rodata (it survives `strip`). The scan is bounded + chunked so a marker straddling a chunk
// boundary is still found and a huge non-Rust module cannot block the agent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "./frida-test-stubs.js";
import {
    RUSTLS_MARKER,
    RUSTLS_LINUX_NAMED_MODULE,
    findRustlsMarker,
    extractRustlsVersion,
    scanBufferForRustls,
    scanChunkedForRustls,
    moduleEmbedsRustls,
    isRustlsModule,
    resetRustlsModuleCache,
} from "./rustls_binary_detection.js";

const G = globalThis as any;
G.send = () => {};
const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** A realistic stripped-Rust-binary rodata fragment: a rustls crate panic-location path. */
function rodataWith(version: string, prefix = 64): Uint8Array {
    const path = `/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/rustls-${version}/src/tls13/key_schedule.rs`;
    const bytes = new Uint8Array(prefix + path.length + 16);
    for (let i = 0; i < path.length; i++) bytes[prefix + i] = path.charCodeAt(i);
    return bytes;
}

/** A fake NativePointer over `memory` (enough for add/readByteArray). */
function ptrInto(memory: Uint8Array, offset = 0): any {
    return {
        add: (n: number) => ptrInto(memory, offset + Number(n)),
        readByteArray: (length: number) => {
            if (offset < 0 || offset + length > memory.length) throw new Error(`access violation at ${offset}`);
            return memory.slice(offset, offset + length).buffer;
        },
        toString: () => `0x${offset.toString(16)}`,
    };
}

/** A module whose single readable data range covers `memory`. */
function rangeModule(memory: Uint8Array, protection = "r--", name = "myapp"): any {
    return {
        name, base: ptrInto(memory), size: memory.length,
        enumerateRanges: (prot: string) => prot === "r--"
            ? [{ base: ptrInto(memory), size: memory.length, protection }] : [],
    };
}

test("the marker is \"rustls-0.2\" (covers rustls 0.20 .. 0.29)", () => {
    assert.equal(RUSTLS_MARKER, "rustls-0.2");
});

test("findRustlsMarker: offset of the marker, or -1 when absent", () => {
    const bytes = rodataWith("0.23.27");
    const offset = findRustlsMarker(bytes);
    assert.ok(offset > 0);
    assert.equal(Buffer.from(bytes.subarray(offset, offset + RUSTLS_MARKER.length)).toString("latin1"), RUSTLS_MARKER);
    assert.equal(findRustlsMarker(new Uint8Array([0x61, 0x62, 0x63])), -1, "absent: -1");
    assert.equal(findRustlsMarker(Buffer.from("rustls-0.1x")), -1, "0.1x is not 0.2x");
});

test("extractRustlsVersion: the dotted version after rustls-, else undefined", () => {
    for (const v of ["0.23.27", "0.22.4", "0.20.0", "0.29.123"]) {
        const bytes = rodataWith(v);
        assert.equal(extractRustlsVersion(bytes, findRustlsMarker(bytes)), v);
    }
    // marker present but the version digits run off the end of the buffer -> no full version
    const truncated = Buffer.concat([Buffer.from("xxxx"), Buffer.from("rustls-0.2")]);
    assert.equal(extractRustlsVersion(truncated, findRustlsMarker(truncated)), "0.2");
});

test("scanBufferForRustls: present + version on a hit, present=false otherwise", () => {
    assert.deepEqual(scanBufferForRustls(rodataWith("0.23.46")), { present: true, version: "0.23.46" });
    assert.deepEqual(scanBufferForRustls(Buffer.from("no crate paths here")), { present: false });
});

test("scanChunkedForRustls: finds a marker straddling a chunk boundary (overlap works)", () => {
    const bytes = rodataWith("0.23.27", 0);
    const markerAt = findRustlsMarker(bytes);
    // chunk boundary lands 3 bytes into the marker, so chunk 0's body ends mid-marker; only
    // the overlap carries the whole "rustls-<version>" token into chunk 0's read window.
    const chunkBytes = markerAt + 3;
    const read = (off: number, len: number) =>
        (off < 0 || off + len > bytes.length) ? null : bytes.subarray(off, off + len);
    assert.deepEqual(scanChunkedForRustls(read, bytes.length, chunkBytes), { present: true, version: "0.23.27" });
});

test("scanChunkedForRustls: an unreadable slice is skipped, a marker-free region is false", () => {
    assert.deepEqual(scanChunkedForRustls(() => null, 4096, 1024), { present: false });
    const clean = new Uint8Array(4096);
    assert.deepEqual(scanChunkedForRustls((o, l) => clean.subarray(o, o + l), clean.length, 1024), { present: false });
});

test("moduleEmbedsRustls: scans every readable range, INCLUDING r-x (lld maps .rodata there)", () => {
    assert.deepEqual(moduleEmbedsRustls(rangeModule(rodataWith("0.22.4"))), { present: true, version: "0.22.4" });
    assert.deepEqual(moduleEmbedsRustls(rangeModule(new Uint8Array(0x1000))), { present: false });
    // .rodata often maps inside the read+execute LOAD segment; it must still be scanned.
    assert.deepEqual(moduleEmbedsRustls(rangeModule(rodataWith("0.23.27"), "r-x")), { present: true, version: "0.23.27" });
});

test("moduleEmbedsRustls: no range enumeration (unsupported) is not rustls, and never throws", () => {
    assert.deepEqual(moduleEmbedsRustls({ name: "x", size: 0x10, base: ptrInto(new Uint8Array(0x10)) } as any), { present: false });
    const broken = {
        name: "x", size: 0x1000, base: ptrInto(new Uint8Array(0x10)),
        enumerateRanges: () => [{ base: { add: () => ({ readByteArray: () => { throw new Error("AV"); } }) }, size: 0x4000, protection: "r--" }],
    };
    assert.deepEqual(moduleEmbedsRustls(broken as any), { present: false });
});

test("isRustlsModule: looks up by name, caches per name+base, unknown module is false", () => {
    const memory = rodataWith("0.23.27");
    let reads = 0;
    const base = ptrInto(memory);
    const counted: any = {
        add: (n: number) => { const p = base.add(n); return { ...p, readByteArray: (l: number) => { reads++; return p.readByteArray(l); } }; },
        toString: base.toString,
    };
    const module = {
        name: "myapp", base: counted, size: memory.length,
        enumerateRanges: (prot: string) => prot === "r--" ? [{ base: counted, size: memory.length, protection: "r--" }] : [],
    };
    const saved = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => name === "myapp" ? module : null;
    try {
        resetRustlsModuleCache();
        assert.equal(isRustlsModule("myapp"), true);
        const readsAfterFirst = reads;
        assert.equal(isRustlsModule("myapp"), true);
        assert.equal(reads, readsAfterFirst, "second call answered from the cache");
        assert.equal(isRustlsModule("libc.so.6"), false, "unknown module");
    } finally {
        G.Process.findModuleByName = saved;
        resetRustlsModuleCache();
    }
});

test("RUSTLS_LINUX_NAMED_MODULE matches exactly the names the name-based row already hooks", () => {
    for (const named of ["librustls.so", "librustls_ex.so", "myrustls", "rustls-ffi.so"]) {
        assert.ok(RUSTLS_LINUX_NAMED_MODULE.test(named), `${named} is name-matched (excluded from the content row)`);
    }
    assert.equal(RUSTLS_LINUX_NAMED_MODULE.test("myapp"), false, "a plain Rust binary is content-detected, not name-excluded");
});

// ---- platform wiring (source assertions, like the Go detection tests) ----------------------

test("Linux registers the content-detected rustls row for both hook paths", () => {
    const src = readFileSync(join(AGENT, "platforms/linux.ts"), "utf8");
    assert.match(src, /pattern: \/\.\*\/,[^\n]*excludePattern: RUSTLS_LINUX_NAMED_MODULE, contentFilter: isRustlsModule, hookFn: \(use_modern \? rustls_execute_modern : rustls_execute\), library: "Rustls", libraryType: "rustls", protocol: "tls"/);
    assert.ok(src.includes(`import { isRustlsModule, RUSTLS_LINUX_NAMED_MODULE } from "../shared/rustls_binary_detection.js"`));
});

test("both Android rustls trees wire the shared static-rustls pattern table", () => {
    for (const file of [
        "legacy/tls/platforms/android/rustls_android.ts",
        "tls/platforms/android/rustls_android.ts",
    ]) {
        const src = readFileSync(join(AGENT, file), "utf8");
        assert.ok(/import \{ installRustlsStaticPatternHooks \} from ".*rustls_static_patterns\.js"/.test(src),
            `${file} imports installRustlsStaticPatternHooks`);
        assert.ok(src.includes("installRustlsStaticPatternHooks("), `${file} calls installRustlsStaticPatternHooks`);
        assert.ok(src.includes("shared.tls13"), `${file} gates the built-in TLS 1.3 hook on the shared-table result`);
        assert.ok(src.includes("shared.tls12"), `${file} gates the built-in TLS 1.2 hook on the shared-table result`);
    }
});
