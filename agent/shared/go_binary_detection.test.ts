// Unit tests for content-based Go image detection (agent/shared/go_binary_detection.ts) and the
// Go TLS registry rows built on it (macOS, Windows, Linux).
//
// Run: npm run test:agent
//
// WHY: Go's crypto/tls lives in the Go image itself — usually the main executable, under any
// name. The Linux rows matched only names like "x.go1.21" / "x.go.so", and macOS/Windows had
// no Go row at all. Detection now keys on Go's build-info blob ("\xff Go buildinf:"):
// ELF ".go.buildinfo", Mach-O "__go_buildinfo", PE: 16-byte aligned near the start of .data.
// The layouts were checked on Go 1.21/1.24/1.25 darwin+windows (amd64, arm64), full + stripped.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "./frida-test-stubs.js";
import {
    GO_BUILDINFO_MAGIC,
    GO_LINUX_NAMED_MODULE,
    findGoBuildInfoMagic,
    hasGoBuildInfoMagicAt,
    isGoModule,
    moduleHasGoBuildInfo,
    parsePeSections,
    resetGoModuleCache,
} from "./go_binary_detection.js";
import { HookRegistry } from "./registry.js";
import { PLATFORM_DARWIN, PLATFORM_LINUX, PLATFORM_WINDOWS } from "./shared_structures.js";

const G = globalThis as any;
G.send = () => {};
const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

/** A minimal PE image: headers with one .text and one .data section; magic at .data + `magicAt`. */
function fakePe(magicAt: number | null, dataRva = 0x3000, dataSize = 0x2000): Uint8Array {
    const image = new Uint8Array(dataRva + dataSize);
    const view = new DataView(image.buffer);
    view.setUint16(0, 0x5a4d, true);          // "MZ"
    view.setUint32(0x3c, 0x80, true);         // e_lfanew
    view.setUint32(0x80, 0x00004550, true);   // "PE\0\0"
    view.setUint16(0x80 + 6, 2, true);        // NumberOfSections
    view.setUint16(0x80 + 20, 0xf0, true);    // SizeOfOptionalHeader (PE32+)
    const table = 0x80 + 24 + 0xf0;
    const section = (i: number, name: string, rva: number, size: number) => {
        for (let j = 0; j < name.length; j++) image[table + i * 40 + j] = name.charCodeAt(j);
        view.setUint32(table + i * 40 + 8, size, true);
        view.setUint32(table + i * 40 + 12, rva, true);
    };
    section(0, ".text", 0x1000, 0x2000);
    section(1, ".data", dataRva, dataSize);
    if (magicAt !== null) image.set(GO_BUILDINFO_MAGIC, dataRva + magicAt);
    return image;
}

function peModule(image: Uint8Array, name = "app.exe"): any {
    return { name, base: ptrInto(image), size: image.length };
}

/** An ELF/Mach-O-like module: no "MZ"; sections from Frida's enumerateSections. */
function sectionModule(sectionName: string, withMagic: boolean): any {
    const image = new Uint8Array(0x2000);
    image[0] = 0x7f; // ELF / Mach-O header bytes are not "MZ"
    if (withMagic) image.set(GO_BUILDINFO_MAGIC, 0x1000);
    return {
        name: "app", base: ptrInto(image), size: image.length,
        enumerateSections: () => [
            { name: "__text", address: ptrInto(image, 0x100), size: 0x100 },
            { name: sectionName, address: ptrInto(image, 0x1000), size: 0x100 },
        ],
    };
}

test("the magic is Go's \"\\xff Go buildinf:\"", () => {
    assert.equal(Buffer.from(GO_BUILDINFO_MAGIC).toString("latin1"), "\xff Go buildinf:");
});

test("findGoBuildInfoMagic: only at 16-byte alignment (debug/buildinfo's search rule)", () => {
    const bytes = new Uint8Array(0x100);
    bytes.set(GO_BUILDINFO_MAGIC, 0x48);
    assert.equal(findGoBuildInfoMagic(bytes), -1, "0x48 is not 16-byte aligned");
    bytes.set(GO_BUILDINFO_MAGIC, 0x60);
    assert.equal(findGoBuildInfoMagic(bytes), 0x60);
    assert.equal(hasGoBuildInfoMagicAt(bytes, 0xf8), false, "a truncated tail never matches");
});

test("parsePeSections reads the in-memory section table; non-PE headers give null", () => {
    const sections = parsePeSections(fakePe(0));
    assert.deepEqual(sections?.map((s) => [s.name, s.virtualAddress, s.virtualSize]),
        [[".text", 0x1000, 0x2000], [".data", 0x3000, 0x2000]]);
    assert.equal(parsePeSections(new Uint8Array(0x200)), null);
    const badSignature = fakePe(0);
    badSignature[0x80] = 0;
    assert.equal(parsePeSections(badSignature), null);
});

test("PE: Go when .data carries the blob (at its start, or later at 16-byte alignment)", () => {
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(0))), true);
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(0x40))), true);
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(null))), false, "no blob: not Go");
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(0x44))), false, "unaligned: not the blob");
});

test("PE: the search is bounded to .data's first 64 KiB", () => {
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(0x10000, 0x3000, 0x20000))), false);
    assert.equal(moduleHasGoBuildInfo(peModule(fakePe(0xfff0, 0x3000, 0x20000))), true);
});

test("ELF/Mach-O: Go when .go.buildinfo / __go_buildinfo opens with the magic", () => {
    assert.equal(moduleHasGoBuildInfo(sectionModule("__go_buildinfo", true)), true);
    assert.equal(moduleHasGoBuildInfo(sectionModule(".go.buildinfo", true)), true);
    assert.equal(moduleHasGoBuildInfo(sectionModule(".go.buildinfo", false)), false, "named section without magic");
    assert.equal(moduleHasGoBuildInfo(sectionModule("__data", true)), false, "magic outside the Go section");
});

test("detection never throws: unreadable memory or a failing section walk is 'not Go'", () => {
    const unreadable = { name: "x", size: 0x1000, base: { readByteArray: () => { throw new Error("AV"); } } };
    assert.equal(moduleHasGoBuildInfo(unreadable as any), false);
    const m = sectionModule("__go_buildinfo", true);
    m.enumerateSections = () => { throw new Error("no sections"); };
    assert.equal(moduleHasGoBuildInfo(m), false);
});

test("isGoModule: looks the module up by name, caches per name+base, unknown module is false", () => {
    const image = fakePe(0);
    let lookups = 0, reads = 0;
    const base = ptrInto(image);
    const counted = { ...base, readByteArray: (n: number) => { reads++; return base.readByteArray(n); }, add: base.add };
    const saved = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => {
        lookups++;
        return name === "go.exe" ? { name, base: counted, size: image.length } : null;
    };
    try {
        resetGoModuleCache();
        assert.equal(isGoModule("go.exe"), true);
        const readsAfterFirst = reads;
        assert.equal(isGoModule("go.exe"), true);
        assert.equal(reads, readsAfterFirst, "second call answered from the cache");
        assert.equal(isGoModule("missing.dll"), false);
        assert.equal(lookups, 3);
    } finally {
        G.Process.findModuleByName = saved;
        resetGoModuleCache();
    }
});

// ---- registry rows -------------------------------------------------------------------------

const noopHook = () => {};

function goRows(platform: any, extra: object = {}): HookRegistry {
    const reg = new HookRegistry();
    reg.registerAll([
        { platform, pattern: /.*libssl\.so/, hookFn: noopHook, library: "OpenSSL", libraryType: "openssl", protocol: "tls" },
        { platform, pattern: /.*/, contentFilter: (name: string) => name === "goapp" || name === "libgo.dylib", hookFn: noopHook, library: "Go TLS", libraryType: "gotls", protocol: "tls", ...extra },
    ] as any);
    return reg;
}

test("contentFilter: a catch-all row matches exactly the modules its predicate accepts", () => {
    const reg = goRows(PLATFORM_DARWIN);
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "goapp", "/tmp/goapp", "tls").map((h) => h.library), ["Go TLS"]);
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "libgo.dylib", undefined, "tls").map((h) => h.library), ["Go TLS"]);
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "curl", "/usr/bin/curl", "tls"), []);
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "libssl.so", undefined, "tls").map((h) => h.library), ["OpenSSL"]);
    assert.equal(reg.findByLibraryType(PLATFORM_DARWIN, "gotls")?.library, "Go TLS");
});

test("contentFilter fails closed on a throw, and runs only after the name gates", () => {
    let calls = 0;
    const reg = goRows(PLATFORM_WINDOWS, {
        excludePattern: /^skip\.exe$/,
        contentFilter: (name: string) => { calls++; if (name === "boom.exe") throw new Error("x"); return true; },
    });
    assert.deepEqual(reg.findAllMatches(PLATFORM_WINDOWS, "boom.exe", undefined, "tls"), []);
    assert.deepEqual(reg.findAllMatches(PLATFORM_WINDOWS, "skip.exe", undefined, "tls"), []);
    assert.equal(calls, 1, "excludePattern short-circuits before the content check");
    assert.deepEqual(reg.findAllMatches(PLATFORM_WINDOWS, "go.exe", undefined, "tls").map((h) => h.library), ["Go TLS"]);
});

test("contentFilter rows obey the protocol filter like any row", () => {
    const reg = goRows(PLATFORM_DARWIN);
    assert.deepEqual(reg.findAllMatches(PLATFORM_DARWIN, "goapp", undefined, "ssh"), []);
});

test("Linux: the content row excludes exactly the names the two name-based Go rows match (no double hook)", () => {
    const reg = new HookRegistry();
    const always = () => true;
    reg.registerAll([
        { platform: PLATFORM_LINUX, pattern: /.*\.go.so$/, hookFn: noopHook, library: "Go TLS (name .go.so)", libraryType: "gotls", protocol: "tls" },
        { platform: PLATFORM_LINUX, pattern: /.*go[0-9.]+$/, hookFn: noopHook, library: "Go TLS (name goN)", libraryType: "gotls", protocol: "tls" },
        { platform: PLATFORM_LINUX, pattern: /.*/, excludePattern: GO_LINUX_NAMED_MODULE, contentFilter: always, hookFn: noopHook, library: "Go TLS (content)", libraryType: "gotls", protocol: "tls" },
    ] as any);
    for (const name of ["app_full.go1.21", "app.go1.24", "libfoo.go.so", "caddy", "libgojni.so", "my-go-tool"]) {
        const matches = reg.findAllMatches(PLATFORM_LINUX, name, `/opt/${name}`, "tls");
        assert.equal(matches.length, 1, `${name}: exactly one Go row, got ${matches.map((m) => m.library)}`);
    }
});

test("platform agents register the content-detected Go TLS row in both hook paths", () => {
    for (const [file, legacy, modern] of [
        ["platforms/macos.ts", "legacy/tls/platforms/macos/gotls_macos.js", "tls/platforms/macos/gotls_macos.js"],
        ["platforms/windows.ts", "legacy/tls/platforms/windows/gotls_windows.js", "tls/platforms/windows/gotls_windows.js"],
        ["platforms/linux.ts", "legacy/tls/platforms/linux/gotls_linux.js", "tls/platforms/linux/gotls_linux.js"],
    ]) {
        const src = readFileSync(join(AGENT, file), "utf8");
        assert.match(src, /pattern: \/\.\*\/,[^\n]*contentFilter: isGoModule, hookFn: \(use_modern \? gotls_execute_modern : gotls_execute\), library: "Go TLS", libraryType: "gotls", protocol: "tls"/, file);
        assert.ok(src.includes(`from "../${legacy}"`), `${file} imports the legacy Go executor`);
        assert.ok(src.includes(`from "../${modern}"`), `${file} imports the modern Go executor`);
    }
});
