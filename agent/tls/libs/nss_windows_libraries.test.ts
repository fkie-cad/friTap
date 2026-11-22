// Unit tests for agent/tls/libs/nss_windows_libraries.ts: which Windows module names
// trigger NSS hooking (nspr4.dll, libnspr4.dll, folded nss3.dll) and where each symbol
// is resolved from (folded vs unfolded layout), shared by the legacy hooker, the modern
// definition and the Windows/Wine platform rows.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    NSS_WINDOWS_MODULE_PATTERN, exportsNsprIo, isNss3ModuleName, nssWindowsAuxiliaryLibraries,
    nssWindowsLibrarySymbols, nssWindowsMethodMapping, resetNsprIoVerdictsForTest,
} from "./nss_windows_libraries.js";

const G = globalThis as any;

/** Frida ApiResolver-style glob (only `*`) -> anchored, case-sensitive RegExp. */
function glob(pattern: string): RegExp {
    return new RegExp("^" + pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$");
}

beforeEach(() => resetNsprIoVerdictsForTest());

test("platform row pattern: NSPR and folded nss3 names match, OpenSSL / other NSS DLLs do not", () => {
    for (const name of ["nspr4.dll", "libnspr4.dll", "NSPR4.DLL", "nss3.dll", "libnss3.dll", "NSS3.dll"]) {
        assert.ok(NSS_WINDOWS_MODULE_PATTERN.test(name), name);
    }
    for (const name of ["libssl-3-x64.dll", "libssl-1_1.dll", "ssl3.dll", "softokn3.dll", "nssutil3.dll",
        "nss3.dll.mui", "freebl3.dll", "libnspr4.so", "libnss3.so"]) {
        assert.ok(!NSS_WINDOWS_MODULE_PATTERN.test(name), name);
    }
});

test("folded nss3.dll resolves every symbol in the hooked module and has no aux libraries", () => {
    assert.equal(isNss3ModuleName("nss3.dll"), true);
    const symbols = nssWindowsLibrarySymbols("nss3.dll");
    for (const s of ["PR_Read", "PR_Write", "PR_GetDescType", "SSL_ImportFD", "SSL_GetExperimentalAPI",
        "NSSSSL_GetVersion", "PK11_ExtractKeyValue", "PK11_GetKeyData"]) {
        assert.ok(symbols.includes(s), s);
    }
    assert.deepEqual(nssWindowsAuxiliaryLibraries("nss3.dll"), []);
});

test("unfolded nspr4.dll: PR_* locally, SSL_* from (lib)ssl3.dll, PK11_* from (lib)nss3.dll", () => {
    for (const nspr of ["nspr4.dll", "libnspr4.dll"]) {
        const local = nssWindowsLibrarySymbols(nspr);
        assert.ok(local.includes("PR_GetDescType"));
        assert.ok(!local.includes("SSL_ImportFD"));
        const aux = nssWindowsAuxiliaryLibraries(nspr);
        const ssl = aux.find((a) => a.symbols.includes("SSL_ImportFD"))!;
        const pk11 = aux.find((a) => a.symbols.includes("PK11_GetKeyData"))!;
        assert.ok(glob(ssl.pattern).test("ssl3.dll") && glob(ssl.pattern).test("libssl3.dll"));
        assert.ok(glob(pk11.pattern).test("nss3.dll") && glob(pk11.pattern).test("libnss3.dll"));
        // The old `*ssl*.dll` glob also matched OpenSSL; the new patterns must not.
        for (const a of aux) {
            for (const openssl of ["libssl-3-x64.dll", "libssl-1_1-x64.dll", "libssl-3.dll"]) {
                assert.ok(!glob(a.pattern).test(openssl), `${a.pattern} vs ${openssl}`);
            }
        }
    }
});

test("legacy method mapping carries PR_GetDescType and the WS2_32 socket helpers", () => {
    const m = nssWindowsMethodMapping("nspr4.dll", "WS2_32.dll");
    assert.ok(m["*nspr4.dll*"].includes("PR_GetDescType"));
    assert.deepEqual(m["*WS2_32.dll*"], ["getpeername", "getsockname", "ntohs", "ntohl"]);
    assert.ok(m["*ssl3.dll"].includes("SSL_GetSessionID"));
    const folded = nssWindowsMethodMapping("nss3.dll", "WS2_32.dll");
    assert.deepEqual(Object.keys(folded).sort(), ["*WS2_32.dll*", "*nss3.dll*"]);
});

test("exportsNsprIo: nspr always; nss3.dll only when it exports PR_Read (folded)", () => {
    const exportsOf: Record<string, string[]> = { "nss3.dll": ["PR_Read", "SSL_ImportFD"], "libnss3.dll": ["PK11_GetKeyData"] };
    const saved = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => exportsOf[name] === undefined ? null : {
        name,
        findExportByName: (sym: string) => exportsOf[name].includes(sym) ? { isNull: () => false } : null,
    };
    try {
        assert.equal(exportsNsprIo("nspr4.dll"), true);
        assert.equal(exportsNsprIo("nss3.dll"), true);       // folded
        assert.equal(exportsNsprIo("libnss3.dll"), false);   // unfolded: hooked via its nspr4.dll
        assert.equal(exportsNsprIo("NSS3.DLL"), false);      // not mapped (yet): false, not cached
        exportsOf["NSS3.DLL"] = ["PR_Read"];
        assert.equal(exportsNsprIo("NSS3.DLL"), true);
    } finally {
        G.Process.findModuleByName = saved;
    }
});

test("exportsNsprIo never throws", () => {
    const saved = G.Process.findModuleByName;
    G.Process.findModuleByName = () => { throw new Error("boom"); };
    try {
        assert.equal(exportsNsprIo("nss3.dll"), false);
    } finally {
        G.Process.findModuleByName = saved;
    }
});
