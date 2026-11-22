// Unit tests for the Windows-relevant NSS changes in agent/tls/libs/nss.ts:
//   - the plaintext helpers (getDescType / PR_GetNameForIdentity) are bound at
//     construction and an unbound PR_GetDescType no longer throws in PR_Read onLeave;
//   - NSPR helpers resolve from the detected module (no hard-coded libnspr4.so/libnss3.so);
//   - the tier-3 offset table is disabled off Linux-LP64 (Windows, 32-bit, PE under Wine);
//   - PR_Read on Windows accepts NSPR's PR_AF_INET6 (23).
//
// Run: npm run test:agent

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { setPlatform } from "../../shared/frida-test-stubs.js";
import { installFakes, call, take, addr, mem } from "../../shared/write_hook_fakes.js";

import { NSS } from "./nss.js";

installFakes();

const G = globalThis as any;
const N: any = NSS;
const savedProcess = { ...G.Process };
const savedPtr = G.ptr;

afterEach(() => {
    G.ptr = savedPtr;
    Object.assign(G.Process, savedProcess);
    setPlatform("linux");
    NSS.setExportScope([]);
    N.cachedVersion = null;
});

let nextBase = 0x10000;

/** Pointer at numeric address `v` over `header` bytes, with the arithmetic isReadable() uses. */
function headerPtr(v: number, header: number[]): any {
    const self: any = {
        v,
        isNull: () => false,
        and: () => self,
        add: (n: number) => headerPtr(v + Number(n), header),
        compare: (o: any) => Math.sign(v - o.v),
        readU16: () => Buffer.from(header).readUInt16LE(0),
        toString: () => `0x${v.toString(16)}`,
    };
    return self;
}

/** A fake module exporting `exports` (name -> fake pointer). */
function fakeModule(name: string, exports: string[], header = [0x7f, 0x45]): any {
    nextBase += 0x10000;
    const base = headerPtr(nextBase, header);
    return { name, base, findExportByName: (sym: string) => exports.includes(sym) ? addr(`${name}!${sym}`) : null };
}

// --- descTypeOf / PR_Read gate --------------------------------------------------------

test("descTypeOf returns -1 instead of throwing when PR_GetDescType is unbound", () => {
    const saved = N.getDescType;
    N.getDescType = undefined;
    try {
        assert.equal(NSS.descTypeOf(addr("fd")), -1);
        N.getDescType = () => 2;
        assert.equal(NSS.descTypeOf(addr("fd")), 2);
    } finally {
        N.getDescType = saved;
    }
});

function installReadHook(mod: string, peer: (sa: any) => void): void {
    G.ptr = (v: any) => v;   // PR_Read onEnter wraps args with ptr(); keep the fake buffers
    N.getpeername = (_fd: any, sa: any) => { peer(sa); return 0; };
    N.getPortsAndAddressesFromNSS = () => ({ src_port: 443, dst_port: 50000 });
    N.getSslSessionIdFromFD = () => "SID";
    N.extractClientRandom = () => "";
    const hooker: any = Object.create(NSS.prototype);
    hooker.moduleName = hooker.module_name = mod;
    hooker.addresses = { [mod]: { PR_Read: addr(`PR_Read_${mod}`) } };
    hooker.install_plaintext_read_hook();
}

const v4Peer = (sa: any) => { sa.writeU32(0x01bb0002); sa.add(4).writeU32(0x0ed7b85d); };

test("PR_Read onLeave with an unbound PR_GetDescType emits the record (was a TypeError per read)", () => {
    const saved = N.getDescType;
    N.getDescType = undefined;
    try {
        installReadHook("nspr4.dll", v4Peer);
        call("PR_Read_nspr4.dll", [addr("fd"), mem("HTTP/1.1 200 OK")], 15);
        assert.deepEqual(take(), ["HTTP/1.1 200 OK"]);
    } finally {
        N.getDescType = saved;
    }
});

test("PR_Read on Windows accepts PR_AF_INET6 = 23 (non-loopback v6 peer)", () => {
    setPlatform("windows");
    const saved = N.getDescType;
    N.getDescType = () => 2;   // PR_DESC_SOCKET_TCP
    try {
        installReadHook("nss3.dll", (sa: any) => {
            sa.writeU32(0xbb010017);                 // family 23, port 443 (BE)
            sa.add(8).writeU32(0xb80d0120);          // 2001:db8::...
            sa.add(20).writeU32(0x01000000);         // ...::1
        });
        call("PR_Read_nss3.dll", [addr("fd"), mem("v6 data")], 7);
        assert.deepEqual(take(), ["v6 data"]);
    } finally {
        N.getDescType = saved;
    }
});

// --- constructor binds the plaintext helpers ------------------------------------------

test("the NSS constructor binds PR_GetDescType / PR_GetNameForIdentity from the module's addresses", () => {
    const savedResolver = G.ApiResolver, savedNF = G.NativeFunction, savedDT = N.getDescType;
    G.ApiResolver = function () {
        return {
            enumerateMatches: (q: string) => {
                const sym = q.split("!")[1];
                return q.startsWith("exports:*nspr4.dll*!") ? [{ name: `nspr4.dll!${sym}`, address: addr(sym) }] : [];
            },
        };
    };
    G.NativeFunction = function (target: any) {
        if (target?.name === "PR_GetDescType") return () => 4;
        if (target?.name === "PR_GetNameForIdentity") return () => "named";
        return () => 0;
    };
    N.getDescType = undefined;
    try {
        new NSS("nspr4.dll", "WS2_32.dll", { "*nspr4.dll*": ["PR_Read", "PR_Write", "PR_GetPeerName", "PR_GetSockName", "PR_GetDescType", "PR_GetNameForIdentity"] });
        assert.equal(NSS.descTypeOf(addr("fd")), 4);
        assert.equal(N.PR_GetNameForIdentity(addr("id")), "named");
    } finally {
        G.ApiResolver = savedResolver;
        G.NativeFunction = savedNF;
        N.getDescType = savedDT;
        installFakes();
    }
});

// --- NSPR exports from the detected module ---------------------------------------------

test("findNsprExport resolves from nspr4.dll / folded nss3.dll, never via a hard-coded .so name", () => {
    G.Process.getModuleByName = (n: string) => { throw new Error(`hard-coded module lookup: ${n}`); };
    G.Process.enumerateModules = () => [
        fakeModule("libssl-3-x64.dll", ["PR_GetIdentitiesLayer"]),   // not NSPR, must be ignored
        fakeModule("nspr4.dll", ["PR_GetIdentitiesLayer", "PR_GetLayersIdentity"]),
    ];
    assert.equal(String(NSS.findNsprExport("PR_GetIdentitiesLayer")), "0xnspr4.dll!PR_GetIdentitiesLayer");
    G.Process.enumerateModules = () => [fakeModule("nss3.dll", ["PR_GetLayersIdentity"])];
    assert.equal(String(NSS.findNsprExport("PR_GetLayersIdentity")), "0xnss3.dll!PR_GetLayersIdentity");
    G.Process.enumerateModules = () => [fakeModule("libnspr4.so", ["PR_GetLayersIdentity"])];
    assert.equal(String(NSS.findNsprExport("PR_GetLayersIdentity")), "0xlibnspr4.so!PR_GetLayersIdentity");
    G.Process.enumerateModules = () => [];
    assert.equal(NSS.findNsprExport("PR_GetLayersIdentity"), null);
});

test("getSSL_Layer returns -1 (no throw) when no NSPR module exports PR_GetIdentitiesLayer", () => {
    G.Process.getModuleByName = (n: string) => { throw new Error(`hard-coded module lookup: ${n}`); };
    G.Process.enumerateModules = () => [];
    assert.equal(NSS.getSSL_Layer(addr("fd")), -1);
});

// --- tier-3 table ABI gate -------------------------------------------------------------

function tableAllowed(): boolean {
    N.cachedVersion = 3100;          // inside the verified version range
    N.tableDisabledLogged = true;
    return NSS.structReadsAllowed();
}

test("tier-3 struct reads stay allowed on Linux LP64 for NSS < 3.115", () => {
    assert.equal(NSS.tableAbiMismatch(), null);
    assert.equal(tableAllowed(), true);
});

test("tier-3 struct reads are disabled on Windows (LLP64) and for 32-bit processes", () => {
    setPlatform("windows");
    assert.match(String(NSS.tableAbiMismatch()), /LLP64/);
    assert.equal(tableAllowed(), false);
    setPlatform("linux");
    G.Process.pointerSize = 4;
    assert.match(String(NSS.tableAbiMismatch()), /pointer size 4/);
    assert.equal(tableAllowed(), false);
});

test("tier-3 struct reads are disabled for a PE NSS module under Wine (platform linux)", () => {
    NSS.setExportScope([fakeModule("nss3.dll", [], [0x4d, 0x5a])]);   // "MZ"
    assert.match(String(NSS.tableAbiMismatch()), /PE/);
    assert.equal(tableAllowed(), false);
    NSS.setExportScope([fakeModule("libnss3.so", [])]);                // ELF
    assert.equal(tableAllowed(), true);
});

// --- Wine: PE NSPR reports PR_AF_INET6 = 23 on Process.platform "linux" ----------------

const v6Peer23 = (sa: any) => {
    sa.writeU32(0xbb010017);                 // family 23, port 443 (BE)
    sa.add(8).writeU32(0xb80d0120);          // 2001:db8::...
    sa.add(20).writeU32(0x01000000);         // ...::1
};

function withDescSocket(fn: () => void): void {
    const saved = N.getDescType;
    N.getDescType = () => 2;   // PR_DESC_SOCKET_TCP
    try { fn(); } finally { N.getDescType = saved; }
}

test("PR_Read under Wine (platform linux) accepts family 23 from a PE nss3.dll", () => {
    G.Process.findModuleByName = (n: string) => n === "nss3.dll" ? fakeModule("nss3.dll", [], [0x4d, 0x5a]) : null;
    withDescSocket(() => {
        installReadHook("nss3.dll", v6Peer23);
        call("PR_Read_nss3.dll", [addr("fd"), mem("wine v6")], 7);
        assert.deepEqual(take(), ["wine v6"]);
    });
});

test("PR_Read on darwin still drops family 23 (macOS PR_AF_INET6 is 30)", () => {
    G.Process.findModuleByName = (n: string) => n === "libnspr4.dylib" ? fakeModule("libnspr4.dylib", []) : null;
    setPlatform("darwin");
    try {
        withDescSocket(() => {
            installReadHook("libnspr4.dylib", v6Peer23);
            call("PR_Read_libnspr4.dylib", [addr("fd"), mem("native")], 6);
            assert.deepEqual(take(), []);
        });
    } finally {
        setPlatform("linux");
    }
});

// installReadHook() replaces the static with a stub; keep the real one (captured at module load).
const realGetPortsAndAddresses = NSS.getPortsAndAddressesFromNSS.bind(NSS);

test("getPortsAndAddressesFromNSS decodes family 23 as AF_INET6 off darwin (Wine reports linux)", () => {
    const savedFns = N._cachedSocketFns;
    const savedAlloc = G.Memory.alloc;
    G.Memory.alloc = (n: number) => mem(Buffer.alloc(Number(n)));
    const peer = (_fd: any, sa: any) => { v6Peer23(sa); return 0; };
    N._cachedSocketFns = { getpeername: peer, getsockname: peer, ntohs: (v: number) => v, ntohl: (v: number) => v };
    try {
        const m = realGetPortsAndAddresses(addr("fd"), true, {}, false);
        assert.equal(m["ss_family"], "AF_INET6");
        assert.equal(m["dst_port"], 443);
        assert.equal(m["dst_addr"], "20010DB8000000000000000000000001");
        setPlatform("darwin");
        assert.throws(() => realGetPortsAndAddresses(addr("fd"), true, {}, false));   // darwin: 23 is not v6
        setPlatform("linux");
    } finally {
        N._cachedSocketFns = savedFns;
        G.Memory.alloc = savedAlloc;
    }
});

// --- nssExportFinder: one loaded-module snapshot per install ---------------------------

test("nssExportFinder: export scope first, then ONE lazy enumeration reused for every lookup", () => {
    const scope = fakeModule("libxul.so", ["SSL_ImportFD"]);
    const nss3 = fakeModule("libnss3.so", ["PR_Close", "PK11_GenerateRandom", "NSS_GetVersion"]);
    let enumerations = 0;
    G.Process.enumerateModules = () => { enumerations++; return [nss3, fakeModule("libc.so.6", ["PR_Close"])]; };
    NSS.setExportScope([scope]);
    const find = NSS.nssExportFinder();
    assert.equal(String(find("SSL_ImportFD")), "0xlibxul.so!SSL_ImportFD");
    assert.equal(enumerations, 0, "a scope hit enumerates nothing");
    assert.equal(String(find("PR_Close")), "0xlibnss3.so!PR_Close");
    assert.equal(String(find("PK11_GenerateRandom")), "0xlibnss3.so!PK11_GenerateRandom");
    assert.equal(find("SSL_GetExperimentalAPI"), null);
    assert.equal(String(find("NSS_GetVersion")), "0xlibnss3.so!NSS_GetVersion");
    assert.equal(enumerations, 1);
    assert.equal(String(NSS.findNssExport("PR_Close")), "0xlibnss3.so!PR_Close");   // same answer per name
});
