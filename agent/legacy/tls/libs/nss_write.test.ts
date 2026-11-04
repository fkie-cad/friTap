// Unit tests for the NSS PR_Write plaintext hook of both NSS hooker copies
// (agent/legacy/tls/libs/nss.ts: Android; agent/tls/libs/nss.ts: Linux/Windows/macOS legacy).
//
// Run: npm run test:agent
//
// WHY: the hook checked PR_Write's return value but still emitted `amount` (the requested
// length). PR_Write returns the bytes written or -1 (PR_WOULD_BLOCK_ERROR, retried by the
// app); on a non-blocking socket NSS can accept fewer than `amount` — the app then writes
// the remainder, so the capture duplicated it.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { installFakes, call, take, addr, mem, int } from "../../../shared/write_hook_fakes.js";

import { NSS as LegacyNSS } from "./nss.js";
import { NSS } from "../../../tls/libs/nss.js";

installFakes();

/** PRNetAddr: family@0 = PR_AF_INET, port, 93.184.215.14 (not loopback). */
function prNetAddr(sa: any): number {
    sa.writeU32(0x01bb0002);
    sa.add(4).writeU32(0x0ed7b85d);
    return 0;
}

for (const [label, Hooker] of [["legacy (Android)", LegacyNSS], ["tls/libs", NSS]] as const) {
    const MOD = `libnss3-${label}.so`;
    const H: any = Hooker;
    H.getsockname = (_fd: any, sa: any) => prNetAddr(sa);
    H.getPortsAndAddressesFromNSS = () => ({ src_port: 50000, dst_port: 443 });
    H.getSslSessionIdFromFD = () => "SID";
    H.extractClientRandom = () => "";
    const hooker: any = Object.create(Hooker.prototype);
    hooker.moduleName = hooker.module_name = MOD;
    hooker.addresses = { [MOD]: { PR_Write: addr(`PR_Write_${label}`) } };
    hooker.install_plaintext_write_hook();
    const write = (data: any, amount: number, ret: number) => call(`PR_Write_${label}`, [addr("sslfd"), data, int(amount)], ret);

    test(`${label}: a full PR_Write emits the buffer once`, () => {
        write(mem("GET / HTTP/1.1"), 14, 14);
        assert.deepEqual(take(), ["GET / HTTP/1.1"]);
    });

    test(`${label}: a partial non-blocking write emits only what NSS accepted`, () => {
        const body = Buffer.from("0123456789abcdef");
        write(mem(body), 16, 10);
        write(mem(body, 10), 6, 6);
        assert.deepEqual(take(), ["0123456789", "abcdef"]);
    });

    test(`${label}: PR_WOULD_BLOCK_ERROR (-1) then the retry emits the data once`, () => {
        const body = mem("POST /submit");
        write(body, 12, -1);
        write(body, 12, 12);
        assert.deepEqual(take(), ["POST /submit"]);
    });

    test(`${label}: a non-socket fd (PIPE / file: no INET family) emits nothing`, () => {
        H.getsockname = (_fd: any, sa: any) => { sa.writeU32(0); return -1; };
        try {
            write(mem("pipe data"), 9, 9);
            assert.deepEqual(take(), []);
        } finally {
            H.getsockname = (_fd: any, sa: any) => prNetAddr(sa);
        }
    });

    test(`${label}: a failed write emits nothing`, () => {
        write(mem("x"), 1, -1);
        write(mem("x"), 1, 0);
        assert.deepEqual(take(), []);
    });
}
