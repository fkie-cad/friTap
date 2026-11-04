// Unit tests for the wolfSSL_write plaintext hook of both WolfSSL hooker copies
// (agent/legacy/tls/libs/wolfssl.ts: Android; agent/tls/libs/wolfssl.ts: Linux/Windows).
//
// Run: npm run test:agent
//
// WHY: the hook emitted args[1] with the REQUESTED length from onEnter. wolfSSL_write
// returns the bytes written or <= 0 (error / WANT_WRITE, retried by the app with the same
// data), and with SSL_MODE_ENABLE_PARTIAL_WRITE a positive count below the request — so
// the capture duplicated retried data and reported bytes that were never sent.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { installFakes, call, take, addr, mem, int, SOCKET_FNS } from "../../../shared/write_hook_fakes.js";

import { WolfSSL as LegacyWolfSSL } from "./wolfssl.js";
import { WolfSSL as WolfSSL } from "../../../tls/libs/wolfssl.js";

installFakes({ wolfSSL_get_fd: () => 7, wolfSSL_get_session: () => ({ isNull: () => true }) });

for (const [label, Hooker] of [["legacy (Android)", LegacyWolfSSL], ["tls/libs", WolfSSL]] as const) {
    const MOD = `libwolfssl-${label}.so`;
    const hooker: any = Object.create(Hooker.prototype);
    hooker.moduleName = hooker.module_name = MOD;
    hooker.addresses = { [MOD]: { wolfSSL_write: addr(`wolfSSL_write_${label}`), ...SOCKET_FNS } };
    (Hooker as any).wolfSSL_get_fd = () => 7;
    (Hooker as any).getSslSessionId = () => "SID";
    hooker.install_plaintext_write_hook();
    const write = (data: any, len: number, ret: number) => call(`wolfSSL_write_${label}`, [addr("ssl"), data, int(len)], ret);

    test(`${label}: a full write emits the whole buffer once, from onLeave`, () => {
        write(mem("GET / HTTP/1.1\r\n\r\n"), 18, 18);
        assert.deepEqual(take(), ["GET / HTTP/1.1\r\n\r\n"]);
    });

    test(`${label}: a partial write emits only the written prefix; the retry the rest`, () => {
        const body = Buffer.from("0123456789");
        write(mem(body), 10, 4);
        write(mem(body, 4), 6, 6);
        assert.deepEqual(take(), ["0123", "456789"], "every byte exactly once");
    });

    test(`${label}: WANT_WRITE then a retry with the same data emits it once`, () => {
        const body = mem("POST /upload");
        write(body, 12, -1);
        assert.deepEqual(take(), [], "nothing was written yet");
        write(body, 12, 12);
        assert.deepEqual(take(), ["POST /upload"]);
    });

    test(`${label}: a failed write emits nothing`, () => {
        write(mem("lost"), 4, 0);
        write(mem("lost"), 4, -1);
        assert.deepEqual(take(), []);
    });
}
