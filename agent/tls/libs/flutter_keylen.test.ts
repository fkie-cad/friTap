// Run: npm run test:agent
//
// Flutter.dumpKeys read a fixed 32 bytes, truncating SHA-384 (48-byte) secrets.
// It now takes ssl_log_secret's length, validated by safeKeyLenLogged, and keeps
// 32 only as the fallback. Both agent trees carry their own copy.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
// Entry first: the hooker modules sit in an import cycle with the platform tables.
import "../../fritap_agent.js";
import { Flutter } from "./flutter.js";
import { Flutter as LegacyFlutter } from "../../legacy/tls/libs/flutter.js";

function bytesRead(FlutterClass: any, label: string, len?: number): number[] {
    const reads: number[] = [];
    const hooker: any = Object.create(FlutterClass.prototype);
    hooker.module_name = "libflutter.so";
    hooker.get_client_random_from_ssl_struct = () => "00".repeat(32);
    const labelPtr = { isNull: () => false, readCString: () => label };
    const keyPtr = { isNull: () => false, readByteArray: (n: number) => { reads.push(n); return new Uint8Array(n).buffer; } };
    hooker.dumpKeys(labelPtr, { isNull: () => false }, keyPtr, len);
    return reads;
}

for (const [tree, FlutterClass] of [["modern", Flutter], ["legacy", LegacyFlutter]] as const) {
    test(`${tree} Flutter.dumpKeys reads the claimed 32- and 48-byte secrets`, () => {
        assert.deepEqual(bytesRead(FlutterClass, "CLIENT_TRAFFIC_SECRET_0", 32), [32]);
        assert.deepEqual(bytesRead(FlutterClass, "SERVER_TRAFFIC_SECRET_0", 48), [48]);
    });

    test(`${tree} Flutter.dumpKeys falls back to 32 for an invalid or absent length`, () => {
        assert.deepEqual(bytesRead(FlutterClass, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 0xdeadbeef), [32]);
        assert.deepEqual(bytesRead(FlutterClass, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 0), [32]);
        assert.deepEqual(bytesRead(FlutterClass, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"), [32]);
    });
}
