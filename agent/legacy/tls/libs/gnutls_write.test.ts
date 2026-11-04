// Unit tests for the gnutls_record_send plaintext hook: both GnuTLS hooker copies
// (agent/legacy/tls/libs/gnutls.ts: Android; agent/tls/libs/gnutls.ts: Linux/Windows/macOS
// legacy) and the modern definition (tls/definitions/gnutls.ts via core/executors).
//
// Run: npm run test:agent
//
// WHY: the legacy hooks emitted the REQUESTED size from onEnter. gnutls_record_send sends
// at most one record and returns its length, or a negative error. On GNUTLS_E_AGAIN /
// GNUTLS_E_INTERRUPTED the record is already encrypted and buffered, and the caller must
// retry with the same arguments OR with data=NULL, size=0 — so the old hooks duplicated
// every retried record, and an executor emitting from the retry's own buffer lost the
// NULL-flushed one.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { installFakes, call, take, addr, mem, int, NULL_PTR, SOCKET_FNS } from "../../../shared/write_hook_fakes.js";

import { GnuTLS as LegacyGnuTLS } from "./gnutls.js";
import { GnuTLS } from "../../../tls/libs/gnutls.js";
import { createGnuTlsDefinition } from "../../../tls/definitions/gnutls.js";
import { installWriteHook } from "../../../core/executors/read_write.js";
import { GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED } from "../../../shared/write_length.js";

installFakes();

const GNUTLS_E_INVALID_SESSION = -10;

function legacyHook(label: string, Hooker: any): void {
    const MOD = `libgnutls-${label}.so`;
    const hooker: any = Object.create(Hooker.prototype);
    hooker.moduleName = hooker.module_name = MOD;
    hooker.addresses = { [MOD]: { gnutls_record_send: addr(`send_${label}`), ...SOCKET_FNS } };
    Hooker.gnutls_transport_get_int = () => 5;
    Hooker.getSslSessionId = () => "SID";
    hooker.install_plaintext_write_hook();
}

function modernHook(label: string): void {
    const MOD = "libgnutls-modern.so";
    const addresses = { [MOD]: { gnutls_record_send: addr(`send_${label}`), ...SOCKET_FNS } };
    const fns: any = { gnutls_transport_get_int: () => 5, gnutls_session_get_id: () => -1 };
    installWriteHook(createGnuTlsDefinition(), addresses, MOD, fns, false);
}

const variants: Array<[string, () => void]> = [
    ["legacy (Android)", () => legacyHook("legacy (Android)", LegacyGnuTLS)],
    ["tls/libs", () => legacyHook("tls/libs", GnuTLS)],
    ["modern definition", () => modernHook("modern definition")],
];

for (const [label, install] of variants) {
    install();
    const send = (session: string, data: any, size: number, ret: number) =>
        call(`send_${label}`, [addr(session), data, int(size)], ret);

    test(`${label}: a successful send emits min(size, retval) bytes once`, () => {
        send("s1", mem("hello"), 5, 5);
        const big = Buffer.alloc(20000, 0x61);
        send("s1", mem(big), big.length, 16384); // one record of a larger request
        send("s1", mem(big, 16384), big.length - 16384, big.length - 16384);
        assert.deepEqual(take().map((s) => s.length), [5, 16384, 20000 - 16384]);
    });

    test(`${label}: E_AGAIN then a retry with the same arguments emits the record once`, () => {
        const body = mem("GET /index.html");
        send("s2", body, 15, GNUTLS_E_AGAIN);
        send("s2", body, 15, GNUTLS_E_AGAIN);
        assert.deepEqual(take(), [], "nothing is on the wire yet");
        send("s2", body, 15, 15);
        assert.deepEqual(take(), ["GET /index.html"]);
    });

    test(`${label}: E_AGAIN / E_INTERRUPTED then a NULL/0 flush emits the buffered record`, () => {
        send("s3", mem("PUT /blob 1234"), 14, GNUTLS_E_INTERRUPTED);
        send("s3", NULL_PTR, 0, GNUTLS_E_AGAIN);
        send("s3", NULL_PTR, 0, 14);
        send("s3", mem("next"), 4, 4);
        assert.deepEqual(take(), ["PUT /blob 1234", "next"]);
    });

    test(`${label}: a hard error emits nothing and leaves no stale record behind`, () => {
        send("s4", mem("never sent"), 10, GNUTLS_E_AGAIN);
        send("s4", NULL_PTR, 0, GNUTLS_E_INVALID_SESSION);
        send("s4", mem("other"), 5, 5);
        assert.deepEqual(take(), ["other"]);
    });

    test(`${label}: pending records are per session`, () => {
        send("a", mem("from A"), 6, GNUTLS_E_AGAIN);
        send("b", mem("from B"), 6, 6);
        send("a", NULL_PTR, 0, 6);
        assert.deepEqual(take(), ["from B", "from A"]);
    });
}
