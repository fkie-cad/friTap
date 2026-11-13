// Unit tests for the legacy (Android) Cronet SSL_write plaintext hook
// (agent/legacy/tls/libs/cronet.ts).
//
// Run: npm run test:agent
//
// WHY: the hook emitted args[1] with the REQUESTED length from onEnter. BoringSSL's
// SSL_write returns the bytes written (fewer with SSL_MODE_ENABLE_PARTIAL_WRITE) or <= 0
// (error / WANT_WRITE, retried with the same buffer, whose earlier-committed bytes the
// successful retry then counts) — so retries duplicated plaintext.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { installFakes, call, take, takeMessages, addr, mem, int, SOCKET_FNS } from "../../../shared/write_hook_fakes.js";

import { Cronet } from "./cronet.js";

installFakes();

const MOD = "libcronet.so";
function hooker(fd: number, structCr = "", ssl = "ssl"): any {
    const h: any = Object.create(Cronet.prototype);
    h.moduleName = h.module_name = MOD;
    h.do_read_write_hooks = true;
    h.addresses = { [MOD]: { SSL_write: addr(`SSL_write_fd${fd}`), ...SOCKET_FNS } };
    h.SSL_get_fd = () => fd;
    h.getSslSessionId = () => "SID";
    h.get_client_random_from_ssl_struct = () => structCr;
    h.install_plaintext_write_hook();
    return (data: any, len: number, ret: number) => call(`SSL_write_fd${fd}`, [addr(ssl), data, int(len)], ret);
}
const write = hooker(9);

test("a full SSL_write emits the whole buffer once, from onLeave", () => {
    write(mem("GET /generate_204 HTTP/1.1"), 26, 26);
    assert.deepEqual(take(), ["GET /generate_204 HTTP/1.1"]);
});

test("a partial write (SSL_MODE_ENABLE_PARTIAL_WRITE) emits only what was written", () => {
    const body = Buffer.from("A".repeat(16384) + "B".repeat(100));
    write(mem(body), body.length, 16384);
    write(mem(body, 16384), 100, 100);
    assert.deepEqual(take().map((s) => s.length), [16384, 100]);
});

test("WANT_WRITE then the same-buffer retry emits the data once", () => {
    const body = mem("POST /api {\"k\":1}");
    write(body, 17, -1);
    write(body, 17, -1);
    write(body, 17, 17);
    assert.deepEqual(take(), ["POST /api {\"k\":1}"]);
});

test("errors emit nothing; an fd-less SSL is skipped without --enable_default_fd", () => {
    write(mem("x"), 1, 0);
    hooker(-1)(mem("unattributed"), 12, 12);
    assert.deepEqual(take(), []);
});

// I2.1 option 5: before, every fd-less record was dropped without --enable_default_fd. One
// whose client_random is known is now kept WITHOUT address fields (the host assigns each
// client_random its own synthetic tuple); the test above still covers the no-cr drop.
test("an fd-less SSL with a known client_random is emitted without address fields", () => {
    const cr = "C0FFEE00".repeat(8);
    hooker(-1, cr, "ssl_with_cr")(mem("endpointless"), 12, 12);
    const [message, ...rest] = takeMessages();
    assert.equal(rest.length, 0);
    assert.equal(message.function, "SSL_write");
    assert.equal(message.client_random, cr.toLowerCase());
    assert.equal(message.library, MOD);
    assert.equal(message.ssl_session_id, "SID");
    for (const field of ["src_addr", "dst_addr", "src_port", "dst_port", "ss_family"]) {
        assert.equal(field in message, false, `${field} on an endpointless record`);
    }
});
