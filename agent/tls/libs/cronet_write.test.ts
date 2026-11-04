// Unit tests for the modern Cronet SSL_read/SSL_write plaintext hooks
// (agent/tls/libs/cronet.ts).
//
// Run: npm run test:agent
//
// WHY: the SSL_write hook emitted args[1] with the REQUESTED length (args[2]) from onEnter.
// BoringSSL's SSL_write returns the bytes written (fewer with SSL_MODE_ENABLE_PARTIAL_WRITE)
// or <= 0 (error / WANT_WRITE, retried with the same buffer) — so partial writes and retries
// duplicated plaintext. It now goes through attachPlaintextWriteHook (emit min(len, ret)).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, call, take, takeMessages, addr, mem, int, SOCKET_FNS } from "../../shared/write_hook_fakes.js";

import { Cronet } from "./cronet.js";

installFakes();

const MOD = "libcronet.so";
function hooker(fd: number): { write: Function; read: Function } {
    const h: any = Object.create(Cronet.prototype);
    h.module_name = MOD;
    h.do_read_write_hooks = true;
    h.sessionFns = {};
    h.addresses = { [MOD]: { SSL_write: addr(`m_SSL_write_fd${fd}`), SSL_read: addr(`m_SSL_read_fd${fd}`), ...SOCKET_FNS } };
    h.SSL_get_fd = () => fd;
    h.get_client_random_from_ssl_struct = () => "CR";
    h.install_plaintext_write_hook();
    h.install_plaintext_read_hook();
    return {
        write: (data: any, len: number, ret: number) => call(`m_SSL_write_fd${fd}`, [addr("ssl"), data, int(len)], ret),
        read: (data: any, len: number, ret: number) => call(`m_SSL_read_fd${fd}`, [addr("ssl"), data, int(len)], ret),
    };
}
const { write, read } = hooker(9);

test("a full SSL_write emits the whole buffer once, with its record metadata", () => {
    write(mem("GET /generate_204 HTTP/1.1"), 26, 26);
    const [message] = takeMessages();
    assert.equal(message.function, "SSL_write");
    assert.equal(message.client_random, "CR");
    write(mem("GET / HTTP/1.1"), 14, 14);
    assert.deepEqual(take(), ["GET / HTTP/1.1"]);
});

test("a partial write emits only what was written", () => {
    const body = Buffer.from("A".repeat(16384) + "B".repeat(100));
    write(mem(body), body.length, 16384);
    write(mem(body, 16384), 100, 100);
    assert.deepEqual(take().map((s) => s.length), [16384, 100]);
});

test("WANT_WRITE then the same-buffer retry emits the data once", () => {
    const body = mem("POST /api {\"k\":1}");
    write(body, 17, -1);
    write(body, 17, 17);
    assert.deepEqual(take(), ["POST /api {\"k\":1}"]);
});

test("SSL_read emits the decrypted byte count from retval; errors emit nothing", () => {
    read(mem("HTTP/1.1 204 No Content....garbage"), 4096, 24);
    read(mem("x"), 4096, -1);
    assert.deepEqual(take(), ["HTTP/1.1 204 No Content."]);
});

test("an fd-less SSL is skipped without --enable_default_fd", () => {
    hooker(-1).write(mem("unattributed"), 12, 12);
    assert.deepEqual(take(), []);
});
