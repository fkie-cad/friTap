// Unit tests for getPortsAndAddresses (shared/shared_functions.ts): the getsockname /
// getpeername return codes and the --enable_default_fd placeholder tuple (I2.1 items 2, 4).
//
// Run: npm run test:agent
//
// WHY: the return codes were ignored. On a closed, reused or not-yet-connected fd (or fd -1)
// the call failed and the shared sockaddr buffer, still holding the PREVIOUS call's address,
// was decoded: a record got another connection's tuple. And the -ed placeholder tuple was
// not flipped for reads, so both directions of an fd-less connection looked like writes.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { installFakes, SOCKET_FNS } from "./write_hook_fakes.js";
import { getPortsAndAddresses, defaultFdPlaceholderTuple, isUnwantedFd } from "./shared_functions.js";
import { unwantedFDs } from "./shared_structures.js";

/** Socket fds whose getpeername fails with -1 (ENOTCONN / EBADF) without touching the buffer. */
const failingPeerFds = new Set<number>();

function writeSockaddrIn(sa: any, port: number): void {
    const b = Buffer.alloc(16);
    b.writeUInt16LE(2, 0); // AF_INET, Linux layout
    b.writeUInt16BE(port, 2);
    Buffer.from([93, 184, 215, 14]).copy(b, 4);
    for (let i = 0; i < 16; i += 4) sa.add(i).writeU32(b.readUInt32LE(i));
}

installFakes({
    getpeername: (fd: number, sa: any) => {
        if (failingPeerFds.has(fd)) return -1;
        writeSockaddrIn(sa, 443);
        return 0;
    },
    getsockname: (_fd: number, sa: any) => { writeSockaddrIn(sa, 50000); return 0; },
});

test("a working socket resolves its oriented tuple (write: local -> peer, read: peer -> local)", () => {
    const write = getPortsAndAddresses(5, false, SOCKET_FNS, false);
    assert.deepEqual([write.src_port, write.dst_port, write.ss_family], [50000, 443, "AF_INET"]);
    const read = getPortsAndAddresses(5, true, SOCKET_FNS, false);
    assert.deepEqual([read.src_port, read.dst_port], [443, 50000]);
});

test("a failing getpeername returns null instead of the previous call's stale address", () => {
    failingPeerFds.add(6);
    try {
        getPortsAndAddresses(5, false, SOCKET_FNS, false); // fills the shared buffer
        assert.equal(getPortsAndAddresses(6, false, SOCKET_FNS, false), null);
        assert.equal(unwantedFDs.has(6), false, "a failed lookup may be transient: not blacklisted");
    } finally {
        failingPeerFds.delete(6);
    }
    const recovered = getPortsAndAddresses(6, false, SOCKET_FNS, false);
    assert.equal(recovered.dst_port, 443, "the fd resolves once getpeername succeeds");
});

test("a failing getpeername under --enable_default_fd yields the oriented placeholder, not stale data", () => {
    failingPeerFds.add(8);
    try {
        assert.deepEqual(getPortsAndAddresses(8, true, SOCKET_FNS, true), defaultFdPlaceholderTuple(true));
    } finally {
        failingPeerFds.delete(8);
    }
});

test("fd -1 without --enable_default_fd returns null and is never added to unwantedFDs", () => {
    assert.equal(getPortsAndAddresses(-1, false, SOCKET_FNS, false), null);
    assert.equal(getPortsAndAddresses(-1, true, SOCKET_FNS, false), null);
    assert.equal(unwantedFDs.has(-1), false);
});

test("--enable_default_fd placeholder: writes 1234 -> 2345, reads flipped 2345 -> 1234", () => {
    const write = getPortsAndAddresses(-1, false, SOCKET_FNS, true);
    const read = getPortsAndAddresses(-1, true, SOCKET_FNS, true);
    assert.deepEqual(write, { src_port: 1234, src_addr: 0x7F000001, dst_port: 2345, dst_addr: 0x7F000001, ss_family: "AF_INET" });
    assert.deepEqual(read, { src_port: 2345, src_addr: 0x7F000001, dst_port: 1234, dst_addr: 0x7F000001, ss_family: "AF_INET" });
});

// ── buildRecordMessage on an fd whose getpeername fails: a lookup failure, not an unwanted fd ──

import { buildRecordMessage } from "./record_message.js";

test("isUnwantedFd: only fds marked non-IP are unwanted; a failed lookup is not", () => {
    failingPeerFds.add(21);
    try {
        assert.equal(getPortsAndAddresses(21, false, SOCKET_FNS, false), null);
        assert.equal(isUnwantedFd(21), false, "getpeername failure is transient, never blacklisted");
        unwantedFDs.add(22);
        assert.equal(isUnwantedFd(22), true);
    } finally {
        failingPeerFds.delete(21);
        unwantedFDs.delete(22);
    }
});

test("buildRecordMessage: fd>=0 whose getpeername fails keeps a known client_random as an endpointless record", () => {
    const cr = "cd".repeat(32);
    failingPeerFds.add(23);
    try {
        const ctx = { fd: 23, isRead: false, functionName: "SSL_write", methodAddresses: SOCKET_FNS,
                      enableDefaultFd: false, library: "libssl.so", clientRandom: () => cr };
        const message = buildRecordMessage(ctx, () => ({ ssl_session_id: "S" }));
        assert.notEqual(message, null);
        assert.equal(message.client_random, cr);
        assert.equal("dst_port" in message, false, "no stale or placeholder address fields");
        const noCr = buildRecordMessage({ ...ctx, clientRandom: () => "" }, () => ({}));
        assert.equal(noCr, null, "without a client_random it is still dropped");
    } finally {
        failingPeerFds.delete(23);
    }
});

test("buildRecordMessage: an unwanted (non-IP) fd stays dropped even with a client_random", () => {
    unwantedFDs.add(24);
    try {
        const ctx = { fd: 24, isRead: false, functionName: "SSL_write", methodAddresses: SOCKET_FNS,
                      enableDefaultFd: false, library: "libssl.so", clientRandom: () => "cd".repeat(32) };
        assert.equal(buildRecordMessage(ctx, () => ({})), null);
    } finally {
        unwantedFDs.delete(24);
    }
});
