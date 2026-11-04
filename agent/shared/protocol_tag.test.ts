// Unit tests for the outgoing-message protocol tag (agent/shared/shared_structures.ts).
//
// Run: npm run test:agent  (node --import tsx --test agent/shared/protocol_tag.test.ts)
//
// `--protocol auto|all` is a hook SELECTION, not a protocol: no message may be
// tagged "auto"/"all". Under a meta selection the hook's own protocol is used;
// under a concrete selection the historical "selected protocol wins" rule holds.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { resolveProtocolTag, sendWithProtocol, setSelectedProtocol } from "./shared_structures.js";
import { runWithRecordProtocol } from "./record_protocol.js";

const G = globalThis as any;

test("resolveProtocolTag: concrete selection wins over the hook's protocol", () => {
    assert.equal(resolveProtocolTag("tls"), "tls");
    assert.equal(resolveProtocolTag("signal", "tls"), "signal");
    assert.equal(resolveProtocolTag("ssh", "ssh"), "ssh");
});

test("resolveProtocolTag: meta selection uses the hook's protocol, else tls", () => {
    assert.equal(resolveProtocolTag("auto", "ssh"), "ssh");
    assert.equal(resolveProtocolTag("all", "ipsec"), "ipsec");
    assert.equal(resolveProtocolTag("auto"), "tls");
    assert.equal(resolveProtocolTag("auto", ""), "tls");
    assert.equal(resolveProtocolTag("auto", "auto"), "tls");
});

test("sendWithProtocol never stamps a meta selection", () => {
    const sent: any[] = [];
    const previous = G.send;
    G.send = (msg: any) => { sent.push(msg); };
    try {
        setSelectedProtocol("auto");
        sendWithProtocol({ contentType: "datalog" });
        runWithRecordProtocol("ssh", () => sendWithProtocol({ contentType: "datalog" }));
        // A message cannot declare its own protocol; only the bound hook can.
        sendWithProtocol({ contentType: "datalog", protocol: "ssh" });
        setSelectedProtocol("tls");
        runWithRecordProtocol("ssh", () => sendWithProtocol({ contentType: "datalog" }));
    } finally {
        G.send = previous;
        setSelectedProtocol("tls");
    }
    assert.deepEqual(sent.map((m) => m.protocol), ["tls", "ssh", "tls", "tls"]);
});
