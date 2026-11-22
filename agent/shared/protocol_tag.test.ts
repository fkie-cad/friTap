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
import {
    activeQuicProtocolTag,
    quicProtocolTag,
    resolveProtocolTag,
    sendConnectionLifecycle,
    sendQuicConnectionLifecycle,
    sendQuicDatalog,
    sendWithProtocol,
    setSelectedProtocol,
} from "./shared_structures.js";
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

test("quicProtocolTag: QUIC records are tagged quic wherever they would be tls", () => {
    assert.equal(quicProtocolTag("tls"), "quic");
    assert.equal(quicProtocolTag("auto"), "quic");
    assert.equal(quicProtocolTag("all", "tls"), "quic");
    assert.equal(quicProtocolTag("signal", "tls"), "signal");
});

function capturedProtocols(selection: string, emit: () => void): string[] {
    const sent: any[] = [];
    const previous = G.send;
    G.send = (msg: any) => { sent.push(msg); };
    try {
        setSelectedProtocol(selection);
        emit();
    } finally {
        G.send = previous;
        setSelectedProtocol("tls");
    }
    return sent.map((m) => `${m.contentType}:${m.protocol}`);
}

test("sendQuicConnectionLifecycle tags like an explicit activeQuicProtocolTag()", () => {
    for (const selection of ["tls", "auto", "all", "quic"]) {
        const viaWrapper = capturedProtocols(selection, () => {
            sendQuicConnectionLifecycle("destroyed", { ssl_session_id: "0x1" });
        });
        const explicit = capturedProtocols(selection, () => {
            sendConnectionLifecycle("destroyed", { ssl_session_id: "0x1" }, activeQuicProtocolTag());
        });
        assert.deepEqual(viaWrapper, explicit, selection);
    }
    assert.deepEqual(capturedProtocols("tls", () => {
        sendQuicConnectionLifecycle("created", { ssl_session_id: "0x1" });
    }), ["connection_lifecycle:quic"]);
});

test("QUIC data and lifecycle share the quic tag; TLS lifecycle stays tls", () => {
    for (const selection of ["tls", "auto", "all"]) {
        assert.deepEqual(capturedProtocols(selection, () => {
            sendConnectionLifecycle("created", { ssl_session_id: "0x1" }, activeQuicProtocolTag());
            sendQuicDatalog({ ssl_session_id: "0x1" }, [1, 2], 0, undefined, undefined, "udp", undefined, "stream");
            sendConnectionLifecycle("created", { ssl_session_id: "0x2" });
        }), ["connection_lifecycle:quic", "datalog:quic", "connection_lifecycle:tls"], selection);
    }
});

test("sendQuicDatalog stamps quic_midstream only when asked", () => {
    const previous = G.send;
    const sent: any[] = [];
    G.send = (msg: any) => { sent.push(msg); };
    try {
        sendQuicDatalog({ ssl_session_id: "0x1" }, [1], 0, undefined, undefined, "udp", undefined, "stream", true);
        sendQuicDatalog({ ssl_session_id: "0x1" }, [1], 4, undefined, undefined, "udp", undefined, "stream", false);
        sendQuicDatalog({ ssl_session_id: "0x1" }, [1], 8, undefined, undefined, "udp", undefined, "stream");
    } finally {
        G.send = previous;
    }
    assert.deepEqual(sent.map((m) => m.quic_midstream), [true, undefined, undefined]);
});
