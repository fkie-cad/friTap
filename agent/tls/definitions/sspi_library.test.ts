// Message-shape tests for the SSPI/Schannel plaintext records (both hook trees):
// every record carries the hooked module (secur32.dll / sspicli.dll) as its `library`.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, call, takeMessages, take, addr } from "../../shared/write_hook_fakes.js";

import { createSspiDefinition } from "./sspi.js";
import { SSPI_Windows } from "../../legacy/tls/platforms/windows/sspi.js";

installFakes();

const SECBUFFER_TYPE_DATA = 1;
const SECBUFFER_TYPE_TOKEN = 2;
const MODULE = "secur32.dll";

interface FakeSecBuffer {
    type: number;
    data: string;
}

/** A readable fake of one SecBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; }. */
function fakeSecBuffer(buffer: FakeSecBuffer): any {
    const bytes = Buffer.from(buffer.data);
    const pvBuffer = {
        isNull: () => false,
        readByteArray: (n: number) => new Uint8Array(bytes.subarray(0, Number(n))).buffer,
    };
    const fields: Record<number, any> = {
        0: { readU32: () => bytes.length, readULong: () => bytes.length },
        4: { readU32: () => buffer.type, readULong: () => buffer.type },
        8: { readPointer: () => pvBuffer },
    };
    return { add: (offset: number) => fields[offset] };
}

/** A fake SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers; } (64-bit stride 16). */
function fakeSecBufferDesc(buffers: FakeSecBuffer[]): any {
    const stride = 16;
    const pBuffers = { add: (offset: number) => fakeSecBuffer(buffers[Number(offset) / stride]) };
    const fields: Record<number, any> = {
        4: { readU32: () => buffers.length, readULong: () => buffers.length },
        8: { readPointer: () => pBuffers },
    };
    return { add: (offset: number) => fields[offset] };
}

const SSPI_ADDRESSES = { [MODULE]: { DecryptMessage: addr("decrypt"), EncryptMessage: addr("encrypt") } };

/** DecryptMessage(phContext, pMessage, ...) then EncryptMessage(phContext, fQOP, pMessage, ...). */
function replayDecryptAndEncrypt(): void {
    const token = { type: SECBUFFER_TYPE_TOKEN, data: "hdr" };
    call("decrypt", [addr("ctx"), fakeSecBufferDesc([token, { type: SECBUFFER_TYPE_DATA, data: "inbound" }])], 0);
    call("encrypt", [addr("ctx"), 0, fakeSecBufferDesc([token, { type: SECBUFFER_TYPE_DATA, data: "outbound" }])], 0);
}

/** Legacy hooks without the constructor (it resolves real exports); they need only these two fields. */
function installLegacySspiHooks(): void {
    const hooker = Object.create(SSPI_Windows.prototype) as SSPI_Windows;
    hooker.addresses = SSPI_ADDRESSES;
    hooker.module_name = MODULE;
    hooker.install_plaintext_read_hook();
    hooker.install_plaintext_write_hook();
}

test("modern SSPI definition: both directions stamp the hooked module as the library", () => {
    const keylog = createSspiDefinition().keylog;
    assert.equal(keylog.kind, "custom");
    (keylog as any).install(SSPI_ADDRESSES, MODULE, {}, false);
    replayDecryptAndEncrypt();
    const messages = takeMessages();
    assert.deepEqual(messages.map((m) => [m.function, m.library]),
        [["DecryptMessage", MODULE], ["EncryptMessage", MODULE]]);
});

test("legacy SSPI_Windows: only SECBUFFER_DATA buffers are emitted", () => {
    installLegacySspiHooks();
    replayDecryptAndEncrypt();
    assert.deepEqual(take(), ["inbound", "outbound"], "only SECBUFFER_DATA is emitted");
});

test("legacy SSPI_Windows: both directions stamp the hooked module as the library (metadata)", () => {
    installLegacySspiHooks();
    replayDecryptAndEncrypt();
    const messages = takeMessages();
    assert.deepEqual(messages.map((m) => [m.function, m.library]),
        [["DecryptMessage", MODULE], ["EncryptMessage", MODULE]]);
});
