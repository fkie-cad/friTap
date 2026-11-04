// agent/shared/write_hook_fakes.ts
//
// Fake native world for the plaintext write-hook unit tests (agent/legacy/tls/libs/
// *_write.test.ts): Interceptor.attach records each listener by address, send() records
// datalog records, getpeername/getsockname answer a fixed IPv4 5-tuple. A hooked call is
// replayed with call(): onEnter(args) then onLeave(retval) on one fresh invocation context,
// exactly as Frida drives them. Import AFTER ./frida-test-stubs.js. Test-only module.

import { setPcapEnabled } from "./shared_structures.js";
// Load the module graph from the agent entry, as Frida does: a hooker class imported first
// re-enters its own module via the platform files (TDZ on `class X_Android extends X`).
import "../fritap_agent.js";

const G = globalThis as any;

/** A non-NULL pointer identified by name (hook targets, SSL/session objects). */
export function addr(name: string): any {
    return { name, isNull: () => false, toString: () => `0x${name}`, equals: (o: any) => o?.name === name };
}

/** Readable/writable fake memory over `buf` (a plaintext buffer, a sockaddr, ...). */
export function mem(buf: Buffer | string, off = 0): any {
    const bytes = typeof buf === "string" ? Buffer.from(buf) : buf;
    const p: any = {
        isNull: () => false,
        add: (n: number) => mem(bytes, off + Number(n)),
        readU8: () => bytes.readUInt8(off),
        readU16: () => bytes.readUInt16LE(off),
        readU32: () => bytes.readUInt32LE(off),
        writeU32: (v: number) => { bytes.writeUInt32LE(v >>> 0, off); return p; },
        // A copy, like Frida's readByteArray (the app may reuse its buffer afterwards).
        readByteArray: (n: number) => new Uint8Array(bytes.subarray(off, off + Number(n))).buffer,
        toString: () => `mem+${off}`,
    };
    return p;
}

export const NULL_PTR: any = {
    isNull: () => true, toString: () => "0x0", toInt32: () => 0, toUInt32: () => 0,
    readByteArray: () => { throw new Error("access violation accessing 0x0"); },
};

/** An integer register/argument/return value (toInt32 sign-extends, toUInt32 does not). */
export function int(n: number): any {
    return {
        toInt32: () => n | 0, toUInt32: () => n >>> 0, isNull: () => n === 0,
        toString: () => (n < 0 ? `0x${(BigInt(n) & 0xffffffffffffffffn).toString(16)}` : `0x${n.toString(16)}`),
    };
}

const listeners = new Map<string, any>();
const sent: Array<{ message: any; data: Buffer }> = [];

/** The listener attached at `name` (the last one, if attached twice). */
export function listener(name: string): any {
    const l = listeners.get(`0x${name}`);
    if (!l) throw new Error(`no listener attached at ${name}`);
    return l;
}

/** Replay one hooked call: onEnter(args), then onLeave(retval), on one invocation context. */
export function call(name: string, args: any[], retval: number, context: any = {}): void {
    const hook = listener(name);
    const invocation: any = { context };
    hook.onEnter?.call(invocation, args);
    hook.onLeave?.call(invocation, int(retval));
}

/** The plaintext of every datalog record emitted since the last take(). */
export function take(): string[] {
    return sent.splice(0, sent.length).map((r) => r.data.toString());
}

/** The metadata of every datalog record emitted since the last take(). */
export function takeMessages(): any[] {
    return sent.splice(0, sent.length).map((r) => r.message);
}

/** Socket helpers resolved by the hooker classes (getPortsAndAddresses). */
export const SOCKET_FNS = {
    getpeername: addr("getpeername"), getsockname: addr("getsockname"),
    ntohs: addr("ntohs"), ntohl: addr("ntohl"),
};

function writeSockaddrIn(sa: any, port: number): void {
    const b = Buffer.alloc(16);
    b.writeUInt16LE(2, 0); // AF_INET, Linux layout (Process.platform = "linux")
    b.writeUInt16BE(port, 2);
    Buffer.from([93, 184, 215, 14]).copy(b, 4);
    for (let i = 0; i < 16; i += 4) sa.add(i).writeU32(b.readUInt32LE(i));
}

/** NativeFunction(target) -> fake by target name; anything else returns `fallback`. */
export function installFakes(natives: Record<string, (...a: any[]) => any> = {}): void {
    const impl: Record<string, (...a: any[]) => any> = {
        getpeername: (_fd: number, sa: any) => { writeSockaddrIn(sa, 443); return 0; },
        getsockname: (_fd: number, sa: any) => { writeSockaddrIn(sa, 50000); return 0; },
        ntohs: (v: number) => v,
        ntohl: (v: number) => v,
        ...natives,
    };
    G.Interceptor.attach = (target: any, callbacks: any) => {
        listeners.set(String(target), callbacks);
        return { detach: () => { } };
    };
    G.NativeFunction = function (target: any) {
        return (target && impl[target.name]) ?? (() => 0);
    };
    G.Memory.alloc = (size: number) => mem(Buffer.alloc(Math.max(Number(size), 16)));
    G.send = (message: any, data?: any) => {
        if (message?.contentType === "datalog") sent.push({ message, data: Buffer.from(data) });
    };
    setPcapEnabled(true);
}
