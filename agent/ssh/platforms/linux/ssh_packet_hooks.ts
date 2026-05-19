/**
 * SSH plaintext capture hooks for OpenSSH on Linux / Android (Termux) / macOS.
 *
 * Strategy
 * --------
 * Primary hook points (post-compression / pre-encryption on send; post-MAC,
 * post-decryption, post-decompression on receive):
 *
 *   int ssh_packet_send2_wrapped(struct ssh *ssh);
 *   int ssh_packet_read_poll2(struct ssh *ssh, u_char *typep);
 *
 * Both are non-static in OpenSSH packet.c since at least 7.6 and present in
 * the dynamic symbol table on standard Debian/Ubuntu/Fedora/Termux builds.
 *
 * Plaintext lives inside `ssh->state->outgoing_packet` (send) and
 * `ssh->state->incoming_packet` (recv) — both `struct sshbuf *`. We never
 * hardcode their offsets within `struct session_state` (those move with
 * `#ifdef WITH_ZLIB` and other compile flags). Instead we probe once per
 * process: scan `state` for two `sshbuf*` slots whose buffers look like a
 * complete SSH binary packet (4-byte big-endian `packet_length` field +
 * 1-byte `padding_length` + payload + padding, matching RFC 4253 §6).
 *
 * Universal fallback when the wrapper symbols are unresolvable (stripped
 * Alpine, custom builds, Magisk modules):
 *
 *   int cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr,
 *                    u_char *dest, const u_char *src,
 *                    u_int len, u_int aadlen, u_int authlen);
 *
 * cipher_crypt is exported in every build we've surveyed. Direction comes
 * from `cc->encrypt` at offset +4 (`plaintext` int at +0, `encrypt` int at
 * +4). The fallback has no `struct ssh *` in scope, so we synthesise the
 * 5-tuple from the same `enable_default_fd` loopback path TLS uses when fd
 * resolution fails (127.0.0.1:1234 ↔ 127.0.0.1:22). This is a documented
 * degraded mode; future work could thread `sshPtr` through thread-local
 * state to recover real socket info.
 *
 * Output: a single `sendDatalog` call per captured packet. Bytes flow
 * through `DatalogEvent` → `PcapngOutputHandler` exactly like TLS — no
 * SSH-specific Python writer is needed for the plaintext PCAPNG.
 */

import { devlog, devlog_error, log } from "../../../util/log.js";
import { sendDatalog } from "../../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../../shared/shared_functions.js";
import { enable_default_fd, pcap_enabled } from "../../../fritap_agent.js";

const ptrSize = Process.pointerSize;
const MAX_SSH_PACKET = 65535;
const MIN_SSH_PACKET = 6; // 4 length + 1 padlen + 1 type byte minimum

interface ModuleHookState {
    sshbufPtrFn: NativeFunction<NativePointer, [NativePointer]> | null;
    sshbufLenFn: NativeFunction<number | UInt64, [NativePointer]> | null;
    connInFn: NativeFunction<number, [NativePointer]> | null;
    connOutFn: NativeFunction<number, [NativePointer]> | null;
    outgoingPacketOffset: number | null;
    incomingPacketOffset: number | null;
    // Socket helpers (getpeername/getsockname/ntohs/ntohl) flat-mapped from
    // readAddresses output. readAddresses writes everything under a single
    // moduleName key (shared_functions.ts:323,370), so this is just an alias
    // to that inner map — no merging needed.
    socketHelpers: { [fn: string]: NativePointer };
}

function looksLikeSshPacketSshbuf(
    sshbufPtr: NativePointer,
    state: ModuleHookState
): boolean {
    if (!state.sshbufPtrFn || !state.sshbufLenFn) return false;
    try {
        if (sshbufPtr.isNull()) return false;
        const len = Number((state.sshbufLenFn as any)(sshbufPtr));
        if (len < MIN_SSH_PACKET || len > MAX_SSH_PACKET) return false;
        const data = (state.sshbufPtrFn as any)(sshbufPtr) as NativePointer;
        if (data.isNull()) return false;
        // Expect SSH binary packet layout: u32 packet_length || u8 padding_length || payload || padding
        const packetLength =
            (data.readU8() << 24) |
            (data.add(1).readU8() << 16) |
            (data.add(2).readU8() << 8) |
            data.add(3).readU8();
        // packet_length covers padding_length(1) + payload + padding, so total = packet_length + 4.
        if (packetLength + 4 !== len) return false;
        const padLen = data.add(4).readU8();
        if (padLen < 4 || padLen > 255) return false;
        return true;
    } catch {
        return false;
    }
}

function probeBufferOffset(
    sshPtr: NativePointer,
    state: ModuleHookState,
    label: "outgoing_packet" | "incoming_packet"
): number | null {
    const cached =
        label === "outgoing_packet" ? state.outgoingPacketOffset : state.incomingPacketOffset;
    if (cached !== null) return cached;
    try {
        const sessionState = sshPtr.readPointer();
        if (sessionState.isNull()) return null;
        for (let off = 0; off < 1024; off += ptrSize) {
            let cand: NativePointer;
            try {
                cand = sessionState.add(off).readPointer();
            } catch {
                continue;
            }
            if (looksLikeSshPacketSshbuf(cand, state)) {
                if (label === "outgoing_packet") {
                    state.outgoingPacketOffset = off;
                } else {
                    state.incomingPacketOffset = off;
                }
                devlog(`[SSH] probed ${label} sshbuf offset in state: ${off}`);
                return off;
            }
        }
    } catch (e) {
        devlog(`[SSH] probeBufferOffset(${label}) error: ${e}`);
    }
    return null;
}

function makeBaseMessage(
    fd: number,
    isRead: boolean,
    socketHelpers: { [fn: string]: NativePointer },
    fnLabel: string
): { [key: string]: any } | null {
    try {
        const msg = getPortsAndAddresses(fd, isRead, socketHelpers as any, enable_default_fd);
        if (!msg) return null;
        msg["function"] = fnLabel;
        msg["ssl_session_id"] = "";
        return msg as any;
    } catch (e) {
        devlog(`[SSH] getPortsAndAddresses(fd=${fd}, isRead=${isRead}) failed: ${e}`);
        return null;
    }
}

function installSendHook(moduleName: string, state: ModuleHookState): boolean {
    const addr = (Module as any).findExportByName(moduleName, "ssh_packet_send2_wrapped");
    if (!addr) return false;
    // No onLeave needed: ssh_packet_send2_wrapped encrypts outgoing_packet in
    // place before returning, so the plaintext must be read in onEnter — and
    // once we have the bytes there's nothing left for onLeave to do. Emitting
    // here halves the Interceptor round-trips per packet.
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const sshPtr = args[0] as NativePointer;
                if (sshPtr.isNull()) return;
                if (!state.connOutFn) return;
                const fd = (state.connOutFn as any)(sshPtr) as number;
                if (fd < 0 && !enable_default_fd) return;

                const off = probeBufferOffset(sshPtr, state, "outgoing_packet");
                if (off === null) return;
                if (!state.sshbufPtrFn || !state.sshbufLenFn) return;

                const sessionState = sshPtr.readPointer();
                const outgoingBuf = sessionState.add(off).readPointer();
                if (outgoingBuf.isNull()) return;

                const len = Number((state.sshbufLenFn as any)(outgoingBuf));
                if (len < MIN_SSH_PACKET || len > MAX_SSH_PACKET) return;
                const data = (state.sshbufPtrFn as any)(outgoingBuf) as NativePointer;
                if (data.isNull()) return;
                const bytes = data.readByteArray(len);
                if (!bytes) return;

                const msg = makeBaseMessage(fd, false, state.socketHelpers, "ssh_packet_send2");
                if (!msg) return;

                sendDatalog(msg, bytes);
            } catch (e) {
                devlog_error(`[SSH] ssh_packet_send2_wrapped onEnter error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked ssh_packet_send2_wrapped in ${moduleName}`);
    return true;
}

function installRecvHook(moduleName: string, state: ModuleHookState): boolean {
    const addr = (Module as any).findExportByName(moduleName, "ssh_packet_read_poll2");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.sshPtr = args[0] as NativePointer;
        },
        onLeave(retval) {
            try {
                // ssh_packet_read_poll2 returns 0 (SSH_ERR_SUCCESS) when a full
                // packet was decoded into incoming_packet; non-zero is incomplete
                // or error and we skip.
                if ((retval as NativePointer).toInt32() !== 0) return;
                const sshPtr = this.sshPtr as NativePointer;
                if (!sshPtr || sshPtr.isNull()) return;
                if (!state.connInFn) return;
                const fd = (state.connInFn as any)(sshPtr) as number;
                if (fd < 0 && !enable_default_fd) return;

                const off = probeBufferOffset(sshPtr, state, "incoming_packet");
                if (off === null) return;
                if (!state.sshbufPtrFn || !state.sshbufLenFn) return;

                const sessionState = sshPtr.readPointer();
                const incomingBuf = sessionState.add(off).readPointer();
                if (incomingBuf.isNull()) return;

                const len = Number((state.sshbufLenFn as any)(incomingBuf));
                if (len < MIN_SSH_PACKET || len > MAX_SSH_PACKET) return;
                const data = (state.sshbufPtrFn as any)(incomingBuf) as NativePointer;
                if (data.isNull()) return;
                const bytes = data.readByteArray(len);
                if (!bytes) return;

                const msg = makeBaseMessage(fd, true, state.socketHelpers, "ssh_packet_read_poll2");
                if (!msg) return;

                sendDatalog(msg, bytes);
            } catch (e) {
                devlog_error(`[SSH] ssh_packet_read_poll2 onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked ssh_packet_read_poll2 in ${moduleName}`);
    return true;
}

function installCipherCryptFallback(moduleName: string, state: ModuleHookState): boolean {
    const addr = (Module as any).findExportByName(moduleName, "cipher_crypt");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                // int cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr,
                //                  u_char *dest, const u_char *src,
                //                  u_int len, u_int aadlen, u_int authlen)
                const cc = args[0] as NativePointer;
                const dest = args[2] as NativePointer;
                const src = args[3] as NativePointer;
                const len = (args[4] as NativePointer).toUInt32();

                if (cc.isNull() || src.isNull() || dest.isNull()) return;
                if (len < 1 || len > MAX_SSH_PACKET) return;

                // sshcipher_ctx layout: int plaintext; int encrypt; ... — encrypt is at +4.
                const isEncrypt = cc.add(4).readInt() === 1;

                if (isEncrypt) {
                    // Encrypt path: src holds plaintext now. dest is filled
                    // post-call but we don't need it — emit in onEnter and
                    // skip onLeave entirely.
                    const bytes = src.readByteArray(len);
                    if (!bytes) return;
                    const msg = makeBaseMessage(-1, false, state.socketHelpers, "ssh_packet_send2");
                    if (!msg) return;
                    sendDatalog(msg, bytes);
                    return;
                }
                // Decrypt path: dest is populated after the call returns.
                // Stash and emit in onLeave.
                this.decryptDest = dest;
                this.decryptLen = len;
            } catch (e) {
                devlog(`[SSH] cipher_crypt onEnter error: ${e}`);
            }
        },
        onLeave(_retval) {
            try {
                const dest = this.decryptDest as NativePointer | undefined;
                if (!dest || dest.isNull()) return;
                const bytes = dest.readByteArray(this.decryptLen as number);
                if (!bytes) return;
                const msg = makeBaseMessage(-1, true, state.socketHelpers, "ssh_packet_read_poll2");
                if (!msg) return;
                sendDatalog(msg, bytes);
            } catch (e) {
                devlog_error(`[SSH] cipher_crypt onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked cipher_crypt fallback in ${moduleName} (synthetic 5-tuple).`);
    return true;
}

// Per-module installation guard — Frida may invoke us more than once if the
// dynamic loader observes the same SSH binary repeatedly.
const installedModules = new Set<string>();

/**
 * Install SSH plaintext capture for one OpenSSH binary or libssh.so.
 *
 * @param moduleName        Frida module name (basename for the main binary).
 * @param methodAddresses   Output of readAddresses(moduleName, ...). All
 *                          resolved pointers (socket helpers) live under the
 *                          single ``moduleName`` key per readAddresses'
 *                          contract — see shared_functions.ts:323,370.
 */
export function installSshPacketHooks(
    moduleName: string,
    methodAddresses: { [lib: string]: { [fn: string]: NativePointer } }
): void {
    if (!pcap_enabled) return;
    if (installedModules.has(moduleName)) return;
    installedModules.add(moduleName);

    const state: ModuleHookState = {
        sshbufPtrFn: null,
        sshbufLenFn: null,
        connInFn: null,
        connOutFn: null,
        outgoingPacketOffset: null,
        incomingPacketOffset: null,
        socketHelpers: methodAddresses[moduleName] || {},
    };

    try {
        const ptrAddr = (Module as any).findExportByName(moduleName, "sshbuf_ptr");
        const lenAddr = (Module as any).findExportByName(moduleName, "sshbuf_len");
        if (ptrAddr && lenAddr) {
            state.sshbufPtrFn = new NativeFunction(ptrAddr, "pointer", ["pointer"]);
            state.sshbufLenFn = new NativeFunction(lenAddr, "size_t", ["pointer"]) as any;
        } else {
            devlog(`[SSH] sshbuf accessors not exported in ${moduleName}; plaintext probe disabled.`);
        }

        const inAddr = (Module as any).findExportByName(moduleName, "ssh_packet_get_connection_in");
        const outAddr = (Module as any).findExportByName(moduleName, "ssh_packet_get_connection_out");
        if (inAddr) state.connInFn = new NativeFunction(inAddr, "int", ["pointer"]);
        if (outAddr) state.connOutFn = new NativeFunction(outAddr, "int", ["pointer"]);
    } catch (e) {
        devlog_error(`[SSH] accessor resolution failed in ${moduleName}: ${e}`);
    }

    const haveAccessors =
        state.sshbufPtrFn !== null &&
        state.sshbufLenFn !== null &&
        state.connInFn !== null &&
        state.connOutFn !== null;

    let primaryInstalled = false;
    if (haveAccessors) {
        primaryInstalled = installSendHook(moduleName, state) || primaryInstalled;
        primaryInstalled = installRecvHook(moduleName, state) || primaryInstalled;
    }

    if (!primaryInstalled) {
        devlog(
            `[SSH] primary plaintext hooks unavailable in ${moduleName} ` +
            `(accessors=${haveAccessors}); trying cipher_crypt fallback.`
        );
        installCipherCryptFallback(moduleName, state);
    }
}
