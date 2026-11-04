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
 * Both are non-static in OpenSSH packet.c since at least 7.6. Builds that do not
 * export them (the stripped Debian/Ubuntu `ssh`) are served by the string-anchor
 * locator (../../shared/openssh_functions.ts). Ubuntu's LTO build inlines
 * ssh_packet_read_poll2 into its only caller, ssh_packet_read_poll_seqnr(ssh, typep,
 * seqnr_p): same signature and, for every message it hands back, the same
 * incoming_packet state on success — so the receive hook falls back to it. It loses the
 * transport messages read_poll_seqnr consumes itself (IGNORE, DEBUG, UNIMPLEMENTED,
 * PING/PONG, DISCONNECT).
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
import { findModuleExport } from "../../../shared/module_exports.js";
import { SshbufView, frameSshMessage, readConnectionFd, readPointerAt, readSshbuf } from "../../shared/sshbuf_view.js";
import { OpenSshFunction, locatedByAnchors, openSshFunction } from "../../shared/openssh_functions.js";

const ptrSize = Process.pointerSize;
const MAX_SSH_PACKET = 65535;
const MIN_SSH_PACKET = 6; // 4 length + 1 padlen + 1 type byte minimum

/** The connection descriptor of one direction of a `struct ssh *`, or -1. */
type ConnectionFdReader = (ssh: NativePointer) => number;

interface ModuleHookState {
    /** An OpenSSH build whose sshbufs we read by struct (exported sshbuf API, or located by anchors). */
    haveSshbuf: boolean;
    connInFn: ConnectionFdReader | null;
    connOutFn: ConnectionFdReader | null;
    outgoingPacketOffset: number | null;
    incomingPacketOffset: number | null;
    // Socket helpers (getpeername/getsockname/ntohs/ntohl) flat-mapped from
    // readAddresses output. readAddresses writes everything under a single
    // moduleName key (shared_functions.ts:323,370), so this is just an alias
    // to that inner map — no merging needed.
    socketHelpers: { [fn: string]: NativePointer };
}

/** sshpkt_start() reserves `u32 packet_length || u8 padding_length` as 5 zero bytes. */
const SEND_HEADER_LEN = 5;
/** ssh_packet_read_poll2 consumes `packet_length || padding_length || type` (4 + 1 + 1). */
const RECV_CONSUMED_LEN = 6;

/**
 * outgoing_packet as ssh_packet_send2_wrapped sees it on entry: the zeroed 5-byte header
 * sshpkt_start() reserved, then `type || payload` (padding is added inside the call).
 */
export function isPendingOutgoingPacket(view: SshbufView | null): boolean {
    try {
        if (!view || view.len < MIN_SSH_PACKET || view.len > MAX_SSH_PACKET) return false;
        for (let i = 0; i < SEND_HEADER_LEN; i++) if (view.data.add(i).readU8() !== 0) return false;
        return view.data.add(SEND_HEADER_LEN).readU8() !== 0;
    } catch {
        return false;
    }
}

/**
 * incoming_packet after a successful ssh_packet_read_poll2 (uncompressed): the header and
 * the type byte are consumed (off = 6), the type just before the payload equals *typep and
 * the padding_length byte is a legal RFC 4253 value (>= 4).
 */
export function isDecodedIncomingPacket(view: SshbufView | null, type: number): boolean {
    try {
        if (!view || view.off !== RECV_CONSUMED_LEN || view.len > MAX_SSH_PACKET) return false;
        if (view.base.add(RECV_CONSUMED_LEN - 1).readU8() !== type) return false;
        return view.base.add(4).readU8() >= 4;
    } catch {
        return false;
    }
}

/** The SSH message (`type || payload`) of a validated outgoing / incoming packet buffer. */
function messageBytes(view: SshbufView, label: "outgoing_packet" | "incoming_packet", type: number): Uint8Array | null {
    if (label === "outgoing_packet") {
        const body = view.data.add(SEND_HEADER_LEN).readByteArray(view.len - SEND_HEADER_LEN);
        return body ? new Uint8Array(body) : null;
    }
    // Compressed sessions rebuild incoming_packet without the type byte, so prepend *typep.
    const payload = view.len > 0 ? view.data.readByteArray(view.len) : new ArrayBuffer(0);
    if (!payload) return null;
    const message = new Uint8Array(1 + view.len);
    message[0] = type;
    message.set(new Uint8Array(payload), 1);
    return message;
}

function probeBufferOffset(
    sshPtr: NativePointer,
    state: ModuleHookState,
    label: "outgoing_packet" | "incoming_packet",
    type: number
): number | null {
    const cached =
        label === "outgoing_packet" ? state.outgoingPacketOffset : state.incomingPacketOffset;
    if (cached !== null) return cached;
    const sessionState = readPointerAt(sshPtr, 0);
    if (sessionState === null) return null;
    for (let off = 0; off < 1024; off += ptrSize) {
        const view = readSshbuf(readPointerAt(sessionState, off));
        const matches = label === "outgoing_packet"
            ? isPendingOutgoingPacket(view)
            : isDecodedIncomingPacket(view, type);
        if (!matches) continue;
        if (label === "outgoing_packet") {
            state.outgoingPacketOffset = off;
        } else {
            state.incomingPacketOffset = off;
        }
        devlog(`[SSH] probed ${label} sshbuf offset in state: ${off}`);
        return off;
    }
    return null;
}

/** The framed plaintext of state->{outgoing,incoming}_packet, or null. Never throws. */
function capturePacket(
    sshPtr: NativePointer,
    state: ModuleHookState,
    label: "outgoing_packet" | "incoming_packet",
    type: number
): ArrayBuffer | null {
    try {
        const off = probeBufferOffset(sshPtr, state, label, type);
        if (off === null) return null;
        const sessionState = readPointerAt(sshPtr, 0);
        if (sessionState === null) return null;
        const view = readSshbuf(readPointerAt(sessionState, off));
        if (view === null) return null;
        if (label === "outgoing_packet" && !isPendingOutgoingPacket(view)) return null;
        const message = messageBytes(view, label, type);
        return message ? frameSshMessage(message) : null;
    } catch (e) {
        devlog(`[SSH] capturePacket(${label}) error: ${e}`);
        return null;
    }
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
    const addr = openSshFunction(moduleName, "ssh_packet_send2_wrapped");
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
                const fd = state.connOutFn(sshPtr);
                if (fd < 0 && !enable_default_fd) return;

                const bytes = capturePacket(sshPtr, state, "outgoing_packet", 0);
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

/** ssh_packet_read_poll2, else its LTO caller ssh_packet_read_poll_seqnr (same signature). */
const RECV_HOOK_FUNCTIONS: OpenSshFunction[] = ["ssh_packet_read_poll2", "ssh_packet_read_poll_seqnr"];

function installRecvHook(moduleName: string, state: ModuleHookState): boolean {
    const hookFunction = RECV_HOOK_FUNCTIONS.find((name) => openSshFunction(moduleName, name) !== null);
    if (hookFunction === undefined) return false;
    const addr = openSshFunction(moduleName, hookFunction)!;
    Interceptor.attach(addr, {
        onEnter(args) {
            // int ssh_packet_read_poll2(struct ssh *ssh, u_char *typep, u_int32_t *seqnr_p)
            // int ssh_packet_read_poll_seqnr(struct ssh *ssh, u_char *typep, u_int32_t *seqnr_p)
            this.sshPtr = args[0] as NativePointer;
            this.typep = args[1] as NativePointer;
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
                const fd = state.connInFn(sshPtr);
                if (fd < 0 && !enable_default_fd) return;

                // SSH_MSG_NONE (0) with success = no complete packet buffered yet.
                const typep = this.typep as NativePointer;
                if (!typep || typep.isNull()) return;
                const type = typep.readU8();
                if (type === 0) return;
                const bytes = capturePacket(sshPtr, state, "incoming_packet", type);
                if (!bytes) return;

                const msg = makeBaseMessage(fd, true, state.socketHelpers, "ssh_packet_read_poll2");
                if (!msg) return;

                sendDatalog(msg, bytes);
            } catch (e) {
                devlog_error(`[SSH] ${hookFunction} onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked ${hookFunction} in ${moduleName}`);
    return true;
}

function installCipherCryptFallback(moduleName: string, state: ModuleHookState): boolean {
    const addr = findModuleExport(moduleName, "cipher_crypt");
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

/**
 * ssh_packet_get_connection_in/_out() when exported; otherwise (stripped builds, where
 * LTO even inlines them) the same field read straight from the struct.
 */
function connectionFdReader(moduleName: string, direction: "in" | "out"): ConnectionFdReader {
    const accessor = findModuleExport(moduleName, `ssh_packet_get_connection_${direction}`);
    if (accessor === null) return (ssh) => readConnectionFd(ssh, direction);
    const fn = new NativeFunction(accessor, "int", ["pointer"]);
    return (ssh) => fn(ssh) as number;
}

// Per-module installation guard — Frida may invoke us more than once if the
// dynamic loader observes the same SSH binary repeatedly.
/** moduleName -> whether plaintext hooks were installed on it (installed once per module). */
const installedModules = new Map<string, boolean>();

/**
 * Install SSH plaintext capture for one OpenSSH binary or libssh.so.
 *
 * @param moduleName        Frida module name (basename for the main binary).
 * @param methodAddresses   Output of readAddresses(moduleName, ...). All
 *                          resolved pointers (socket helpers) live under the
 *                          single ``moduleName`` key per readAddresses'
 *                          contract — see shared_functions.ts:323,370.
 * @returns                 whether plaintext hooks are installed on the module.
 */
export function installSshPacketHooks(
    moduleName: string,
    methodAddresses: { [lib: string]: { [fn: string]: NativePointer } }
): boolean {
    if (!pcap_enabled) return false;
    if (installedModules.has(moduleName)) return installedModules.get(moduleName) === true;
    installedModules.set(moduleName, false);

    const state: ModuleHookState = {
        haveSshbuf: false,
        connInFn: null,
        connOutFn: null,
        outgoingPacketOffset: null,
        incomingPacketOffset: null,
        socketHelpers: methodAddresses[moduleName] || {},
    };

    try {
        const ptrAddr = findModuleExport(moduleName, "sshbuf_ptr");
        const lenAddr = findModuleExport(moduleName, "sshbuf_len");
        // Presence check only: the target's sshbuf_len()/sshbuf_ptr() are never called
        // (sshbuf_check_sanity() SIGSEGVs the process on a non-sshbuf candidate).
        if ((ptrAddr && lenAddr) || locatedByAnchors(moduleName)) {
            state.haveSshbuf = true;
        } else {
            devlog(`[SSH] ${moduleName} is not a recognised OpenSSH build; plaintext probe disabled.`);
        }
        state.connInFn = connectionFdReader(moduleName, "in");
        state.connOutFn = connectionFdReader(moduleName, "out");
    } catch (e) {
        devlog_error(`[SSH] accessor resolution failed in ${moduleName}: ${e}`);
    }

    const haveAccessors =
        state.haveSshbuf &&
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
        primaryInstalled = installCipherCryptFallback(moduleName, state);
    }
    installedModules.set(moduleName, primaryInstalled);
    return primaryInstalled;
}
