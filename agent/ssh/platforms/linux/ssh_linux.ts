/**
 * SSH key extraction + plaintext capture entry point for Linux/Android/macOS.
 *
 * Handles OpenSSH (binary or libssh.so) and emits:
 *   - ssh_keylog messages with Wireshark-compatible `<cookie> SHARED_SECRET <K>`
 *     content (one line per (re)keying), produced by correlating cookies from
 *     kex_send_kexinit / kex_input_kexinit with the shared secret K returned
 *     in arg3 of kex_derive_keys (sshbuf*).
 *   - ssh_key messages with direction-aware C2S/S2C labels, produced from
 *     cipher_init(... key, keylen, iv, ivlen, do_encrypt). Direction is
 *     derived from (process role, do_encrypt) and matches Wireshark naming.
 *   - ssh_newkeys status notifications.
 *   - SSH plaintext PCAPNG records via installSshPacketHooks() — see
 *     ssh_packet_hooks.ts for the binary-packet interception path.
 *
 * Hook addresses come from the module's exports, or — for the stripped `ssh`/`sshd` that
 * Debian and Ubuntu ship — from the string anchors in ../../shared/openssh_functions.ts.
 *
 * Notes on the legacy struct walk:
 *  - The pre-rewrite implementation here read `state` at offset 0 of struct ssh
 *    and then walked `state[0]/state[8]` as if it were `newkeys[2]`. That was
 *    wrong: session_state begins with `connection_in`/`connection_out` (int)
 *    and the `newkeys[MODE_MAX]` array sits ~120 bytes in (offset varies with
 *    `#ifdef WITH_ZLIB`). We replaced the primary path with cipher_init (whose
 *    arguments are direct pointers — no struct offsets needed) and kept the
 *    sshenc walk as a *validated-scan* fallback for forensic attach scenarios
 *    where cipher_init never fires (e.g. attach-post-rekey).
 *
 * Based on keys-in-flux research:
 *   https://github.com/fkie-cad/keys-in-flux-paper-material
 */

import { log, devlog, devlog_error } from "../../../util/log.js";
import { sendWithProtocol, sendKeyMaterial } from "../../../shared/shared_structures.js";
import { toHexString, readAddresses } from "../../../shared/shared_functions.js";
import { installSshPacketHooks } from "./ssh_packet_hooks.js";
import { keylog_enabled } from "../../../fritap_agent.js";
import { findModuleExport } from "../../../shared/module_exports.js";
import {
    KexLayout, kexinitCookie, probeKexLayout, readPointerAt, readShortCString, readSshbuf, sharedSecretBytes,
} from "../../shared/sshbuf_view.js";
import { guardAgentFdsAgainstClosefrom } from "../../shared/closefrom_guard.js";
import { locatedByAnchors, openSshFunction, withOpenSshFunctions } from "../../shared/openssh_functions.js";

// ---------------------------------------------------------------------------
// sshenc struct offsets (OpenSSH 7.6+ on 64-bit LP64) — used only by the
// validated-scan fallback. The base offset of newkeys[] in session_state
// shifts with build flags, so the fallback *scans* session_state for two
// consecutive plausible newkeys pointers instead of trusting a hardcoded
// position. The sshenc *interior* layout has been stable since OpenSSH 7.6
// (verified against upstream packet.c / kex.h tags V_7_6_P1 → V_10_0_P1).
// ---------------------------------------------------------------------------
const SSHENC_CIPHER_NAME_OFFSET = 0;   // pointer to ASCII cipher name
const SSHENC_KEY_LEN_OFFSET = 20;      // u_int
const SSHENC_IV_LEN_OFFSET = 24;       // u_int
const SSHENC_KEY_PTR_OFFSET = 32;      // pointer to key bytes
// IV pointer = key pointer + Process.pointerSize

// ---------------------------------------------------------------------------
// Process-role detection — used to map MODE_IN/MODE_OUT (or do_encrypt) to
// C2S/S2C semantics that match Wireshark's SSH dissector.
//
// On the SSH client (`ssh`, `scp`, `sftp`, etc.):
//   MODE_OUT / do_encrypt=1 → client → server (C2S)
//   MODE_IN  / do_encrypt=0 → server → client (S2C)
// On the SSH server (`sshd`, `sshd-session`):
//   MODE_OUT / do_encrypt=1 → server → client (S2C)
//   MODE_IN  / do_encrypt=0 → client → server (C2S)
//
// We detect the role once at module load and cache it. The check parses
// the main module path; if Frida's enumerateModules returns the executable
// path with an `sshd` basename (possibly suffixed with `-session`), we are
// running on the server.
// ---------------------------------------------------------------------------
const isServerSide: boolean = (() => {
    try {
        const modules = (Process as any).enumerateModules() as Array<{ path?: string; name?: string }>;
        if (!modules || modules.length === 0) return false;
        const mainPath = modules[0].path || modules[0].name || "";
        const basename = mainPath.split("/").pop() || mainPath;
        return /^sshd(-session)?$/.test(basename);
    } catch {
        return false;
    }
})();

function directionForEncryptFlag(do_encrypt: number): "C2S" | "S2C" {
    const localSends = do_encrypt === 1;
    if (isServerSide) {
        return localSends ? "S2C" : "C2S";
    }
    return localSends ? "C2S" : "S2C";
}

// MODE_IN=0 / MODE_OUT=1 share the same "is the local process the sender"
// semantics as do_encrypt — callers convert via directionForEncryptFlag(mode).

// Emits one or two `ssh_key` messages (encryption key, IV) with C2S/S2C
// labels. Shared by both the cipher_init primary path and the sshenc-walk
// fallback so the message shape doesn't drift.
function emitSshKey(
    dir: "C2S" | "S2C",
    cipherName: string,
    keyData: ArrayBuffer | null,
    keyLen: number,
    ivData: ArrayBuffer | null,
    ivLen: number,
): void {
    // SSH session keys are keylog material — gate on keylog_enabled so
    // plaintext-only captures (-p without -k) don't leak them. We emit via
    // sendKeyMaterial(), the shared choke point for key material that doesn't
    // flow through sendKeylog(), so the gate is enforced in one place. This
    // early return is the performance optimization on top of that: it skips
    // the toHexString() work below when keys aren't wanted.
    if (!keylog_enabled) return;
    if (keyData && keyLen > 0) {
        sendKeyMaterial({
            contentType: "ssh_key",
            direction: dir,
            key_type: `SSH_ENC_KEY_${dir}`,
            cipher: cipherName,
            key_len: keyLen,
            key_data: toHexString(keyData),
        });
    }
    if (ivData && ivLen > 0) {
        sendKeyMaterial({
            contentType: "ssh_key",
            direction: dir,
            key_type: `SSH_IV_${dir}`,
            cipher: cipherName,
            iv_len: ivLen,
            key_data: toHexString(ivData),
        });
    }
}

// ---------------------------------------------------------------------------
// Per-`struct ssh*` cookie correlation map.
//
// kex_send_kexinit captures the local cookie, kex_input_kexinit captures the
// peer cookie. When kex_derive_keys fires it pairs whichever cookies we have
// with the shared secret K and emits an ssh_keylog message.
// ---------------------------------------------------------------------------
interface CookiePair {
    local?: string;
    peer?: string;
}
const sshCookies = new Map<string, CookiePair>();

function recordCookie(sshPtr: NativePointer, side: "local" | "peer", cookieHex: string): void {
    const tag = sshPtr.toString();
    const entry = sshCookies.get(tag) || {};
    entry[side] = cookieHex;
    sshCookies.set(tag, entry);
}

// Drains the cookie pair for one SSH session. The Map entry is deleted so
// long-lived sshd daemons don't accumulate entries across thousands of
// handshakes; a subsequent rekey re-populates fresh cookies before the
// next kex_derive_keys hook fires.
function consumeCookies(sshPtr: NativePointer): CookiePair {
    const tag = sshPtr.toString();
    const entry = sshCookies.get(tag) || {};
    sshCookies.delete(tag);
    return entry;
}

// ---------------------------------------------------------------------------
// Cookie extraction from struct ssh -> kex -> {my, peer} (sshbuf*).
//
// kex->my / kex->peer hold the KEXINIT *bodies* — `cookie[16] || name-lists ...`, without
// the SSH_MSG_KEXINIT type byte. kex_send_kexinit fills `my`; kex_input_kexinit copies
// the peer's body into `peer` (the adjacent field). `kex` is a direct member of struct
// ssh (the 2nd field), not of session_state.
//
// The offsets are discovered once per process by content (probeKexLayout) and every
// candidate is read with guarded struct reads (sshbuf_view.ts). Never call the target's
// sshbuf_len()/sshbuf_ptr() on an unverified pointer: sshbuf_check_sanity() raises
// SIGSEGV on anything that is not a sane sshbuf, killing the target.
// ---------------------------------------------------------------------------

const ptrSize = Process.pointerSize;
let kexLayout: KexLayout | null = null;

/** Whether the module exports the sshbuf API, i.e. is an OpenSSH build we understand. */
function hasSshbufExports(moduleName: string): boolean {
    return findModuleExport(moduleName, "sshbuf_ptr") !== null
        && findModuleExport(moduleName, "sshbuf_len") !== null;
}

/**
 * Whether `moduleName` is an OpenSSH build whose structs sshbuf_view.ts reads: one that
 * exports the sshbuf API, or a stripped one whose functions the string anchors located
 * (the anchors are OpenSSH's own log literals).
 */
export function isOpenSshBuild(moduleName: string): boolean {
    return hasSshbufExports(moduleName) || locatedByAnchors(moduleName);
}

/** ssh->kex, probing the layout on first use (needs kex->my filled). */
function kexOf(sshPtr: NativePointer): NativePointer | null {
    if (kexLayout === null) {
        kexLayout = probeKexLayout(sshPtr);
        if (kexLayout === null) return null;
        devlog(`[SSH] probed offsets: ssh->kex=${kexLayout.kexInSsh}, kex->my=${kexLayout.myInKex}, ` +
            `kex->peer=${kexLayout.myInKex + ptrSize}`);
    }
    return readPointerAt(sshPtr, kexLayout.kexInSsh);
}

/** The local (`my`) or peer KEXINIT cookie of this session as hex, or null. */
function readKexinitCookie(sshPtr: NativePointer, side: "local" | "peer"): string | null {
    const kex = kexOf(sshPtr);
    if (kex === null || kexLayout === null) return null;
    const slot = kexLayout.myInKex + (side === "peer" ? ptrSize : 0);
    return kexinitCookie(readPointerAt(kex, slot), toHexString);
}

// ---------------------------------------------------------------------------
// Validated sshenc walk fallback. Only runs when cipher_init isn't hooked.
//
// Replaces the previous fixed-offset walk which assumed `newkeys[2]` lived at
// offset 0 of `state`. We now scan `state` for two consecutive pointers that
// both pass plausibility checks: dereferencing them yields a struct whose
// first slot points to printable ASCII (cipher name) and whose +20/+24
// uint32 values are sane (8..64 for key_len, 0..32 for iv_len).
// ---------------------------------------------------------------------------
let newkeysOffsetInState: number | null = null;

function plausibleSshencSlot(slotPtr: NativePointer): boolean {
    try {
        if (slotPtr.isNull()) return false;
        const namePtr = slotPtr.add(SSHENC_CIPHER_NAME_OFFSET).readPointer();
        if (namePtr.isNull()) return false;
        // Bounded NUL-terminated read: readCString(31) would read 31 bytes past the NUL.
        const name = readShortCString(namePtr, 32);
        if (!name || name.length === 0) return false;
        if (!/^[\x20-\x7e]+$/.test(name)) return false;
        const keyLen = slotPtr.add(SSHENC_KEY_LEN_OFFSET).readU32();
        const ivLen = slotPtr.add(SSHENC_IV_LEN_OFFSET).readU32();
        if (keyLen < 8 || keyLen > 64) return false;
        // chacha20-poly1305@openssh.com derives its nonce from the sequence number: iv_len 0.
        if (ivLen > 32) return false;
        return true;
    } catch {
        return false;
    }
}

function readSshEncKeys(sshencPtr: NativePointer, mode: number): void {
    const dir = directionForEncryptFlag(mode === 1 ? 1 : 0);
    try {
        const cipherNamePtr = sshencPtr.add(SSHENC_CIPHER_NAME_OFFSET).readPointer();
        const cipherName = cipherNamePtr.readCString() || "unknown";
        const keyLen = sshencPtr.add(SSHENC_KEY_LEN_OFFSET).readU32();
        const ivLen = sshencPtr.add(SSHENC_IV_LEN_OFFSET).readU32();
        const keyPtr = sshencPtr.add(SSHENC_KEY_PTR_OFFSET).readPointer();
        const ivPtr = sshencPtr.add(SSHENC_KEY_PTR_OFFSET + ptrSize).readPointer();

        const keyData = (keyLen > 0 && keyLen < 256 && !keyPtr.isNull())
            ? keyPtr.readByteArray(keyLen) : null;
        const ivData = (ivLen > 0 && ivLen < 256 && !ivPtr.isNull())
            ? ivPtr.readByteArray(ivLen) : null;
        emitSshKey(dir, cipherName, keyData, keyLen, ivData, ivLen);
        if (keyData) {
            devlog(`[SSH] (fallback) ${dir} key extracted via sshenc walk: cipher=${cipherName}, len=${keyLen}`);
        }
    } catch (e) {
        devlog(`[SSH] sshenc-walk error in ${dir}: ${e}`);
    }
}

function scanForNewkeysAndExtract(sshPtr: NativePointer): void {
    try {
        const state = sshPtr.readPointer();
        if (state.isNull()) return;
        if (newkeysOffsetInState !== null) {
            const a = state.add(newkeysOffsetInState).readPointer();
            const b = state.add(newkeysOffsetInState + ptrSize).readPointer();
            if (plausibleSshencSlot(a)) readSshEncKeys(a, 0); // MODE_IN
            if (plausibleSshencSlot(b)) readSshEncKeys(b, 1); // MODE_OUT
            return;
        }
        for (let off = 0; off < 512; off += ptrSize) {
            let a: NativePointer;
            let b: NativePointer;
            try {
                a = state.add(off).readPointer();
                b = state.add(off + ptrSize).readPointer();
            } catch {
                continue;
            }
            if (plausibleSshencSlot(a) && plausibleSshencSlot(b)) {
                newkeysOffsetInState = off;
                devlog(`[SSH] probed newkeys[] offset in state: ${off}`);
                readSshEncKeys(a, 0);
                readSshEncKeys(b, 1);
                return;
            }
        }
    } catch (e) {
        devlog(`[SSH] scanForNewkeysAndExtract error: ${e}`);
    }
}

// ---------------------------------------------------------------------------
// Hook installers
// ---------------------------------------------------------------------------

function hookCipherInit(moduleName: string): boolean {
    const addr = findModuleExport(moduleName, "cipher_init");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                // int cipher_init(struct sshcipher_ctx **ccp,
                //                 const struct sshcipher *cipher,
                //                 const u_char *key,  u_int keylen,
                //                 const u_char *iv,   u_int ivlen,
                //                 int do_encrypt)
                const cipherStruct = args[1] as NativePointer;
                const keyPtr = args[2] as NativePointer;
                const keyLen = (args[3] as NativePointer).toUInt32();
                const ivPtr = args[4] as NativePointer;
                const ivLen = (args[5] as NativePointer).toUInt32();
                const doEncrypt = (args[6] as NativePointer).toInt32();

                let cipherName = "unknown";
                if (!cipherStruct.isNull()) {
                    const namePtr = cipherStruct.readPointer();
                    if (!namePtr.isNull()) {
                        const s = namePtr.readCString();
                        if (s) cipherName = s;
                    }
                }
                const dir = directionForEncryptFlag(doEncrypt);
                const keyData = (keyLen > 0 && keyLen < 256 && !keyPtr.isNull())
                    ? keyPtr.readByteArray(keyLen) : null;
                const ivData = (ivLen > 0 && ivLen < 256 && !ivPtr.isNull())
                    ? ivPtr.readByteArray(ivLen) : null;
                emitSshKey(dir, cipherName, keyData, keyLen, ivData, ivLen);
                devlog(`[SSH] cipher_init hooked: cipher=${cipherName} dir=${dir} keylen=${keyLen} ivlen=${ivLen}`);
            } catch (e) {
                devlog_error(`[SSH] cipher_init onEnter error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked cipher_init in ${moduleName}`);
    return true;
}

function hookKexSendKexinit(moduleName: string): boolean {
    const addr = openSshFunction(moduleName, "kex_send_kexinit");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.sshPtr = args[0] as NativePointer;
        },
        onLeave(_retval) {
            try {
                if (!this.sshPtr || (this.sshPtr as NativePointer).isNull()) return;
                const cookieHex = readKexinitCookie(this.sshPtr as NativePointer, "local");
                if (cookieHex) recordCookie(this.sshPtr as NativePointer, "local", cookieHex);
            } catch (e) {
                devlog(`[SSH] kex_send_kexinit onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked kex_send_kexinit in ${moduleName}`);
    return true;
}

function hookKexInputKexinit(moduleName: string): boolean {
    const addr = openSshFunction(moduleName, "kex_input_kexinit");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            // int kex_input_kexinit(int type, u_int32_t seq, struct ssh *ssh)
            this.sshPtr = args[2] as NativePointer;
        },
        onLeave(_retval) {
            try {
                if (!this.sshPtr || (this.sshPtr as NativePointer).isNull()) return;
                const cookieHex = readKexinitCookie(this.sshPtr as NativePointer, "peer");
                if (cookieHex) recordCookie(this.sshPtr as NativePointer, "peer", cookieHex);
            } catch (e) {
                devlog(`[SSH] kex_input_kexinit onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked kex_input_kexinit in ${moduleName}`);
    return true;
}

function hookKexDeriveKeys(moduleName: string): boolean {
    const addr = openSshFunction(moduleName, "kex_derive_keys");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                // int kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
                //                     const struct sshbuf *shared_secret)
                this.sshPtr = args[0] as NativePointer;
                this.secretBuf = args[3] as NativePointer;
            } catch (e) {
                devlog_error(`[SSH] kex_derive_keys onEnter capture error: ${e}`);
            }
        },
        onLeave(_retval) {
            // SSH shared-secret is keylog material — same gate as emitSshKey().
            // Returning here also skips the secret-buffer reads below, so we
            // don't pay the cost when keys aren't wanted.
            if (!keylog_enabled) return;
            try {
                const sshPtr = this.sshPtr as NativePointer;
                const secretBuf = this.secretBuf as NativePointer;
                if (!sshPtr || sshPtr.isNull()) return;
                if (!secretBuf || secretBuf.isNull()) return;
                // Guarded struct read, never the target's sshbuf_len(): see sshbuf_view.ts.
                const view = readSshbuf(secretBuf);
                if (view === null || view.len <= 0 || view.len > 16384) return;
                const secret = sharedSecretBytes(view);
                if (secret === null) return;
                const len = secret.byteLength;
                const sharedSecretHex = toHexString(secret);
                const cookies = consumeCookies(sshPtr);
                sendKeyMaterial({
                    contentType: "ssh_keylog",
                    cookie: cookies.local || "",
                    peer_cookie: cookies.peer || "",
                    shared_secret: sharedSecretHex,
                    direction: isServerSide ? "server" : "client",
                    session_tag: sshPtr.toString(),
                });
                log(
                    `[SSH] kex_derive_keys: emitted ssh_keylog ` +
                    `(local_cookie=${cookies.local ? "yes" : "no"}, peer_cookie=${cookies.peer ? "yes" : "no"}, ` +
                    `K-bytes=${len})`
                );
            } catch (e) {
                devlog_error(`[SSH] kex_derive_keys onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked kex_derive_keys in ${moduleName}`);
    return true;
}

function hookSshSetNewkeys(moduleName: string, fallbackToScan: boolean): boolean {
    const addr = openSshFunction(moduleName, "ssh_set_newkeys");
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.sshPtr = args[0] as NativePointer;
            this.mode = (args[1] as NativePointer).toInt32();
        },
        onLeave(_retval) {
            try {
                const dir = directionForEncryptFlag((this.mode as number) === 1 ? 1 : 0);
                sendWithProtocol({
                    contentType: "ssh_newkeys",
                    direction: dir,
                    message: `SSH new keys activated: ${dir}`,
                });
                if (fallbackToScan) {
                    scanForNewkeysAndExtract(this.sshPtr as NativePointer);
                }
            } catch (e) {
                devlog(`[SSH] ssh_set_newkeys onLeave error: ${e}`);
            }
        },
    });
    log(`[SSH] Hooked ssh_set_newkeys in ${moduleName}`);
    return true;
}

// ---------------------------------------------------------------------------
// Public entry point — invoked from agent/platforms/{linux,android,macos}.ts
// when the loader matches an SSH binary / library.
// ---------------------------------------------------------------------------
//
// Returns whether any hook was installed (ModuleHookingType): the central loader
// announces the module and sends its single library_detected from that verdict. A
// stripped OpenSSH first has its functions located by string anchors, so the verdict
// then arrives as a Promise (openssh_functions.ts withOpenSshFunctions).
export function ssh_execute(moduleName: string, _is_base_hook: boolean): boolean | Promise<boolean> {
    return withOpenSshFunctions(moduleName, () => installSshHooks(moduleName));
}

/**
 * Install every SSH hook on `moduleName` whose function is known (exported, or already
 * located by anchors). Synchronous; returns whether any hook was installed.
 */
export function installSshHooks(moduleName: string): boolean {
    devlog(`[SSH] Installing SSH hooks for: ${moduleName}`);

    // Resolve libc socket helpers once for getPortsAndAddresses() inside the
    // plaintext hooks. The mapping keys here mirror what TLS hooks use.
    let methodAddresses: { [lib: string]: { [fn: string]: NativePointer } } = {};
    try {
        methodAddresses = readAddresses(moduleName, {
            "*libc*": ["getpeername", "getsockname", "ntohs", "ntohl"],
        });
    } catch (e) {
        devlog(`[SSH] readAddresses for socket helpers failed: ${e}`);
    }

    // 1. An OpenSSH build whose sshbufs the hooks read (by struct): exported sshbuf API,
    //    or a stripped build identified by its located functions.
    const haveSshbuf = isOpenSshBuild(moduleName);
    if (!haveSshbuf) {
        devlog(`[SSH] ${moduleName} is not a recognised OpenSSH build; cookie + K extraction skipped.`);
    }

    // ssh's main() calls closefrom(3), which would close the agent's channel in spawn mode
    // and silently drop every message the hooks below send.
    guardAgentFdsAgainstClosefrom(moduleName);

    // 2. Cookie capture (best-effort).
    let installed = false;
    if (haveSshbuf) {
        installed = hookKexSendKexinit(moduleName) || installed;
        installed = hookKexInputKexinit(moduleName) || installed;
    }

    // 3. Shared-secret extraction → ssh_keylog (preferred for Wireshark side-car).
    if (haveSshbuf) {
        installed = hookKexDeriveKeys(moduleName) || installed;
    } else {
        devlog(`[SSH] Skipping kex_derive_keys hook (not a recognised OpenSSH build).`);
    }

    // 4. Per-direction key extraction → ssh_key with C2S/S2C labels.
    //    Primary: cipher_init (direct args, no struct walk).
    //    Fallback: sshenc validated scan, triggered from ssh_set_newkeys.
    const cipherInitHooked = hookCipherInit(moduleName);
    if (!cipherInitHooked) {
        devlog(`[SSH] cipher_init not resolvable in ${moduleName}; falling back to sshenc scan.`);
    }
    installed = hookSshSetNewkeys(moduleName, /* fallbackToScan */ !cipherInitHooked) || cipherInitHooked || installed;

    // 5. Plaintext PCAPNG capture — separate file (ssh_packet_hooks.ts).
    try {
        installed = installSshPacketHooks(moduleName, methodAddresses) || installed;
    } catch (e) {
        devlog_error(`[SSH] installSshPacketHooks failed for ${moduleName}: ${e}`);
    }
    if (!installed) devlog(`[SSH] no SSH hook resolvable in ${moduleName}`);
    return installed;
}

// Backward-compatible alias used by the platform loaders.
export { ssh_execute as ssh_detect_execute };
