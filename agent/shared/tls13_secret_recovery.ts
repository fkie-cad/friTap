/*
 * EXPERIMENTAL (Milestone 2 spike): TLS 1.3 traffic-secret recovery for ATTACH
 * mode. DISABLED BY DEFAULT — found NON-VIABLE for Signal on Android; kept as
 * documented scaffolding for future research. When `recoveryEnabled` is false
 * (the default) every entry point is a cheap no-op and the normal capture path
 * is completely unaffected.
 *
 * Idea: the handshake-only `ssl_log_secret`/Cronet keylog hook never fires for
 * connections established before friTap attached, so those sessions yield no
 * keys. The hope was that BoringSSL retains the current application traffic
 * secrets in `ssl->s3` (read/write_traffic_secret, kept for KeyUpdate); LEARN
 * the offset from a witnessed handshake, then RECOVER it for un-witnessed
 * connections.
 *
 * DEVICE FINDINGS (Pixel 7, libsignal_jni.so, 2026-06-15) — three walls:
 *   1. NOT RETAINED: a safe read-compare sweep of the entire SSL3_STATE (s3)
 *      allocation found neither CLIENT_ nor SERVER_TRAFFIC_SECRET_0 — the raw
 *      secret is not kept inline in s3 in this build (it lives in the freed
 *      bssl::SSL_HANDSHAKE struct or only as derived AEAD state).
 *   2. NO TRIGGER: libsignal is stripped, statically-linked BoringSSL hooked
 *      ONLY at the handshake keylog function (Cronet pattern path); it exposes
 *      no SSL_read/SSL_write hook points, so there is no per-connection trigger
 *      to run RECOVER on already-established connections during attach.
 *   3. SCAN UNSAFE: Memory.scan over the live scudo/MTE-tagged heap SIGSEGVs
 *      even when deferred off the interceptor thread (the libringrtc tombstone
 *      hazard) — hence the offset probe uses readByteArray + byte-compare only.
 *
 * Also: s3 pointers are ARM64 top-byte/scudo TAGGED (e.g. 0xb40000…); reads work
 * via Top-Byte-Ignore, but Process.findRangeByAddress needs the untagged base.
 *
 * CONCLUSION: reliable Signal key capture on attach = SPAWN (`-s`, fully
 * working) or a FORCE-RECONNECT helper (drop the chat socket so Signal
 * re-handshakes and the existing keylog hook fires) — no memory archaeology.
 */
import { sendKeylog } from "./shared_structures.js";
import { get_hex_string_from_byte_array } from "./shared_functions.js";
import { findS3, readClientRandomHex, isMostlyZero } from "./ssl_struct_walk.js";
import { FifoSet } from "./lru.js";
import { devlog_debug, log } from "../util/log.js";
import { keylog_enabled } from "../fritap_agent.js";

// NSS keylog labels for the TLS 1.3 application traffic secrets.
const LABEL_CLIENT = "CLIENT_TRAFFIC_SECRET_0";
const LABEL_SERVER = "SERVER_TRAFFIC_SECRET_0";

// EXPERIMENTAL, OFF by default (see file header for why). When false, every
// entry point early-returns and the normal capture path is untouched.
let recoveryEnabled = false;

export function setTls13AttachRecoveryEnabled(value: boolean): void {
    recoveryEnabled = value;
}

const SEEN_CACHE_MAX = 4096;
// Upper bound (bytes) of the s3 region we scan for a known secret. The traffic
// secrets live well within SSL3_STATE; clamped further to the live range size.
const S3_SCAN_WINDOW = 0x2000;
const MIN_SECRET_LEN = 16;
const MAX_SECRET_LEN = 64;

// SSL* whose handshake we witnessed (keys already emitted the normal way) — we
// must NOT re-extract these from memory (it would just duplicate the keys).
const loggedSsl = new FifoSet<string>(SEEN_CACHE_MAX);
// SSL* already recovered via struct walk (one extraction attempt per session).
const recoveredSsl = new FifoSet<string>(SEEN_CACHE_MAX);

interface Discovery {
    clientOff: number | null;   // byte offset of CLIENT_TRAFFIC_SECRET_0 within s3
    serverOff: number | null;   // byte offset of SERVER_TRAFFIC_SECRET_0 within s3
    clientLen: number;
    serverLen: number;
    module: string;             // module the ground truth came from (scope guard)
}
const discovery: Discovery = {
    clientOff: null, serverOff: null, clientLen: 0, serverLen: 0, module: "",
};

function bothOffsetsKnown(): boolean {
    return discovery.clientOff !== null && discovery.serverOff !== null;
}

/*
 * Locate *secret* within s3 by READING fixed candidate offsets and byte-comparing
 * — deliberately NOT Memory.scan, which faults on this target's scudo/MTE heap
 * (uncatchable SIGSEGV, same hazard as the libringrtc tombstone). Plain
 * readByteArray works on the tagged pointer via ARM Top-Byte-Ignore (proven by
 * the client_random read), so this stays survivable.
 */
function scanS3ForSecret(s3Ptr: NativePointer, secret: Uint8Array): number | null {
    const len = secret.length;
    for (let off = 0x38; off + len <= S3_SCAN_WINDOW; off += 4) {
        let buf: ArrayBuffer | null;
        try {
            buf = s3Ptr.add(off).readByteArray(len);
        } catch (_) {
            continue;
        }
        if (!buf) continue;
        const u8 = new Uint8Array(buf);
        let match = true;
        for (let i = 0; i < len; i++) {
            if (u8[i] !== secret[i]) { match = false; break; }
        }
        if (match) return off;
    }
    return null;
}

/* Mark an SSL* as already keyed via the witnessed handshake (no re-extraction). */
export function noteHandshakeLogged(sslPtr: NativePointer): void {
    if (!recoveryEnabled || sslPtr.isNull()) return;
    loggedSsl.add(sslPtr.toString());
}

/*
 * LEARN step. Called from the ssl_log_secret hook with the ground-truth secret.
 * Locates the per-label offset within s3 once and caches it.
 */
export function observeHandshakeSecret(
    moduleName: string,
    sslPtr: NativePointer,
    label: string,
    secret: Uint8Array,
): void {
    if (!recoveryEnabled || !keylog_enabled || sslPtr.isNull()) return;
    if (secret.length < MIN_SECRET_LEN || secret.length > MAX_SECRET_LEN) return;
    const isClient = label === LABEL_CLIENT;
    const isServer = label === LABEL_SERVER;
    if (!isClient && !isServer) return;
    if (isClient && discovery.clientOff !== null) return;
    if (isServer && discovery.serverOff !== null) return;

    // Defer the s3 offset probe OFF the interceptor thread: doing memory work
    // from inside the keylog hook can fault the instrumented JNI thread. Copy
    // the secret now (its buffer is only valid here) and probe shortly after.
    const secretCopy = Uint8Array.from(secret);
    setTimeout(() => learnSecretOffset(moduleName, sslPtr, label, isClient, secretCopy), 0);
}

function learnSecretOffset(
    moduleName: string,
    sslPtr: NativePointer,
    label: string,
    isClient: boolean,
    secret: Uint8Array,
): void {
    if (isClient && discovery.clientOff !== null) return;
    if (!isClient && discovery.serverOff !== null) return;
    const s3 = findS3(sslPtr);
    if (!s3) return;
    const off = scanS3ForSecret(s3, secret);
    if (off === null) return;

    if (isClient) {
        discovery.clientOff = off;
        discovery.clientLen = secret.length;
    } else {
        discovery.serverOff = off;
        discovery.serverLen = secret.length;
    }
    discovery.module = moduleName;
    log(`[*] TLS1.3 attach-recovery: learned ${label} at s3+0x${off.toString(16)} ` +
        `(len ${secret.length}) in ${moduleName}`);
}

function emitSecret(
    label: string, clientRandom: string, s3: NativePointer, off: number, len: number,
): boolean {
    try {
        const buf = s3.add(off).readByteArray(len);
        if (!buf) return false;
        const u8 = new Uint8Array(buf as ArrayBuffer);
        if (isMostlyZero(u8)) return false;
        sendKeylog(`${label} ${clientRandom} ${get_hex_string_from_byte_array(u8)}`);
        return true;
    } catch (e) {
        devlog_debug(`[tls13-recover] emit ${label} failed: ${e}`);
        return false;
    }
}

/*
 * RECOVER step. Called once per SSL* from the SSL_read/SSL_write hooks. No-op
 * unless we (a) have learned both offsets, (b) are on the discovery module, and
 * (c) did NOT witness this SSL*'s handshake. Reads the retained traffic secrets
 * straight out of s3 and emits them as NSS keylog lines.
 */
export function recoverTls13Secrets(moduleName: string, sslPtr: NativePointer): void {
    if (!recoveryEnabled || !keylog_enabled || sslPtr.isNull()) return;
    if (!bothOffsetsKnown()) return;
    if (discovery.module && moduleName !== discovery.module) return;

    const key = sslPtr.toString();
    if (loggedSsl.has(key) || recoveredSsl.has(key)) return;
    // One-shot: mark before doing the work so a failed attempt isn't retried on
    // every subsequent read of the same connection.
    recoveredSsl.add(key);

    const s3 = findS3(sslPtr);
    if (!s3) return;
    const clientRandom = readClientRandomHex(s3);
    if (!clientRandom) return;

    const okC = emitSecret(LABEL_CLIENT, clientRandom, s3, discovery.clientOff!, discovery.clientLen);
    const okS = emitSecret(LABEL_SERVER, clientRandom, s3, discovery.serverOff!, discovery.serverLen);
    if (okC || okS) {
        log(`[*] TLS1.3 attach-recovery: recovered keys for un-witnessed connection ` +
            `(cr=${clientRandom.substring(0, 16)}…)`);
    }
}
