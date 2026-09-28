// agent/mtproto/definitions/tgnet.ts
//
// Static definitions for Telegram's native MTProto stack (tgnet), shipped on
// Android inside `libtmessages.tmessages.so`. This is the data-only home for
// every symbol name, file glob, and per-arch byte-pattern the Phase-0
// reverse-engineering effort will need to fill in.
//
// The keylog hook needs `Datacenter::getAuthKey`:
//   - `_ZN10Datacenter10getAuthKeyE14ConnectionTypebPli`
//        ByteArray* Datacenter::getAuthKey(ConnectionType, bool perm,
//                                          int64_t* authKeyId, int allowPendingKey)
//   - `_ZN10Datacenter15getDatacenterIdEv`
//        int Datacenter::getDatacenterId()
//
// IMPORTANT — RE-verified on org.telegram.messenger 12.8.1 (libtmessages.49.so,
// arm64): these tgnet C++ methods are **stripped local symbols**. The library
// exports only its JNI surface — objdump shows .dynsym = 716 entries (no
// getAuthKey) and .symtab = 4 entries (stripped) — so BOTH enumerateExports()
// (.dynsym) and enumerateSymbols() (.symtab) miss them. Symbol resolution CANNOT
// find getAuthKey on a release build; the byte-pattern scan below is the only
// viable path. `Datacenter::getAuthKey` was located at file offset 0xB05EE4 via
// the native_getCurrentAuthKeyId JNI chain; its arm64 prologue pattern is filled
// in TGNET_PATTERNS_ARM64 below. `getAuthKey` is emitted primarily from the
// per-protocol pattern file friTap/patterns/default_mtproto.json (delivered at
// runtime); TGNET_PATTERNS_ARM64 is the compiled-in fallback. arm32/x64 remain
// TODO. Symbol resolution stays as a first attempt for any non-stripped build.

/**
 * The Android native library that carries Telegram's tgnet MTProto stack.
 * On modern Telegram builds the symbols are stripped, so symbol-based
 * resolution will usually fail and Phase-0 byte patterns become mandatory.
 */
export const TGNET_LIBRARY_NAME = "libtmessages.tmessages.so";

/**
 * Looser library-name matchers. Telegram forks and ABI-split APKs sometimes
 * version-decorate the soname (e.g. `libtmessages.<n>.so`). The android
 * platform table registers both the exact name and a loose `/libtmessages.*\.so/`.
 */
export const TGNET_LIBRARY_REGEX_EXACT = /libtmessages\.tmessages\.so/;
export const TGNET_LIBRARY_REGEX_LOOSE = /libtmessages.*\.so/;

/**
 * Mangled C++ symbol names we attempt to resolve before falling back to
 * pattern scanning.
 *
 * `Datacenter::getAuthKey()` returns the permanent/temporary auth key for a
 * datacenter. Hooking it is the cleanest place to dump (auth_key_id, auth_key,
 * dc_id) because both the key bytes and the owning Datacenter are in scope.
 *
 * The exact mangling depends on the Itanium ABI signature of the method.
 * `getAuthKey()` (no args) most plausibly mangles as `_ZN10Datacenter10getAuthKeyEv`,
 * but overloads taking a `bool perm` / `ConnectionType` argument exist across
 * versions, so we keep a small candidate list and try each.
 */
export const SYM_DATACENTER_GET_AUTH_KEY_CANDIDATES: string[] = [
    // RE-verified on org.telegram.messenger 12.8.1 (libtmessages.49.so):
    //   ByteArray* Datacenter::getAuthKey(ConnectionType, bool perm,
    //                                     int64_t* authKeyId, int allowPendingKey)
    "_ZN10Datacenter10getAuthKeyE14ConnectionTypebPli",
    "_ZN10Datacenter10getAuthKeyEv",        // getAuthKey()
    "_ZN10Datacenter10getAuthKeyEb",        // getAuthKey(bool)
    "_ZN10Datacenter10getAuthKeyE14ConnectionType", // getAuthKey(ConnectionType)
    "_ZN10Datacenter10getAuthKeyEi",        // getAuthKey(int)
];

/**
 * Verified export for the datacenter id getter on 12.8.1:
 *   int Datacenter::getDatacenterId()
 * Called as a NativeFunction(addr, 'int', ['pointer']) on a saved Datacenter*
 * to resolve the real dc_id (replaces the placeholder 0).
 */
export const SYM_DATACENTER_GET_DATACENTER_ID = "_ZN10Datacenter15getDatacenterIdEv";

/**
 * MTProto plaintext boundary functions, RE-verified on org.telegram.messenger
 * 12.8.1 (libtmessages.49.so, non-stripped). Both directions funnel through
 * Datacenter, so the plaintext hook resolves these by symbol (with a fuzzy
 * export-scan fallback) exactly like getAuthKey.
 *
 * INBOUND (post-decrypt):
 *   bool Datacenter::decryptServerResponse(int64_t keyId, uint8_t* key,
 *                                          uint8_t* data, uint32_t length,
 *                                          Connection* connection)
 *   `data` is AES-IGE decrypted IN PLACE, so reading it onLeave yields the
 *   decrypted MTProto message (server salt + session + msg_id + body + padding).
 *   As a non-static method the hooked args are:
 *     args[0]=this, args[1]=keyId, args[2]=key, args[3]=data,
 *     args[4]=length, args[5]=Connection*.
 */
export const SYM_DATACENTER_DECRYPT_SERVER_RESPONSE_CANDIDATES: string[] = [
    "_ZN10Datacenter21decryptServerResponseElPhS0_jP10Connection",
];

/**
 * OUTBOUND (pre-encrypt) + the shared AES-IGE primitive:
 *   static void Datacenter::aesIgeEncryption(uint8_t* buffer, uint8_t* key,
 *                                            uint8_t* iv, bool encrypt,
 *                                            bool changeIv, uint32_t length)
 *   In-place AES-IGE used for BOTH directions. When `encrypt` is true the call
 *   encrypts an outgoing message, so `buffer` holds the plaintext at onEnter.
 *   This is a STATIC method (no implicit `this`) — RE-confirmed at runtime by
 *   observing 16-byte-aligned lengths land in args[5] and changeIv in args[4]:
 *     args[0]=buffer, args[1]=key, args[2]=iv,
 *     args[3]=encrypt(bool), args[4]=changeIv(bool), args[5]=length.
 */
export const SYM_DATACENTER_AES_IGE_ENCRYPTION_CANDIDATES: string[] = [
    "_ZN10Datacenter16aesIgeEncryptionEPhS0_S0_bbj",
];

/** Fuzzy export-scan fragments for the inbound decrypt boundary. */
export const DECRYPT_SERVER_RESPONSE_NAME_FRAGMENTS: { class: RegExp; method: RegExp } = {
    class: /datacenter/i,
    method: /decryptserverresponse/i,
};

/** Fuzzy export-scan fragments for the AES-IGE primitive (outbound). */
export const AES_IGE_ENCRYPTION_NAME_FRAGMENTS: { class: RegExp; method: RegExp } = {
    class: /datacenter/i,
    method: /aesigeencryption/i,
};

/**
 * Case-insensitive fragment matchers used when scanning `enumerateExports`
 * for a getAuthKey-like symbol whose exact mangling we did not anticipate.
 * A symbol qualifies when its name matches BOTH fragments.
 */
export const GET_AUTH_KEY_NAME_FRAGMENTS: { class: RegExp; method: RegExp } = {
    class: /datacenter/i,
    method: /getauthkey/i,
};

/**
 * Glob patterns for Telegram's on-disk auth-key store (`tgnet.dat`). Useful for
 * an offline / disk-based fallback path that parses the persisted auth keys
 * directly instead of hooking. Not consumed by the agent yet — recorded here so
 * the Phase-0 implementer has a single source of truth.
 */
export const TGNET_DAT_PATH_GLOBS: string[] = [
    "/data/data/org.telegram.messenger/files/tgnet.dat",
    "/data/data/org.telegram.messenger.web/files/tgnet.dat",
    "/data/data/org.telegram.messenger.beta/files/tgnet.dat",
    "/data/user/*/org.telegram.*/files/tgnet.dat",
];

/**
 * Per-architecture byte-pattern home for Phase-0 results.
 *
 * Each entry is a Frida-style space-separated hex pattern (wildcards `??`)
 * locating the prologue of the target function. They MUST NOT begin or end
 * with `??` (Frida rejects such patterns — see the pattern-scan gotchas note).
 *
 * TODO(Phase 0): fill these in from an on-device scan of
 * `libtmessages.tmessages.so`. Empty string = "not yet reverse engineered".
 */
export interface TgnetBytePatterns {
    /** Pattern locating Datacenter::getAuthKey (key extraction). */
    getAuthKey: string;
    /** Pattern locating the post-AES-IGE-decrypt inbound buffer handler. */
    decryptInbound: string;
    /** Pattern locating the pre-AES-IGE-encrypt outbound buffer handler. */
    encryptOutbound: string;
}

export const TGNET_PATTERNS_ARM64: TgnetBytePatterns = {
    // RE-verified on org.telegram.messenger 12.8.1 / libtmessages.49.so (arm64):
    // Datacenter::getAuthKey @ 0xB05EE4. Anchors at the function-entry prologue;
    // empirically unique (1 match) in the module. The two `??` bytes mask only the
    // imm12 struct-offset of `LDRB W8,[X0,#0x1A0]` (the field offset most likely to
    // drift across app versions). Does not begin/end with `??` (Frida requirement).
    // Kept in sync with friTap/patterns/default_mtproto.json (the primary source).
    getAuthKey: "FD 7B BB A9 F9 0B 00 F9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 03 00 91 08 ?? ?? 39 F3 03 03 AA",
    decryptInbound: "",   // TODO(Phase 0): arm64 inbound plaintext buffer site
    encryptOutbound: "",  // TODO(Phase 0): arm64 outbound plaintext buffer site
};

export const TGNET_PATTERNS_ARM32: TgnetBytePatterns = {
    getAuthKey: "",       // TODO(Phase 0): arm (32-bit) Datacenter::getAuthKey prologue
    decryptInbound: "",   // TODO(Phase 0): arm (32-bit) inbound plaintext buffer site
    encryptOutbound: "",  // TODO(Phase 0): arm (32-bit) outbound plaintext buffer site
};

export const TGNET_PATTERNS_X64: TgnetBytePatterns = {
    getAuthKey: "",       // TODO(Phase 0): x86_64 Datacenter::getAuthKey prologue
    decryptInbound: "",   // TODO(Phase 0): x86_64 inbound plaintext buffer site
    encryptOutbound: "",  // TODO(Phase 0): x86_64 outbound plaintext buffer site
};

/**
 * Select the byte-pattern set for the current process architecture.
 * Returns the arm64 set as a harmless default for unknown arches (its patterns
 * are still empty, so the caller falls through to the Phase-0 warning path).
 */
export function getTgnetPatternsForArch(): TgnetBytePatterns {
    switch (Process.arch) {
        case "arm64":
            return TGNET_PATTERNS_ARM64;
        case "arm":
            return TGNET_PATTERNS_ARM32;
        case "x64":
            return TGNET_PATTERNS_X64;
        default:
            return TGNET_PATTERNS_ARM64;
    }
}

/** MTProto auth-key sizes (bytes). Used to size onLeave memory reads. */
export const MTPROTO_AUTH_KEY_LEN = 256;     // 2048-bit auth key
export const MTPROTO_AUTH_KEY_ID_LEN = 8;    // low 64 bits of SHA1(auth_key)

/**
 * Layout of the tgnet `ByteArray` struct returned by Datacenter::getAuthKey,
 * as VERIFIED at runtime on Telegram 12.8.1 / libtmessages.49.so (arm64):
 *
 *   struct ByteArray {
 *       uint32_t length;   // offset 0: number of valid bytes (256 for auth keys)
 *       uint8_t* bytes;    // offset 8: pointer to the raw key bytes
 *   };
 *
 * (Confirmed by observing retval[0] == 0x100 == 256, i.e. the length, and the
 * key pointer living at offset 8 — the reverse of the naive {bytes,length} order.)
 */
export const BYTEARRAY_LENGTH_OFFSET = 0;
export const BYTEARRAY_BYTES_OFFSET = 8;

/**
 * Offset of the `int datacenterId` field on the tgnet `Datacenter` object,
 * RE-verified on 12.8.1 / libtmessages.49.so (arm64): the getDatacenterId getter
 * is exactly `LDR W0,[X0,#0x14]; RET`. Used as a fallback for dc_id when the
 * getDatacenterId symbol is stripped. Informational only (offline decrypt joins
 * by auth_key_id), so a wrong offset on another build merely yields a bogus/0 id.
 */
export const DATACENTER_ID_OFFSET = 0x14;

/* ---------------------------------------------------------------------------
 * Tier E — per-connection obfuscated-transport CTR state (mid-stream recovery).
 *
 * DISABLED, PENDING ON-DEVICE REVERSE ENGINEERING. Everything below is empty
 * scaffolding, exactly like the empty Phase-0 byte patterns above: the offsets
 * require physical-device RE we cannot do here, so the Tier E scanner ships gated
 * OFF and reads these placeholders only to self-report "off".
 *
 * WHY THIS TIER EXISTS
 *   MTProto's obfuscated transport is AES-256-CTR. The per-direction key/IV are
 *   derived from the first 64 client bytes (the "init block"), which are MISSED
 *   when a connection was already open before the capture started. tgnet does not
 *   retain that init block, but it DOES hold the live per-direction CTR state on
 *   the native `Connection` object for as long as the connection is alive:
 *     - the expanded AES-256 key schedule (raw key = the first 8 schedule words,
 *       big-endian — RE MUST re-confirm this endianness on the target build),
 *     - the live 16-byte CTR counter block (`ivec`), and
 *     - the byte-phase (`num`) into the current keystream block.
 *   Recovering these lets the offline path (friTap/offline/mtproto/transport.py
 *   ObfuscationCipher.from_recovered + recover_obf_alignment) de-obfuscate a
 *   mid-stream Telegram connection whose init block was never captured.
 *
 * ALIVE-DURING-SCAN REQUIREMENT
 *   The CTR state is only valid while the connection is OPEN. Once tgnet tears the
 *   Connection down the fields are freed/reused, so this tier is meaningful only
 *   for connections that are still alive at scan time.
 *
 * ANCHOR
 *   The `Connection` object's first qword is its C++ vtable pointer
 *   (`_ZTV10Connection`), resolved at configure time; the runtime needle is that
 *   pointer's little-endian bytes (mirroring how Tier B needles an auth_key_id).
 */

/**
 * The C++ vtable symbol for tgnet's `Connection`. Resolved at configure time to a
 * runtime address; its little-endian bytes become the Tier E scan needle.
 * Non-empty so the resolver has something to look up, but the tier stays gated OFF
 * until the struct offsets below are filled in by Phase-0 RE.
 */
export const SYM_CONNECTION_VTABLE = "_ZTV10Connection";

/**
 * Per-arch `Connection` CTR-field offsets (bytes from the object base). arm64
 * first. ALL null == "not yet reverse engineered"; a null offset keeps Tier E
 * self-reporting "off" (it never reads or emits).
 *
 * TODO(Phase 0, on-device): fill these from an on-device scan of a LIVE Connection
 *   in `libtmessages.tmessages.so`:
 *     encrypt_key   -> expanded AES-256 key schedule, client->server ("out")
 *     encrypt_ivec  -> live 16-byte CTR counter block, client->server
 *     encrypt_num   -> int byte-phase (0..15), client->server
 *     decrypt_key   -> expanded AES-256 key schedule, server->client ("in")
 *     decrypt_ivec  -> live 16-byte CTR counter block, server->client
 *     decrypt_num   -> int byte-phase (0..15), server->client
 */
export interface ConnectionCtrOffsets {
    encrypt_key: number | null;
    encrypt_ivec: number | null;
    encrypt_num: number | null;
    decrypt_key: number | null;
    decrypt_ivec: number | null;
    decrypt_num: number | null;
}

export const CONNECTION_OFFSETS_ARM64: ConnectionCtrOffsets = {
    encrypt_key: null,   // TODO(Phase 0): arm64 Connection encrypt AES key schedule
    encrypt_ivec: null,  // TODO(Phase 0): arm64 Connection encrypt live CTR counter
    encrypt_num: null,   // TODO(Phase 0): arm64 Connection encrypt byte-phase
    decrypt_key: null,   // TODO(Phase 0): arm64 Connection decrypt AES key schedule
    decrypt_ivec: null,  // TODO(Phase 0): arm64 Connection decrypt live CTR counter
    decrypt_num: null,   // TODO(Phase 0): arm64 Connection decrypt byte-phase
};

export const CONNECTION_OFFSETS_ARM32: ConnectionCtrOffsets = {
    encrypt_key: null,   // TODO(Phase 0): arm (32-bit) Connection encrypt key schedule
    encrypt_ivec: null,  // TODO(Phase 0): arm (32-bit) Connection encrypt CTR counter
    encrypt_num: null,   // TODO(Phase 0): arm (32-bit) Connection encrypt byte-phase
    decrypt_key: null,   // TODO(Phase 0): arm (32-bit) Connection decrypt key schedule
    decrypt_ivec: null,  // TODO(Phase 0): arm (32-bit) Connection decrypt CTR counter
    decrypt_num: null,   // TODO(Phase 0): arm (32-bit) Connection decrypt byte-phase
};

export const CONNECTION_OFFSETS_X64: ConnectionCtrOffsets = {
    encrypt_key: null,   // TODO(Phase 0): x86_64 Connection encrypt key schedule
    encrypt_ivec: null,  // TODO(Phase 0): x86_64 Connection encrypt CTR counter
    encrypt_num: null,   // TODO(Phase 0): x86_64 Connection encrypt byte-phase
    decrypt_key: null,   // TODO(Phase 0): x86_64 Connection decrypt key schedule
    decrypt_ivec: null,  // TODO(Phase 0): x86_64 Connection decrypt CTR counter
    decrypt_num: null,   // TODO(Phase 0): x86_64 Connection decrypt byte-phase
};

/**
 * `ConnectionSocket` offset placeholders. Reserved for a future RE step that must
 * confirm whether the CTR state lives directly on `Connection` or on an inner
 * `ConnectionSocket` it owns. Empty until Phase-0 RE settles the ownership.
 *
 * TODO(Phase 0, on-device): if the CTR fields live on ConnectionSocket, record the
 *   Connection->socket pointer offset here and rebase the offsets above onto it.
 */
export const CONNECTION_SOCKET_OFFSETS_ARM64: { socket_ptr: number | null } = {
    socket_ptr: null,  // TODO(Phase 0): Connection -> ConnectionSocket pointer offset
};

/** MTProto obfuscation CTR sizes (bytes). Used to size Tier E memory reads. */
export const MTPROTO_OBF_KEY_LEN = 32;   // AES-256 key
export const MTPROTO_OBF_IVEC_LEN = 16;  // 128-bit CTR counter block

/**
 * Select the `Connection` CTR offsets for the current process architecture.
 * Returns the arm64 set (all null) as a harmless default for unknown arches, so
 * the caller falls through to the Tier E "off" path.
 */
export function getConnectionOffsetsForArch(): ConnectionCtrOffsets {
    switch (Process.arch) {
        case "arm64":
            return CONNECTION_OFFSETS_ARM64;
        case "arm":
            return CONNECTION_OFFSETS_ARM32;
        case "x64":
            return CONNECTION_OFFSETS_X64;
        default:
            return CONNECTION_OFFSETS_ARM64;
    }
}
