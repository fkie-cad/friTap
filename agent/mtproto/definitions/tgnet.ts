// agent/mtproto/definitions/tgnet.ts
//
// Static definitions for Telegram's native MTProto stack (tgnet), shipped on
// Android inside `libtmessages.tmessages.so`. This is the data-only home for
// every symbol name, file glob, and per-arch byte-pattern the Phase-0
// reverse-engineering effort will need to fill in.
//
// The two symbols used by the live keylog hook are now RE-verified on
// org.telegram.messenger 12.8.1 (native lib `libtmessages.49.so`, NOT stripped,
// ~37k exports):
//   - `_ZN10Datacenter10getAuthKeyE14ConnectionTypebPli`
//        ByteArray* Datacenter::getAuthKey(ConnectionType, bool perm,
//                                          int64_t* authKeyId, int allowPendingKey)
//   - `_ZN10Datacenter15getDatacenterIdEv`
//        int Datacenter::getDatacenterId()
// Symbol resolution works on this non-stripped build, so the per-arch
// byte-pattern arrays below stay empty — the pattern path remains a future
// fallback for stripped builds. Treat every `""` pattern as a TODO.

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
    getAuthKey: "",       // TODO(Phase 0): arm64 Datacenter::getAuthKey prologue
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
