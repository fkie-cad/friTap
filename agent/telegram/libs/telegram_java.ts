/**
 * Telegram Secret-Chat (E2E / MTProto 2.0) Java-layer live capture.
 *
 * Mirrors agent/signal/libs/signal_java.ts. Two independent concerns, gated
 * individually by the caller:
 *
 *   - KEY extraction (keylog intent) — read the byte[256] `auth_key` off the
 *     `EncryptedChat` argument carried by both hookable methods, derive the
 *     fingerprint as the LAST 8 bytes of SHA-1(auth_key) (matching the offline
 *     compute_secret_chat_fingerprint = sha1(key)[-8:]), and emit ONCE per
 *     fingerprint via sendKeyMaterial({contentType:"telegram_e2e_key", ...}).
 *     These keys feed friTap's OFFLINE Secret-Chat decryptor.
 *
 *   - PLAINTEXT capture (pcap intent) — extract the cleartext message String at
 *     the SecretChatHelper boundary and emit it as a {contentType:
 *     "telegram_e2e_plaintext", ...} message so it rides friTap's existing
 *     plaintext->PCAP pipeline (Python: message_router.py::
 *     _emit_telegram_e2e_plaintext -> DatalogEvent(protocol="telegram_e2e")).
 *
 * Hook targets (org.telegram.messenger 12.8.1; R8 did NOT rename these):
 *   - SecretChatHelper.processDecryptedObject(EncryptedChat, EncryptedFile,
 *       int date, TLObject obj, boolean) — incoming. `obj` is the decrypted
 *       object; unwrap TL_decryptedMessageLayer -> message.value
 *       (DecryptedMessage) -> message.value (text String). direction "read".
 *   - SecretChatHelper.performSendEncryptedRequest(DecryptedMessage req,
 *       Message, EncryptedChat, InputEncryptedFile, String, MessageObject)
 *       — outgoing. `req.message.value` is the text String. direction "write".
 *   - Both methods carry an EncryptedChat arg, so both can also read the key.
 *
 * Each Java.use()/field read is wrapped in its own try/catch (devlog on miss),
 * so a method overload absent in a given build is skipped without blocking the
 * rest. Process-global once-guard prevents stacking replacements when the
 * Telegram native lib is reported loaded multiple times.
 */

import { log, devlog } from "../../util/log.js";
import { sendWithProtocol, sendKeyMaterial } from "../../shared/shared_structures.js";
import { _isShuttingDown } from "../../fritap_agent.js";
import { Java } from "../../shared/javalib.js";
import {
    SECRET_CHAT_HELPER,
    METHODS,
    FIELDS,
} from "../definitions/telegram_e2e.js";

// Process-global guard. Java implementation swaps are process-wide, so even
// though telegram_android.ts guards install per-module, libtmessages can be
// reported loaded several times; we must never re-install the Java hooks (that
// would stack replacements). Guard once for the whole process.
let _telegramJavaHooksInstalled = false;

// One emission per Secret-Chat key, identified by its fingerprint hex. The same
// EncryptedChat flows through every processed message, so without this the agent
// would re-emit the key on every decrypt.
const _seenFingerprints = new Set<string>();

/**
 * Convert a Java `byte[]` (a JS array of signed 8-bit ints as surfaced by
 * frida-java-bridge) into an ArrayBuffer of unsigned bytes. Returns null when
 * the input is null/empty so callers can skip.
 */
function javaByteArrayToArrayBuffer(javaBytes: number[] | null): ArrayBuffer | null {
    if (javaBytes === null || javaBytes.length === 0) {
        return null;
    }
    const out = new Uint8Array(javaBytes.length);
    for (let i = 0; i < javaBytes.length; i++) {
        // Java bytes are signed (-128..127); & 0xff folds them back to 0..255.
        out[i] = javaBytes[i] & 0xff;
    }
    return out.buffer;
}

/** Lower-case hex of an unsigned byte array. */
function bytesToHex(bytes: Uint8Array): string {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += (bytes[i] & 0xff).toString(16).padStart(2, "0");
    }
    return hex;
}

/**
 * Read the byte[256] auth_key off an EncryptedChat wrapper as unsigned bytes.
 * Returns null when the field is absent/empty.
 */
function readAuthKeyBytes(encryptedChat: any): Uint8Array | null {
    try {
        if (encryptedChat === null || encryptedChat === undefined) return null;
        const field = encryptedChat[FIELDS.AUTH_KEY];
        if (field === null || field === undefined) return null;
        const javaBytes = field.value as number[] | null;
        const buf = javaByteArrayToArrayBuffer(javaBytes);
        if (buf === null) return null;
        return new Uint8Array(buf);
    } catch (e) {
        devlog(`[telegram_java] auth_key read error: ${e}`);
        return null;
    }
}

/**
 * Compute the Secret-Chat fingerprint = LAST 8 bytes of SHA-1(auth_key), hex.
 * Matches the offline compute_secret_chat_fingerprint() (sha1(key)[-8:]).
 */
function computeFingerprintHex(authKey: Uint8Array): string | null {
    try {
        const MessageDigest = Java.use("java.security.MessageDigest");
        const md = MessageDigest.getInstance("SHA-1");
        // digest(byte[]) expects signed Java bytes; pass the values directly —
        // frida-java-bridge accepts a JS number[] for a byte[] parameter.
        const input: number[] = [];
        for (let i = 0; i < authKey.length; i++) {
            // fold 0..255 back to signed -128..127 for the Java byte[] arg
            input.push(authKey[i] > 127 ? authKey[i] - 256 : authKey[i]);
        }
        const digest = md.digest(input) as number[];
        const out = new Uint8Array(digest.length);
        for (let i = 0; i < digest.length; i++) out[i] = digest[i] & 0xff;
        // last 8 bytes
        const last8 = out.subarray(out.length - 8);
        return bytesToHex(last8);
    } catch (e) {
        devlog(`[telegram_java] SHA-1 fingerprint error: ${e}`);
        return null;
    }
}

/** Read the int Secret-Chat id off an EncryptedChat wrapper; -1 on miss. */
function readChatId(encryptedChat: any): number {
    try {
        if (encryptedChat === null || encryptedChat === undefined) return -1;
        const field = encryptedChat[FIELDS.ID];
        if (field === null || field === undefined) return -1;
        const v = field.value;
        return typeof v === "number" ? v : -1;
    } catch (e) {
        devlog(`[telegram_java] chat_id read error: ${e}`);
        return -1;
    }
}

/**
 * Extract + emit the Secret-Chat key from an EncryptedChat, once per
 * fingerprint. Gated upstream by keylog (the install side) AND by
 * sendKeyMaterial's keylog_enabled choke point.
 */
function emitTelegramKey(encryptedChat: any): void {
    try {
        const authKey = readAuthKeyBytes(encryptedChat);
        if (authKey === null) return;
        const fingerprint = computeFingerprintHex(authKey);
        if (fingerprint === null) return;
        if (_seenFingerprints.has(fingerprint)) return;
        _seenFingerprints.add(fingerprint);

        const chatId = readChatId(encryptedChat);
        sendKeyMaterial({
            contentType: "telegram_e2e_key",
            shared_key: bytesToHex(authKey),
            key_fingerprint: fingerprint,
            chat_id: chatId,
        });
        log(`[telegram_java] Captured Secret-Chat key (fingerprint ${fingerprint}, chat_id ${chatId})`);
    } catch (e) {
        devlog(`[telegram_java] key extraction error: ${e}`);
    }
}

/**
 * Convert a decrypted-message text value to a UTF-8 ArrayBuffer. Returns null
 * when the input is null/empty so callers can skip emission.
 *
 * IMPORTANT: frida-java-bridge surfaces a Java `String` *field* read (`.value`)
 * as a JS string PRIMITIVE, not a Java String object — so `.getBytes("UTF-8")`
 * does not exist on it (that call threw and was silently swallowed, which is why
 * no live plaintext was ever emitted). We therefore UTF-8 encode in pure JS and
 * tolerate either a JS string or (defensively) anything string-coercible.
 */
function javaStringToUtf8Buffer(text: any): ArrayBuffer | null {
    try {
        if (text === null || text === undefined) return null;
        const s: string = (typeof text === "string") ? text : String(text);
        if (s.length === 0) return null;
        const out: number[] = [];
        for (let i = 0; i < s.length; i++) {
            let c = s.charCodeAt(i);
            if (c < 0x80) {
                out.push(c);
            } else if (c < 0x800) {
                out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
            } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
                const c2 = s.charCodeAt(++i);
                const cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
                out.push(
                    0xf0 | (cp >> 18),
                    0x80 | ((cp >> 12) & 0x3f),
                    0x80 | ((cp >> 6) & 0x3f),
                    0x80 | (cp & 0x3f),
                );
            } else {
                out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            }
        }
        return new Uint8Array(out).buffer;
    } catch (e) {
        devlog(`[telegram_java] String->UTF-8 error: ${e}`);
        return null;
    }
}

/**
 * Emit decrypted Secret-Chat plaintext to the Python side. Gated identically to
 * sendDatalog (skip once gracefulDetach has fired) — this is plaintext content,
 * not key material, so it is captured in plaintext-only (-p) mode like every
 * other protocol's datalog. Mirrors signal's emitSignalPlaintext.
 */
function emitTelegramPlaintext(
    func: string,
    direction: "read" | "write",
    chatId: number,
    plain: ArrayBuffer,
): void {
    if (_isShuttingDown) return;
    sendWithProtocol(
        {
            contentType: "telegram_e2e_plaintext",
            function: func,
            direction,
            transport: "tcp",
            chat_id: chatId,
        },
        plain,
    );
}

/**
 * Pull the text String out of an incoming decrypted `obj`. Unwrap chain (per
 * 12.8.1): TL_decryptedMessageLayer -> message.value (DecryptedMessage) ->
 * message.value (String). Defensive: the object may be a non-message TL type
 * (e.g. service actions) with no text — return null to skip those.
 */
function extractIncomingText(obj: any): any {
    try {
        if (obj === null || obj === undefined) return null;
        let candidate = obj;
        // If it is the layer wrapper, descend into its `message` field which
        // carries the DecryptedMessage.
        try {
            const layerMsg = obj[FIELDS.MESSAGE];
            if (layerMsg !== null && layerMsg !== undefined && layerMsg.value !== undefined && layerMsg.value !== null) {
                candidate = layerMsg.value;
            }
        } catch (_e) { /* not a layer wrapper — fall through to direct read */ }

        // candidate should now be a DecryptedMessage carrying a `message` String.
        const textField = candidate[FIELDS.MESSAGE];
        if (textField === null || textField === undefined) return null;
        const value = textField.value;
        if (value === null || value === undefined) return null;
        return value;
    } catch (e) {
        devlog(`[telegram_java] incoming text extract error: ${e}`);
        return null;
    }
}

/**
 * Pull the text String out of an outgoing DecryptedMessage `req`:
 * req.message.value (String).
 */
function extractOutgoingText(req: any): any {
    try {
        if (req === null || req === undefined) return null;
        const textField = req[FIELDS.MESSAGE];
        if (textField === null || textField === undefined) return null;
        const value = textField.value;
        if (value === null || value === undefined) return null;
        return value;
    } catch (e) {
        devlog(`[telegram_java] outgoing text extract error: ${e}`);
        return null;
    }
}

/**
 * Hook SecretChatHelper.processDecryptedObject — incoming path. Reads the key
 * off the EncryptedChat arg (position 0) and the plaintext off the decrypted
 * object arg (position 3). Each concern is independently enabled.
 */
function hookProcessDecryptedObject(SecretChatHelper: any, keylog: boolean, plaintext: boolean): void {
    try {
        const overloads = SecretChatHelper[METHODS.PROCESS_DECRYPTED_OBJECT].overloads;
        let bound = 0;
        for (const overload of overloads) {
            overload.implementation = function (...args: any[]) {
                try {
                    // arg 0: EncryptedChat. arg 3: decrypted TLObject `obj`.
                    if (keylog && args.length >= 1) {
                        emitTelegramKey(args[0]);
                    }
                    if (plaintext && args.length >= 4) {
                        const chatId = readChatId(args[0]);
                        const text = extractIncomingText(args[3]);
                        const buf = javaStringToUtf8Buffer(text);
                        if (buf !== null) {
                            emitTelegramPlaintext(
                                "SecretChatHelper.processDecryptedObject",
                                "read",
                                chatId,
                                buf,
                            );
                        }
                    }
                } catch (e) {
                    devlog(`[telegram_java] processDecryptedObject capture error: ${e}`);
                }
                return overload.apply(this, args);
            };
            bound++;
        }
        log(`[telegram_java] Hooked SecretChatHelper.processDecryptedObject (${bound} overload(s))`);
    } catch (e) {
        devlog(`[telegram_java] processDecryptedObject not hooked (method absent?): ${e}`);
    }
}

/**
 * Hook SecretChatHelper.performSendEncryptedRequest — outgoing path. Reads the
 * key off the EncryptedChat arg (position 2 in the first overload) and the
 * plaintext off the DecryptedMessage `req` arg (position 0). We scan args for an
 * EncryptedChat-shaped value to stay robust to overload ordering.
 */
function hookPerformSendEncryptedRequest(SecretChatHelper: any, keylog: boolean, plaintext: boolean): void {
    try {
        const overloads = SecretChatHelper[METHODS.PERFORM_SEND_ENCRYPTED_REQUEST].overloads;
        let bound = 0;
        for (const overload of overloads) {
            overload.implementation = function (...args: any[]) {
                try {
                    // The EncryptedChat is at position 2 in the documented first
                    // overload; locate it defensively by probing for an auth_key
                    // field so other overloads still yield the key.
                    let encryptedChat: any = null;
                    for (let i = 0; i < args.length; i++) {
                        const a = args[i];
                        try {
                            if (a !== null && a !== undefined && a[FIELDS.AUTH_KEY] !== undefined) {
                                encryptedChat = a;
                                break;
                            }
                        } catch (_e) { /* not an EncryptedChat — keep probing */ }
                    }
                    if (keylog && encryptedChat !== null) {
                        emitTelegramKey(encryptedChat);
                    }
                    if (plaintext && args.length >= 1) {
                        const chatId = readChatId(encryptedChat);
                        const text = extractOutgoingText(args[0]);
                        const buf = javaStringToUtf8Buffer(text);
                        if (buf !== null) {
                            emitTelegramPlaintext(
                                "SecretChatHelper.performSendEncryptedRequest",
                                "write",
                                chatId,
                                buf,
                            );
                        }
                    }
                } catch (e) {
                    devlog(`[telegram_java] performSendEncryptedRequest capture error: ${e}`);
                }
                return overload.apply(this, args);
            };
            bound++;
        }
        log(`[telegram_java] Hooked SecretChatHelper.performSendEncryptedRequest (${bound} overload(s))`);
    } catch (e) {
        devlog(`[telegram_java] performSendEncryptedRequest not hooked (method absent?): ${e}`);
    }
}

/**
 * Install the Telegram Secret-Chat Java-layer hooks for the requested concerns.
 *
 * @param opts.keylog    Install the auth_key extraction concern (keylog intent).
 * @param opts.plaintext Install the plaintext capture concern (pcap intent).
 *
 * No-op when the Java runtime is unavailable (non-Android / native-only) or when
 * neither concern is requested. Process-global guard ensures repeated module
 * loads do not re-hook. Each Java.use()/field read is defensive (try/catch +
 * devlog) so a missing overload never aborts the rest.
 */
export function install_telegram_e2e_hooks(opts: { keylog: boolean; plaintext: boolean }): void {
    if (!opts.keylog && !opts.plaintext) {
        devlog(`[telegram_java] Neither keylog nor plaintext requested; skipping Telegram E2E Java hooks.`);
        return;
    }
    if (_telegramJavaHooksInstalled) {
        devlog(`[telegram_java] Java hooks already installed; skipping.`);
        return;
    }
    if (!Java.available) {
        devlog(`[telegram_java] Java runtime not available — skipping Telegram E2E Java hooks.`);
        return;
    }

    _telegramJavaHooksInstalled = true;
    log(`[telegram_java] Installing Telegram Secret-Chat Java hooks (keylog=${opts.keylog}, plaintext=${opts.plaintext})`);

    Java.perform(function () {
        try {
            const SecretChatHelper = Java.use(SECRET_CHAT_HELPER);
            hookProcessDecryptedObject(SecretChatHelper, opts.keylog, opts.plaintext);
            hookPerformSendEncryptedRequest(SecretChatHelper, opts.keylog, opts.plaintext);
        } catch (e) {
            devlog(`[telegram_java] SecretChatHelper not resolved (class absent?): ${e}`);
        }
    });
}
