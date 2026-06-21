// agent/telegram/definitions/telegram_e2e.ts
//
// Static, data-only definitions for Telegram's Secret-Chat (E2E / MTProto-2.0
// over-the-MTProto) Java layer, shipped on Android inside the Telegram client
// (org.telegram.messenger). This is the single source of truth for the Java
// class names, method names, and field names the live-capture hooks resolve.
//
// Mirrors agent/signal/definitions/signal.ts in role: it carries only constants,
// no behaviour. The hook logic lives in agent/telegram/libs/telegram_java.ts.
//
// RE-VERIFICATION NOTE: every name below was re-verified on
// org.telegram.messenger 12.8.1 (Android). R8/ProGuard did NOT rename these
// symbols in that build — the Secret-Chat helper, the EncryptedChat TL type, and
// the decrypted-message TL wrappers all retained their source names. Names can
// drift between releases, so every Java.use()/field read in telegram_java.ts is
// wrapped in try/catch + devlog so a renamed/absent symbol is skipped rather
// than aborting the rest of the install.

/**
 * Secret-Chat orchestrator class. Carries both hookable methods:
 *   - processDecryptedObject(...)      — incoming decrypted plaintext
 *   - performSendEncryptedRequest(...) — outgoing plaintext
 * Both also receive an EncryptedChat from which the auth_key is read.
 */
export const SECRET_CHAT_HELPER = "org.telegram.messenger.SecretChatHelper";

/**
 * TL type holding the long-lived Secret-Chat key material and chat identity.
 * Field `auth_key` is the byte[256] shared key; `key_fingerprint` (long), `id`
 * (int chat id), `admin_id` (long creator), `participant_id` (long) identify it.
 */
export const ENCRYPTED_CHAT = "org.telegram.tgnet.TLRPC$EncryptedChat";

/**
 * TL wrapper for an incoming decrypted message. Unwrap chain:
 *   layer.message.value (TLRPC$DecryptedMessage) -> .message.value (text String)
 */
export const DECRYPTED_MESSAGE_LAYER = "org.telegram.tgnet.TLRPC$TL_decryptedMessageLayer";

/**
 * Hookable SecretChatHelper method names (re-verified on 12.8.1).
 */
export const METHODS = {
    /** Incoming: 4th arg `obj` is the decrypted TLObject. */
    PROCESS_DECRYPTED_OBJECT: "processDecryptedObject",
    /** Outgoing: 1st arg `req` is the DecryptedMessage being sent. */
    PERFORM_SEND_ENCRYPTED_REQUEST: "performSendEncryptedRequest",
} as const;

/**
 * Field names read off the EncryptedChat / DecryptedMessage TL objects. frida-
 * java-bridge surfaces public fields via `<wrapper>.<field>.value`.
 */
export const FIELDS = {
    /** byte[256] shared Secret-Chat key on EncryptedChat. */
    AUTH_KEY: "auth_key",
    /** long fingerprint Telegram itself computes for the key. */
    KEY_FINGERPRINT: "key_fingerprint",
    /** int Secret-Chat id on EncryptedChat. */
    ID: "id",
    /** long creator id on EncryptedChat. */
    ADMIN_ID: "admin_id",
    /** Nested TL field carrying a value on DecryptedMessage / layer wrappers. */
    MESSAGE: "message",
} as const;

/**
 * Length in bytes of the Secret-Chat auth_key (MTProto 2.0). The offline
 * fingerprint is computed as sha1(auth_key)[-8:] (last 8 bytes), matching
 * the Python-side compute_secret_chat_fingerprint().
 */
export const SECRET_CHAT_KEY_LEN = 256;
