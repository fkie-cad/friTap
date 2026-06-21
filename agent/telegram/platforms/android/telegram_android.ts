// agent/telegram/platforms/android/telegram_android.ts
//
// Android executor for Telegram's Secret-Chat (E2E / MTProto 2.0) Java-layer
// live capture. Mirrors agent/signal/platforms/android/signal_android.ts: a
// `(moduleName, is_base_hook) => void` entry that installs the Java hooks under
// try/catch. Registered in agent/platforms/android.ts (protocol "telegram"),
// triggered when the Telegram native lib (libtmessages*.so) loads.
//
// The Secret-Chat key + plaintext both live in the Java layer
// (org.telegram.messenger.SecretChatHelper / TLRPC$EncryptedChat), so the
// native module load is used only as the install trigger; the actual hooks are
// Java.perform-based and installed by install_telegram_e2e_hooks().

import { devlog, log } from "../../../util/log.js";
import { keylog_enabled, pcap_enabled } from "../../../fritap_agent.js";
import { install_telegram_e2e_hooks } from "../../libs/telegram_java.js";

// One attempt per module. libtmessages*.so can be reported loaded several times
// during app startup; the Java hooks carry their own process-global once-guard,
// but guarding per-module too avoids redundant install attempts/log noise.
const _telegramAttempted = new Set<string>();

/**
 * Entry point for hooking the Telegram native lib (Secret-Chat trigger).
 *
 * Two independent capture intents, gated separately (friTap.py: -k sets
 * keylog_enabled, -p sets pcap_enabled). keylog_enabled -> Secret-Chat auth_key
 * extraction (keys for OFFLINE decrypt); pcap_enabled -> LIVE plaintext capture.
 * install_telegram_e2e_hooks() further gates each concern internally, so passing
 * both flags is safe; it installs only the requested ones.
 *
 * @param moduleName   Resolved module name/path matched by the android table.
 * @param is_base_hook Whether this is the base (first) hook installation pass.
 */
export function telegram_execute_modern(moduleName: string, is_base_hook: boolean): void {
    if (_telegramAttempted.has(moduleName)) {
        devlog(`[telegram_android] Secret-Chat hooks already attempted for ${moduleName}; skipping.`);
        return;
    }
    _telegramAttempted.add(moduleName);

    if (!keylog_enabled && !pcap_enabled) {
        devlog(`[telegram_android] neither keylog (-k) nor plaintext (-p) enabled; skipping Telegram Secret-Chat hooks on ${moduleName}.`);
        return;
    }

    log(`[telegram_android] Installing Telegram Secret-Chat hooks for ${moduleName} (keylog=${keylog_enabled}, plaintext=${pcap_enabled})`);
    try {
        install_telegram_e2e_hooks({ keylog: keylog_enabled, plaintext: pcap_enabled });
    } catch (e) {
        devlog(`[telegram_android] telegram_execute_modern error on ${moduleName} (is_base_hook=${is_base_hook}): ${e}`);
    }
}
