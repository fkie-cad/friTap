// agent/mtproto/platforms/android/tgnet_android.ts
//
// Android executor for Telegram's native tgnet (MTProto) stack. Mirrors the
// SSH android executor's exported-function shape (e.g. openssh_execute_modern):
// a `(moduleName, is_base_hook) => void` entry that instantiates the lib class
// and installs hooks. Registered in agent/platforms/android.ts.

import { devlog } from "../../../util/log.js";
import { TGNET_Telegram } from "../../libs/tgnet_telegram.js";

/**
 * Entry point for hooking `libtmessages.tmessages.so`.
 *
 * @param moduleName   Resolved module name/path matched by the android table.
 * @param is_base_hook Whether this is the base (first) hook installation pass.
 */
export function tgnet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    try {
        const tgnet = new TGNET_Telegram(moduleName);
        tgnet.install_hooks();
    } catch (e) {
        devlog(`[tgnet_android] tgnet_execute_modern error on ${moduleName} (is_base_hook=${is_base_hook}): ${e}`);
    }
}
