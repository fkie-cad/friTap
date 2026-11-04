import { socket_library } from "../../../platforms/android.js";
import { pcap_enabled } from "../../../fritap_agent.js";
import { installChromiumPlaintextHooks } from "../../shared/chromium_plaintext.js";

// Supplementary entry point for Chromium monoliths (Chrome, WebView): TCP TLS
// plaintext only. Keys keep coming from the Cronet row of the same module; this
// row never marks the module hooked (registry `supplementary`).
// ModuleHookingType contract: `false` when nothing can be installed (no plaintext
// pcap), otherwise a Promise of whether the async locator found and hooked the API.
export function chromium_plaintext_execute(moduleName: string, is_base_hook: boolean): false | Promise<boolean> {
    if (!pcap_enabled) return false;
    return installChromiumPlaintextHooks(moduleName, socket_library as string, is_base_hook);
}
