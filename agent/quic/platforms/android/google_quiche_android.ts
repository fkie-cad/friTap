import { installGoogleQuicheHooks } from "../../definitions/google_quiche.js";
import { log, devlog } from "../../../util/log.js";
import { pcap_enabled } from "../../../fritap_agent.js";

export async function google_quiche_execute(moduleName: string, _is_base_hook: boolean) {
    if (!pcap_enabled) {
        devlog("[*] Google QUICHE detected in " + moduleName + " but plaintext pcap disabled; skipping QUIC stream hooks.");
        return;
    }
    log("[*] Google QUICHE detected in " + moduleName + ", installing QUIC stream hooks...");
    // installGoogleQuicheHooks is now async (its pattern-scan fallback yields to
    // the event loop so detach can be serviced mid-scan). The dispatcher calls
    // us fire-and-forget, so swallow + log any rejection here rather than leak an
    // unhandled promise rejection into Frida.
    try {
        await installGoogleQuicheHooks(moduleName);
    } catch (e) {
        devlog("[Google QUICHE] install failed in " + moduleName + ": " + e);
    }
}
