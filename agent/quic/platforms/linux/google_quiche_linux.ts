import { installGoogleQuicheHooks } from "../../definitions/google_quiche.js";
import { log, devlog } from "../../../util/log.js";

export async function google_quiche_execute(moduleName: string, _is_base_hook: boolean) {
    log("[*] Google QUICHE detected in " + moduleName + ", installing QUIC stream hooks...");
    // installGoogleQuicheHooks is now async (its pattern-scan fallback yields to
    // the event loop so detach can be serviced mid-scan). Fire-and-forget caller,
    // so swallow + log any rejection here rather than leak an unhandled rejection.
    try {
        await installGoogleQuicheHooks(moduleName);
    } catch (e) {
        devlog("[Google QUICHE] install failed in " + moduleName + ": " + e);
    }
}
