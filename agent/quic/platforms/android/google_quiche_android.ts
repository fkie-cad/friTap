import { installGoogleQuicheHooks } from "../../definitions/google_quiche.js";
import { log, devlog } from "../../../util/log.js";
import { pcap_enabled } from "../../../fritap_agent.js";

export function google_quiche_execute(moduleName: string, _is_base_hook: boolean) {
    if (!pcap_enabled) {
        devlog("[*] Google QUICHE detected in " + moduleName + " but plaintext pcap disabled; skipping QUIC stream hooks.");
        return;
    }
    log("[*] Google QUICHE detected in " + moduleName + ", installing QUIC stream hooks...");
    installGoogleQuicheHooks(moduleName);
}
