import { installGoogleQuicheHooks } from "../../definitions/google_quiche.js";
import { log } from "../../../util/log.js";

export function google_quiche_execute(moduleName: string, _is_base_hook: boolean) {
    log("[*] Google QUICHE detected in " + moduleName + ", installing QUIC stream hooks...");
    installGoogleQuicheHooks(moduleName);
}
