import { socket_library } from "../../../platforms/android.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createNssHpkeDefinition } from "../../definitions/nss_hpke.js";

export function nss_hpke_execute_android(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(createNssHpkeDefinition(), moduleName, socket_library, is_base_hook, false);
}
