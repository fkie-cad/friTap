import ObjC_bridge from "frida-objc-bridge";
import { devlog } from "../util/log.js";

// `any`-typed so this compiles against BOTH the real frida-objc-bridge (main
// bundle) and the slim Wine bundle's empty shim — see javalib.ts (friTap#52).
let ObjC: any;
const objcLegacy = (globalThis as any).ObjC;
if (objcLegacy && typeof objcLegacy.perform === "function") {
    devlog("[frida-objc-bridge] Pre-v17 Frida detected. Using legacy global ObjC bridge.");
    ObjC = objcLegacy;
} else {
    devlog("[frida-objc-bridge] Frida >=17 detected. Using 'frida-objc-bridge' module.");
    ObjC = ObjC_bridge;
}
type ObjCTypes = any;
export { ObjC, ObjCTypes };
