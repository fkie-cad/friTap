import type { default as ObjCTypes } from "frida-objc-bridge";
import ObjC_bridge from "frida-objc-bridge";
import { devlog } from "../util/log.js";  // Adjust the import path to your structure
let ObjC: typeof ObjC_bridge;
// Robust legacy detection with type check  
const objcLegacy = (globalThis as any).ObjC;
if (objcLegacy && typeof objcLegacy.perform === "function") {
    devlog("[frida-objc-bridge] Pre-v17 Frida detected. Using legacy global ObjC bridge.");
    ObjC = objcLegacy;
}
else {
    devlog("[frida-objc-bridge] Frida >=17 detected. Using 'frida-objc-bridge' module.");
    ObjC = ObjC_bridge;
}

export { ObjC, ObjCTypes };
