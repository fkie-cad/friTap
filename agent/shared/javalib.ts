import Java_bridge from "frida-java-bridge";
import { devlog } from "../util/log.js";

// `any`-typed so this compiles against BOTH the real frida-java-bridge (main
// bundle) and the empty shim the slim Wine bundle aliases in via tsconfig
// `paths` (fkie-cad/friTap#52): carrying the bridge's bytes in the Wine bundle
// made early injection into a freshly-created Chromium network service
// unreliable, so the Wine bundle excludes them entirely. The main bundle keeps
// the real bridge for Android/iOS.
let Java: any;
const javaLegacy = (globalThis as any).Java;
if (javaLegacy && typeof javaLegacy.perform === "function") {
    devlog("[frida-java-bridge] Pre-v17 Frida detected. Using legacy global Java bridge.");
    Java = javaLegacy;
} else {
    devlog("[frida-java-bridge] Frida >=17 detected. Using 'frida-java-bridge' module.");
    Java = Java_bridge;
}
type JavaWrapper = any;
type JavaMethod = any;
export { Java, JavaWrapper, JavaMethod };
