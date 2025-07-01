import Java_bridge from "frida-java-bridge";
import { devlog } from "../util/log.js";  // Passe den Importpfad an deine Struktur an
import type JavaBridge from "frida-java-bridge";
let Java: typeof Java_bridge;

// Robust legacy detection with type check
const javaLegacy = (globalThis as any).Java;

if (javaLegacy && typeof javaLegacy.perform === "function") {
  devlog("[frida-java-bridge] Pre-v17 Frida detected. Using legacy global Java bridge.");
  Java = javaLegacy;
} else {
  devlog("[frida-java-bridge] Frida >=17 detected. Using 'frida-java-bridge' module.");
  Java = Java_bridge;
}






// Simple safe aliases using 'any' to avoid generic constraints
type JavaWrapper = JavaBridge.Wrapper<any>;
type JavaMethod = JavaBridge.Method<any>;

export { Java, JavaWrapper, JavaMethod };