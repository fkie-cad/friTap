import { socket_library } from "../../../platforms/macos.js";
import { chromiumPlaintextExecutor } from "../../shared/chromium_plaintext.js";

// Supplementary row for Chrome / Electron frameworks: TCP TLS plaintext only; keys come from
// the "BoringSSL (Chromium Framework)" row of the same module (registry `supplementary`).
export const chromium_plaintext_execute = chromiumPlaintextExecutor(() => socket_library);
