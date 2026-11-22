import { socket_library } from "../../../platforms/android.js";
import { chromiumPlaintextExecutor } from "../../shared/chromium_plaintext.js";

// Supplementary row for Chromium monoliths (Chrome, WebView), Cronet, Signal, Flutter: TCP TLS
// plaintext only; keys come from the module's primary row (registry `supplementary`).
export const chromium_plaintext_execute = chromiumPlaintextExecutor(() => socket_library);
