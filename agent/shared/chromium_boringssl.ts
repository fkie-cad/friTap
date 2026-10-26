// agent/shared/chromium_boringssl.ts
//
// Key extraction for BoringSSL statically linked into Chromium-based Windows
// binaries: CEF (libcef.dll), Chrome / Edge (chrome.dll, msedge.dll), Qt
// WebEngine (Qt5/Qt6WebEngineCore.dll) and Electron apps (BoringSSL inside the
// app's own .exe). These are the launchers from fkie-cad/friTap#52 (Battle.net,
// EA app, Ubisoft Connect, Epic Games Launcher).
//
// None of them export SSL_CTX_set_keylog_callback or carry ssl_log_secret
// symbols, and their codegen changes every Chromium release, so the callback,
// symbol and byte-pattern tiers cannot work. They go straight to the tier-4
// anchor locator (boringssl_anchor_locator.ts) — the same ssl_log_secret hook
// used for stripped Android libchrome.so — which finds ssl_log_secret by the
// keylog-label xrefs and installs friTap's keylog callback into
// ctx->keylog_callback. Under Wine the module is PE (Win64 ABI) code inside a
// Linux-host Frida, so its ABI is pinned to win64 first (see call_abi.ts).

import { keylog_enabled } from "../fritap_agent.js";
import { devlog, log } from "../util/log.js";
import { setModuleCallAbi } from "./call_abi.js";
import { onAllKeylogTiersMissed, startTier4Once } from "./boringssl_keylog_outcome.js";
import { makeBoringSslDumpKeys } from "./boringssl_symbol_hook.js";
import { listPeImages, type ModuleLike } from "../util/proc_maps.js";
import { isTlsFamilyRequested } from "./shared_functions.js";

/** Module-name patterns of Chromium-family binaries with embedded BoringSSL. */
export const CHROMIUM_BORINGSSL_MODULES: RegExp[] = [
    /^libcef\.dll$/i,
    /^chrome\.dll$/i,
    /^msedge\.dll$/i,
    /^Qt[56]WebEngineCore\.dll$/i,
];

/** A PE .exe at least this large may be an Electron app with BoringSSL inside. */
export const ELECTRON_EXE_MIN_SIZE = 64 * 1024 * 1024;

const started = new Set<string>();

/**
 * Install the keylog hook for a Chromium-family module. `winePe` pins the
 * module to the Win64 ABI (PE code under Wine). Idempotent per module.
 */
export function chromium_boringssl_execute(moduleName: string, winePe: boolean = false): void {
    if (!keylog_enabled) return;
    const key = moduleName.toLowerCase();
    if (started.has(key)) return;
    started.add(key);
    if (winePe) setModuleCallAbi(moduleName, "win64");
    log(`[*] ${moduleName}: Chromium-embedded BoringSSL — locating ssl_log_secret via keylog-label xrefs`);
    void onAllKeylogTiersMissed(moduleName, makeBoringSslDumpKeys(moduleName), {
        detail: "Chromium-embedded BoringSSL (no exports/symbols; anchor locator only)",
        pairipDisabled: false,
    });
}

/** Factory for registry rows (hookFn receives the module name). */
export function chromium_boringssl_hook(winePe: boolean): (moduleName: string) => void {
    return (moduleName: string) => chromium_boringssl_execute(moduleName, winePe);
}

/**
 * Electron apps link BoringSSL into the main .exe, whose name is arbitrary. Try
 * the tier-4 locator on every large .exe image: it reads the keylog label
 * strings first and gives up cheaply when they are absent.
 */
export function hookElectronStyleExecutables(images: (Module | ModuleLike)[], winePe: boolean): void {
    if (!keylog_enabled || !isTlsFamilyRequested()) return;
    for (const m of images) {
        if (!/\.exe$/i.test(m.name) || m.size < ELECTRON_EXE_MIN_SIZE) continue;
        const key = m.name.toLowerCase();
        if (!keylog_enabled || started.has(key)) continue;
        started.add(key);
        if (winePe) setModuleCallAbi(m.name, "win64");
        devlog(`[chromium] ${m.name}: large executable (${(m.size / (1024 * 1024)).toFixed(0)} MB); checking for embedded BoringSSL`);
        // startTier4Once, not onAllKeylogTiersMissed: most large executables
        // are not Electron, and a missing label set must stay silent.
        startTier4Once(m.name, makeBoringSslDumpKeys(m.name), "Electron-style executable");
    }
}

/** Wine: Chromium-family PE images already mapped (Frida does not list them). */
export function hookMappedChromiumPeImages(): void {
    if (!keylog_enabled || !isTlsFamilyRequested()) return;
    const images = listPeImages();
    for (const m of images) {
        if (CHROMIUM_BORINGSSL_MODULES.some((re) => re.test(m.name))) chromium_boringssl_execute(m.name, true);
    }
    hookElectronStyleExecutables(images, true);
}
