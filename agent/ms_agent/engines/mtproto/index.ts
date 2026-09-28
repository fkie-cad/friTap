import { state as hostState } from "../../state.js";
import { registerEngine } from "../../registry.js";
import { MemscanEngine } from "../../types.js";
import { mtstate } from "./mtstate.js";
import { mtprotoConfigure, mtprotoScanOnce } from "./scanner.js";

/* The Telegram MTProto engine: hook-free heap scanner ported from
 * research/memory_scan_MTProto/agent/scanner.js. Self-contained (own mtstate +
 * helpers); plugs into the shared agent via runTiers. */
export const MtprotoEngine: MemscanEngine = {
    name: 'mtproto',
    runTiers: function (ranges: any, stats: any, errors: string[]): void {
        // Lazy configure: the shared driver has set hostState.profile to the
        // active mtproto profile before calling us. (Re)configure on first use
        // or if the active profile object changed. A bad target (wrong pointer
        // size / ART offsets) throws here and is reported, not emitted.
        try {
            if (mtstate.profile !== hostState.profile) {
                mtprotoConfigure(hostState.profile);
            }
        } catch (e: any) {
            errors.push('mtproto configure failed: ' + (e && e.message ? e.message : e));
            return;
        }
        var m = mtprotoScanOnce();
        if (m && m.errors) { for (var i = 0; i < m.errors.length; i++) errors.push(m.errors[i]); }
        stats.emitted = (stats.emitted || 0) + (m && m.emitted ? m.emitted : 0);
        stats.mtproto = m;   // full per-tier mtproto stats, for host-side visibility
    }
};
registerEngine(MtprotoEngine);
