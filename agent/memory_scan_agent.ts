/*
 * memory_scan_agent — heap scanning agent (independently loaded).
 *
 * Thin entry point. The scanner was refactored out of this single file into a
 * modular tree under agent/ms_agent/ (core helpers + one folder per engine +
 * a registry + the scan driver + the RPC surface), mirroring how the main
 * fritap_agent.ts is organised, so future engines / ABIs / platforms slot in
 * without touching a dispatch switch.
 *
 * This entry does two things and nothing else:
 *   1. side-effect-import each engine barrel, which self-registers the engine
 *      into the registry (the `import "./x/index.js"` convention the main agent
 *      uses for its protocol units);
 *   2. install the RPC surface (configure / scanOnce / needle) the Python host
 *      is written against.
 *
 * frida-compile still compiles THIS file (agent/memory_scan_agent.ts) into the
 * standalone bundle friTap/fritap_memscan.js — the build entry is unchanged.
 *
 * There is deliberately NOT ONE byte pattern, struct offset, stride or NSS label
 * in the agent code. Every piece of layout knowledge arrives at runtime in the
 * profile object handed to configure() — one element of the pattern database.
 */
'use strict';

// Engine barrels: importing each one runs its registerEngine(...) side effect.
// Add a new engine by dropping in agent/ms_agent/engines/<name>/index.ts and
// adding one import line here — no dispatch switch to edit (Open/Closed).
import "./ms_agent/engines/boringssl/index.js";
import "./ms_agent/engines/schannel/index.js";
import "./ms_agent/engines/rc4/index.js";
import "./ms_agent/engines/mtproto/index.js";

import { buildRpcExports } from "./ms_agent/rpc.js";

rpc.exports = buildRpcExports();
