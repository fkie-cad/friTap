📦
108663 /agent/memory_scan_agent.js
✄
// agent/ms_agent/state.ts
var state = {
  profile: null,
  // the ACTIVE profile for the current scan/tier group
  profiles: null,
  // all profiles configure() was handed (see rpc.ts);
  // a single profile is stored as a one-element list so
  // scanOnce() has one code path. null until configure().
  validators: null,
  // parsed once by configure(), see parseValidators()
  needle: null,
  // Tier B needle derived by Tier A: {value, module, rva}
  recorded: {},
  // "LABEL|client_random" -> secret hex
  faults: 0,
  // native faults seen by the exception handler
  handlerInstalled: false,
  // configure() is allowed to be called more than once
  mappedRanges: null,
  // per-scan address index, see buildMappedRangeIndex()
  scanIndex: 0,
  // 0 on the FIRST scan, so scan 1 is never throttled
  lastTierBValidated: null,
  // Tier B's validated count on the previous scan;
  // null means "there has not been one yet"
  // --- Schannel engine state (WS4). Resolved once per process; a schannel
  // profile only ever runs in one lsass session, so caching globally is safe.
  schannelReady: false,
  // resolveSchannelNeedles()/module lookups done?
  schannelNeedles: [],
  // [{value, module, rva}] ncryptsslp invariant pointers
  schannelNeedleModule: null,
  // {base,size} of ncryptsslp.dll
  schannelModule: null,
  // {base,size} of schannel.dll (session-cache vftable host)
  schannelCacheVftable: null,
  // CSslCacheClientItem vftable, derived + cached
  // --- RC4 engine state (WS3).
  rc4KatOk: null,
  // known-answer-test result, run once (null = not yet)
  rc4Sboxes: [],
  // S-boxes found this scan
  rc4Emitted: {}
  // dedup for emitted rc4_key messages across scans
};

// agent/ms_agent/registry.ts
var engines = {};
function registerEngine(engine) {
  engines[engine.name] = engine;
}
function getEngine(name) {
  return Object.prototype.hasOwnProperty.call(engines, name) ? engines[name] : null;
}

// agent/ms_agent/core/log.ts
function log(level, msg) {
  send({ type: "log", level, msg });
}

// agent/ms_agent/core/memory.ts
function hexBytes(u) {
  var s = "";
  for (var i = 0; i < u.length; i++)
    s += (u[i] < 16 ? "0" : "") + u[i].toString(16);
  return s;
}
function hex(buf) {
  if (buf === null)
    return "";
  return hexBytes(new Uint8Array(buf));
}
function readHex(addr, len) {
  try {
    return hex(addr.readByteArray(len));
  } catch (e) {
    return null;
  }
}
function readBytes(addr, len) {
  try {
    var buf = addr.readByteArray(len);
    return buf === null ? null : new Uint8Array(buf);
  } catch (e) {
    return null;
  }
}
function readPointerOrNull(addr) {
  try {
    return addr.readPointer();
  } catch (e) {
    return null;
  }
}
function readU8OrNull(addr) {
  try {
    return addr.readU8();
  } catch (e) {
    return null;
  }
}
function readU16OrNull(addr) {
  try {
    return addr.readU16();
  } catch (e) {
    return null;
  }
}
function readU32OrNull(addr) {
  try {
    return addr.readU32();
  } catch (e) {
    return null;
  }
}
function ptrToNum(p) {
  return parseInt(p.toString(), 16);
}
function clampReadableLength(base, size, rangeBase, rangeSize) {
  if (size <= 0 || rangeSize <= 0)
    return 0;
  if (base < rangeBase)
    return 0;
  var available = rangeBase + rangeSize - base;
  if (available <= 0)
    return 0;
  return available < size ? available : size;
}
function readableScanLength(base, size) {
  try {
    var rd = Process.findRangeByAddress(base);
    if (rd === null || !rd.protection || rd.protection.charAt(0) !== "r")
      return 0;
    return clampReadableLength(ptrToNum(base), size, ptrToNum(rd.base), rd.size);
  } catch (e) {
    return 0;
  }
}
function scanRange(range, pattern, errors) {
  var len = readableScanLength(range.base, range.size);
  if (len <= 0) {
    return [];
  }
  try {
    return Memory.scanSync(range.base, len, pattern);
  } catch (e) {
    errors.push("scan " + range.base + ": " + e.message);
    return [];
  }
}
function installExceptionHandler() {
  if (state.handlerInstalled)
    return;
  state.handlerInstalled = true;
  Process.setExceptionHandler(function(details) {
    state.faults++;
    if (state.faults <= 3)
      log("debug", "native fault " + details.type + " at " + details.address);
    return false;
  });
}
function pointerToScanPattern(p) {
  var buf = Memory.alloc(Process.pointerSize);
  buf.writePointer(p);
  return hex(buf.readByteArray(Process.pointerSize)).match(/../g).join(" ");
}

// agent/ms_agent/core/pointers.ts
function untag(p) {
  return p.and(state.validators.tagMask);
}
function addressToNumber(p) {
  return parseInt(p.toString(16), 16);
}
function buildMappedRangeIndex() {
  var ranges = Process.enumerateRanges({ protection: "---", coalesce: false });
  var index = new Array(ranges.length);
  for (var i = 0; i < ranges.length; i++) {
    var start = addressToNumber(ranges[i].base);
    index[i] = [start, start + ranges[i].size];
  }
  index.sort(function(a, b) {
    return a[0] - b[0];
  });
  return index;
}
function indexContains(index, address) {
  var lo = 0, hi = index.length - 1;
  while (lo <= hi) {
    var mid = lo + hi >> 1;
    if (address < index[mid][0])
      hi = mid - 1;
    else if (address >= index[mid][1])
      lo = mid + 1;
    else
      return true;
  }
  return false;
}
function isMappedAddress(untagged) {
  if (state.mappedRanges === null)
    return Process.findRangeByAddress(untagged) !== null;
  return indexContains(state.mappedRanges, addressToNumber(untagged));
}
function looksLikeHeapPointer(p) {
  if (p === null || p.isNull())
    return false;
  var u = untag(p);
  if (u.compare(state.validators.pointerMin) < 0)
    return false;
  return isMappedAddress(u);
}

// agent/ms_agent/core/heuristics.ts
function parseValidators(v) {
  return {
    maxZeroFraction: v.max_zero_fraction,
    minEntropyBits: v.min_shannon_entropy_bits,
    minSecretLen: v.min_secret_len,
    maxSecretLen: v.max_secret_len,
    pointerMin: ptr(v.pointer_min),
    tagMask: ptr(v.pointer_tag_mask)
  };
}
function passesZeroFraction(bytes) {
  var zeros = 0;
  for (var i = 0; i < bytes.length; i++)
    if (bytes[i] === 0)
      zeros++;
  return zeros / bytes.length <= state.validators.maxZeroFraction;
}
function shannonEntropyBits(bytes) {
  var counts = {}, i;
  for (i = 0; i < bytes.length; i++)
    counts[bytes[i]] = (counts[bytes[i]] || 0) + 1;
  var bits = 0;
  for (var k in counts) {
    var p = counts[k] / bytes.length;
    bits -= p * (Math.log(p) / Math.LN2);
  }
  return bits;
}
function passesEntropy(bytes) {
  return shannonEntropyBits(bytes) >= state.validators.minEntropyBits;
}
function passesLengthBounds(len) {
  return len >= state.validators.minSecretLen && len <= state.validators.maxSecretLen;
}
function isValidHashLen(len) {
  return state.profile.constants.valid_hash_lens.indexOf(len) !== -1;
}
function looksLikeSecret(bytes) {
  return bytes !== null && isValidHashLen(bytes.length) && passesLengthBounds(bytes.length) && passesZeroFraction(bytes) && passesEntropy(bytes);
}
function looksLikeRandom(bytes) {
  return bytes !== null && passesZeroFraction(bytes) && passesEntropy(bytes);
}

// agent/ms_agent/engines/boringssl/index.ts
function emitKeylog(label, clientRandom, secret, tier, ssl, source, stats) {
  var key = label + "|" + clientRandom;
  var previous = state.recorded[key];
  if (previous === secret)
    return false;
  if (previous !== void 0) {
    log("warn", "conflict for " + label + " " + clientRandom.substring(0, 16) + "... (KeyUpdate rotation?) \u2014 not emitting from " + source);
    return false;
  }
  state.recorded[key] = secret;
  send({
    type: "keylog",
    line: label + " " + clientRandom + " " + secret,
    tier,
    ssl: ssl.toString(),
    source
  });
  stats.emitted++;
  return true;
}
function emitUnpaired(base, secret, sessionId, sslVersion, stats) {
  send({
    type: "unpaired",
    kind: "orphan_session",
    secret,
    session_id: sessionId,
    ssl_version: sslVersion,
    addr: base.toString()
  });
  stats.emitted++;
}
function readSlotLengths(hs) {
  var slots = state.profile.tiers.A_ssl_handshake.slots;
  var lengths = new Array(slots.length);
  var common = 0;
  var hasLabelled = false;
  for (var i = 0; i < slots.length; i++) {
    var len = readU8OrNull(hs.add(slots[i].len));
    if (len === null)
      return null;
    lengths[i] = len;
    if (len === 0)
      continue;
    if (!isValidHashLen(len))
      return null;
    if (common === 0)
      common = len;
    else if (len !== common)
      return null;
    if (slots[i].label !== null)
      hasLabelled = true;
  }
  return hasLabelled ? lengths : null;
}
function closesRoundTrip(hs, s3) {
  var back = readPointerOrNull(s3.add(state.profile.struct_offsets.SSL3_STATE.hs));
  return back !== null && !back.isNull() && untag(back).equals(untag(hs));
}
function resolveHandshakeContext(hs) {
  var off = state.profile.struct_offsets;
  var ssl = readPointerOrNull(hs.add(off.SSL_HANDSHAKE.ssl));
  if (!looksLikeHeapPointer(ssl))
    return null;
  var s3 = readPointerOrNull(ssl.add(off.SSL.s3));
  if (!looksLikeHeapPointer(s3))
    return null;
  if (!closesRoundTrip(hs, s3))
    return null;
  return { ssl, s3 };
}
function readClientRandom(s3) {
  var c = state.profile.constants;
  var bytes = readBytes(s3.add(state.profile.struct_offsets.SSL3_STATE.client_random), c.ssl3_random_size);
  return looksLikeRandom(bytes) ? hexBytes(bytes) : null;
}
function emitHandshakeSlots(hs, ssl, clientRandom, tier, lengths, stats) {
  var slots = state.profile.tiers.A_ssl_handshake.slots;
  for (var i = 0; i < slots.length; i++) {
    var slot = slots[i];
    if (slot.label === null)
      continue;
    var len = lengths[i];
    if (len === 0)
      continue;
    var bytes = readBytes(hs.add(slot.data), len);
    if (!looksLikeSecret(bytes))
      continue;
    emitKeylog(slot.label, clientRandom, hexBytes(bytes), tier, ssl, slot.name, stats);
  }
}
function rememberNeedle(ssl) {
  var method = readPointerOrNull(ssl.add(state.profile.struct_offsets.SSL.method));
  if (!looksLikeHeapPointer(method))
    return;
  if (state.needle !== null && state.needle.value.equals(method))
    return;
  var mod = Process.findModuleByAddress(untag(method));
  state.needle = {
    value: method,
    module: mod === null ? null : mod.name,
    rva: mod === null ? null : "0x" + untag(method).sub(mod.base).toString(16)
  };
  log("info", "Tier B needle derived from Tier A: " + method + (mod === null ? "" : " (" + state.needle.module + "+" + state.needle.rva + ")"));
}
function processHandshakeCandidate(hs, stats) {
  var lengths = readSlotLengths(hs);
  if (lengths === null)
    return;
  var ctx = resolveHandshakeContext(hs);
  if (ctx === null)
    return;
  stats.tierA.validated++;
  rememberNeedle(ctx.ssl);
  var clientRandom = readClientRandom(ctx.s3);
  if (clientRandom === null)
    return;
  emitHandshakeSlots(hs, ctx.ssl, clientRandom, "A", lengths, stats);
}
function runTierA(ranges, stats, errors) {
  var tier = state.profile.tiers.A_ssl_handshake;
  if (!tier.enabled)
    return;
  for (var r = 0; r < ranges.length; r++) {
    for (var a = 0; a < tier.anchors.length; a++) {
      var hits = scanRange(ranges[r], tier.anchors[a].pattern, errors);
      for (var h = 0; h < hits.length; h++) {
        stats.tierA.candidates++;
        var hs = hits[h].address.sub(tier.anchor_offset_in_struct);
        try {
          processHandshakeCandidate(hs, stats);
        } catch (e) {
          errors.push("tierA " + hs + ": " + e.message);
        }
      }
    }
  }
}
function tierARescanEvery() {
  var configured = state.profile.tiers.A_ssl_handshake.rescan_every;
  if (typeof configured !== "number" || !isFinite(configured) || configured < 1)
    return 1;
  return Math.floor(configured);
}
function shouldRunTierA() {
  if (resolveNeedleValue() === null)
    return true;
  if (state.scanIndex % tierARescanEvery() === 0)
    return true;
  return state.lastTierBValidated === 0;
}
function resolveNeedleValue() {
  if (state.needle !== null)
    return state.needle.value;
  var hint = state.profile.tiers.B_ssl_method_ptr.needle;
  if (!hint || !hint.module || !hint.rva)
    return null;
  var mod = Process.findModuleByName(hint.module);
  return mod === null ? null : mod.base.add(ptr(hint.rva));
}
var needleSeedInstalled = false;
var needleSeedListeners = [];
function seedFromSslIoEnabled() {
  var tier = state.profile && state.profile.tiers && state.profile.tiers.B_ssl_method_ptr;
  return !!tier && tier.seed_from_ssl_io !== false;
}
function seedNeedleFromSsl(ssl, source) {
  if (ssl === null || ssl.isNull())
    return false;
  var method;
  try {
    method = readPointerOrNull(ssl.add(state.profile.struct_offsets.SSL.method));
  } catch (e) {
    return false;
  }
  if (!looksLikeHeapPointer(method))
    return false;
  if (state.needle !== null)
    return state.needle.value.equals(method);
  var mod = null;
  try {
    mod = Process.findModuleByAddress(untag(method));
  } catch (e) {
    mod = null;
  }
  state.needle = {
    value: method,
    module: mod === null ? null : mod.name,
    rva: mod === null ? null : "0x" + untag(method).sub(mod.base).toString(16),
    source
  };
  log("info", "Tier B needle derived from SSL_read/SSL_write: " + method + (mod === null ? "" : " (" + state.needle.module + "+" + state.needle.rva + ")"));
  return true;
}
function candidateModules() {
  var out = [];
  var profiles = state.profiles !== null ? state.profiles : [state.profile];
  for (var i = 0; i < profiles.length; i++) {
    var p = profiles[i];
    var mods = p && p.match && p.match.modules;
    if (!mods)
      continue;
    for (var j = 0; j < mods.length; j++) {
      if (typeof mods[j] === "string" && mods[j].indexOf("*") === -1)
        out.push(mods[j]);
    }
  }
  return out;
}
function resolveSslExport(name) {
  var mods = candidateModules();
  for (var i = 0; i < mods.length; i++) {
    try {
      var m = Process.findModuleByName(mods[i]);
      var a = m === null ? null : m.findExportByName(name);
      if (a !== null && !a.isNull())
        return a;
    } catch (e2) {
    }
  }
  try {
    var g = Module.findGlobalExportByName(name);
    if (g !== null && !g.isNull())
      return g;
  } catch (e2) {
  }
  try {
    var all = Process.enumerateModules();
    for (var k = 0; k < all.length; k++) {
      try {
        var e = all[k].findExportByName(name);
        if (e !== null && !e.isNull())
          return e;
      } catch (err) {
      }
    }
  } catch (e2) {
  }
  return null;
}
function resolveSslExportsAll(name) {
  var out = [];
  var seen = {};
  function add(p) {
    if (p === null || p.isNull())
      return;
    var key = p.toString();
    if (seen[key])
      return;
    seen[key] = true;
    out.push(p);
  }
  var single = resolveSslExport(name);
  if (single !== null)
    add(single);
  try {
    var all = Process.enumerateModules();
    for (var i = 0; i < all.length; i++) {
      var m = all[i];
      try {
        var ex = m.findExportByName(name);
        if (ex !== null && !ex.isNull())
          add(ex);
      } catch (e) {
      }
      var nm = (m.name || "").toLowerCase();
      var sslBearing = [
        "libssl",
        "boringssl",
        "conscrypt",
        "httpengine",
        "signal"
      ];
      var isSslBearing = false;
      for (var s = 0; s < sslBearing.length; s++) {
        if (nm.indexOf(sslBearing[s]) !== -1) {
          isSslBearing = true;
          break;
        }
      }
      if (!isSslBearing)
        continue;
      try {
        var syms = m.enumerateSymbols();
        for (var j = 0; j < syms.length; j++) {
          if (syms[j].name === name && syms[j].address !== null && !syms[j].address.isNull())
            add(syms[j].address);
        }
      } catch (e2) {
      }
    }
  } catch (e3) {
  }
  return out;
}
function detachNeedleSeedHooks() {
  for (var i = 0; i < needleSeedListeners.length; i++) {
    try {
      needleSeedListeners[i].detach();
    } catch (e) {
    }
  }
  needleSeedListeners = [];
}
function onSslIoEnter(args) {
  try {
    seedNeedleFromSsl(args[0], "ssl_io");
  } catch (e) {
  }
  if (state.needle !== null)
    detachNeedleSeedHooks();
}
function attachSslIoHook(name) {
  var addrs = resolveSslExportsAll(name);
  var n = 0;
  for (var i = 0; i < addrs.length; i++) {
    try {
      needleSeedListeners.push(Interceptor.attach(addrs[i], { onEnter: onSslIoEnter }));
      n++;
    } catch (e) {
    }
  }
  return n > 0;
}
function installNeedleSeedHooks() {
  if (needleSeedInstalled)
    return;
  needleSeedInstalled = true;
  if (!seedFromSslIoEnabled())
    return;
  if (typeof Interceptor === "undefined" || Interceptor === null)
    return;
  var names = ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];
  var attached = 0;
  for (var i = 0; i < names.length; i++)
    if (attachSslIoHook(names[i]))
      attached++;
  if (attached === 0) {
    log("warn", "Tier B needle seed: could not resolve SSL_read/SSL_write in this process; falling back to Tier A / profile hint");
  } else {
    log("info", "Tier B needle seed hooks installed on " + attached + " SSL I/O export(s)");
  }
}
function emitS3TrafficSecrets(ssl, s3, clientRandom, stats) {
  var secrets = state.profile.tiers.B_ssl_method_ptr.s3_secrets;
  var off = state.profile.struct_offsets.SSL3_STATE;
  for (var i = 0; i < secrets.length; i++) {
    var entry = secrets[i];
    var len = readU8OrNull(s3.add(off[entry.field + "_len"]));
    if (len === null || len === 0)
      continue;
    var bytes = readBytes(s3.add(off[entry.field]), len);
    if (!looksLikeSecret(bytes))
      continue;
    emitKeylog(entry.label, clientRandom, hexBytes(bytes), "B", ssl, entry.field, stats);
  }
}
function emitSecretBundle(ssl, s3, clientRandom, stats) {
  var tier = state.profile.tiers.B_ssl_method_ptr;
  if (!tier.emit_secret_bundle)
    return false;
  var off = state.profile.struct_offsets.SSL3_STATE;
  var c = state.profile.constants;
  var serverRandomBytes = readBytes(s3.add(off.server_random), c.ssl3_random_size);
  if (!looksLikeRandom(serverRandomBytes))
    return false;
  var fields = [
    { field: "write_traffic_secret", key: "client_traffic_secret_0" },
    { field: "read_traffic_secret", key: "server_traffic_secret_0" },
    { field: "exporter_secret", key: "exporter_secret" }
  ];
  var bundle = {};
  for (var i = 0; i < fields.length; i++) {
    var len = readU8OrNull(s3.add(off[fields[i].field + "_len"]));
    if (len === null || len === 0)
      return false;
    var bytes = readBytes(s3.add(off[fields[i].field]), len);
    if (!looksLikeSecret(bytes))
      return false;
    bundle[fields[i].key] = hexBytes(bytes);
  }
  send({
    type: "tls_secret_bundle",
    client_random: clientRandom,
    server_random: hexBytes(serverRandomBytes),
    client_traffic_secret_0: bundle.client_traffic_secret_0,
    server_traffic_secret_0: bundle.server_traffic_secret_0,
    exporter_secret: bundle.exporter_secret,
    ssl: ssl.toString()
  });
  stats.emitted++;
  return true;
}
function sessionBaseFor(path, ssl, s3) {
  var off = state.profile.struct_offsets;
  if (path.from === "SSL3_STATE")
    return s3.add(off.SSL3_STATE[path.field]);
  if (path.from === "SSL")
    return ssl.add(off.SSL[path.field]);
  return null;
}
function emitSessionMasterSecret(ssl, session, clientRandom, source, stats) {
  var cfg = state.profile.tiers.B_ssl_method_ptr.tls12_session;
  var off = state.profile.struct_offsets.SSL_SESSION;
  var version = readU16OrNull(session.add(off.ssl_version));
  if (version !== cfg.require_ssl_version)
    return;
  var len = readU8OrNull(session.add(off.secret_len));
  if (len !== cfg.require_secret_len)
    return;
  var bytes = readBytes(session.add(off.secret), len);
  if (!looksLikeSecret(bytes))
    return;
  emitKeylog(cfg.label, clientRandom, hexBytes(bytes), "B", ssl, source, stats);
}
function emitSessionSecrets(ssl, s3, clientRandom, handshakeState, stats) {
  var paths = state.profile.tiers.B_ssl_method_ptr.tls12_session.paths;
  for (var i = 0; i < paths.length; i++) {
    if (paths[i].when_handshake_complete_only && handshakeState !== HS_COMPLETE)
      continue;
    var slot = sessionBaseFor(paths[i], ssl, s3);
    if (slot === null)
      continue;
    var session = readPointerOrNull(slot);
    if (!looksLikeHeapPointer(session))
      continue;
    emitSessionMasterSecret(ssl, session, clientRandom, paths[i].field, stats);
  }
}
var HS_COMPLETE = "complete";
var HS_LIVE = "live";
var HS_INDETERMINATE = "indeterminate";
function classifyHandshake(hs) {
  if (hs === null)
    return HS_INDETERMINATE;
  if (hs.isNull())
    return HS_COMPLETE;
  return looksLikeHeapPointer(hs) ? HS_LIVE : HS_INDETERMINATE;
}
function processSslCandidate(ssl, stats) {
  var off = state.profile.struct_offsets;
  var s3 = readPointerOrNull(ssl.add(off.SSL.s3));
  if (!looksLikeHeapPointer(s3))
    return;
  stats.tierB.validated++;
  var clientRandom = readClientRandom(s3);
  if (clientRandom === null)
    return;
  var hs = readPointerOrNull(s3.add(off.SSL3_STATE.hs));
  var handshakeState = classifyHandshake(hs);
  if (handshakeState === HS_LIVE) {
    if (closesRoundTrip(hs, s3)) {
      var lengths = readSlotLengths(hs);
      if (lengths !== null)
        emitHandshakeSlots(hs, ssl, clientRandom, "B", lengths, stats);
    }
  } else if (handshakeState === HS_COMPLETE) {
    emitS3TrafficSecrets(ssl, s3, clientRandom, stats);
    emitSecretBundle(ssl, s3, clientRandom, stats);
  } else {
    stats.indeterminateHs++;
  }
  emitSessionSecrets(ssl, s3, clientRandom, handshakeState, stats);
}
function runTierB(ranges, stats, errors) {
  var tier = state.profile.tiers.B_ssl_method_ptr;
  if (!tier.enabled)
    return;
  var needle = resolveNeedleValue();
  if (needle === null) {
    log("warn", "Tier B skipped: no needle derived by Tier A and the profile hint did not resolve in this process");
    return;
  }
  var pattern = pointerToScanPattern(needle);
  for (var r = 0; r < ranges.length; r++) {
    var hits = scanRange(ranges[r], pattern, errors);
    for (var h = 0; h < hits.length; h++) {
      stats.tierB.candidates++;
      try {
        processSslCandidate(hits[h].address, stats);
      } catch (e) {
        errors.push("tierB " + hits[h].address + ": " + e.message);
      }
    }
  }
}
function processOrphanSession(base, tier, stats) {
  var off = state.profile.struct_offsets.SSL_SESSION;
  var len = readU8OrNull(base.add(off.secret_len));
  if (len !== tier.require_secret_len)
    return;
  var bytes = readBytes(base.add(off.secret), len);
  if (!looksLikeSecret(bytes))
    return;
  stats.tierC.validated++;
  var idLen = readU8OrNull(base.add(off.session_id_len));
  var version = readU16OrNull(base.add(off.ssl_version));
  emitUnpaired(base, hexBytes(bytes), idLen ? readHex(base.add(off.session_id), idLen) : "", version === null ? 0 : version, stats);
}
function runTierC(ranges, stats, errors) {
  var tier = state.profile.tiers.C_orphan_session;
  if (!tier || !tier.enabled)
    return;
  for (var r = 0; r < ranges.length; r++) {
    var hits = scanRange(ranges[r], tier.anchor.pattern, errors);
    for (var h = 0; h < hits.length; h++) {
      stats.tierC.candidates++;
      var base = hits[h].address.sub(tier.anchor.offset_in_struct);
      try {
        processOrphanSession(base, tier, stats);
      } catch (e) {
        errors.push("tierC " + base + ": " + e.message);
      }
    }
  }
}
var BoringsslEngine = {
  name: "boringssl",
  runTiers: function(ranges, stats, errors) {
    installNeedleSeedHooks();
    if (shouldRunTierA())
      runTierA(ranges, stats, errors);
    else
      stats.tierA.skipped = true;
    runTierB(ranges, stats, errors);
    runTierC(ranges, stats, errors);
    state.lastTierBValidated = stats.tierB.validated;
  }
};
registerEngine(BoringsslEngine);

// agent/ms_agent/engines/schannel/index.ts
function schannelResolved() {
  var p = state.profile;
  if (p && p.resolved)
    return p.resolved;
  var arch = p && p.arch || {};
  return arch[Process.arch] || arch.arm64 || {};
}
function schannelLooksLikeSecret(bytes) {
  return bytes !== null && passesZeroFraction(bytes) && passesEntropy(bytes);
}
function pointerInModule(p, mod) {
  if (p === null || mod === null)
    return false;
  var u = untag(p);
  return u.compare(mod.base) >= 0 && u.compare(mod.base.add(mod.size)) < 0;
}
function reverseStr(s) {
  return s.split("").reverse().join("");
}
function bytesEqualAscii(bytes, str) {
  if (bytes === null || bytes.length < str.length)
    return false;
  for (var i = 0; i < str.length; i++)
    if (bytes[i] !== str.charCodeAt(i))
      return false;
  return true;
}
function magicMatches(addr, magicStr) {
  var b = readBytes(addr, magicStr.length);
  if (b === null)
    return false;
  return bytesEqualAscii(b, magicStr) || bytesEqualAscii(b, reverseStr(magicStr));
}
function isAllZero(bytes) {
  if (bytes === null)
    return true;
  for (var i = 0; i < bytes.length; i++)
    if (bytes[i] !== 0)
      return false;
  return true;
}
function asciiToScanPattern(str) {
  var parts = [];
  for (var i = 0; i < str.length; i++) {
    var h = str.charCodeAt(i).toString(16);
    parts.push(h.length < 2 ? "0" + h : h);
  }
  return parts.join(" ");
}
function resolveSchannelNeedles() {
  var cfg = schannelResolved().needle;
  if (!cfg || !cfg.module) {
    log("warn", "schannel: no needle configured for this arch; TLS 1.2 tier disabled");
    return { needles: [], module: null };
  }
  var mod = Process.findModuleByName(cfg.module);
  if (mod === null) {
    log("warn", "schannel: needle module " + cfg.module + " not loaded; nothing to scan for");
    return { needles: [], module: null };
  }
  var out = [];
  var cands = cfg.candidates || [];
  for (var i = 0; i < cands.length; i++) {
    var value = mod.base.add(ptr(cands[i].rva));
    out.push({ value, module: cfg.module, rva: cands[i].rva });
    log("info", "schannel needle " + cfg.module + "+" + cands[i].rva + " -> " + value);
  }
  return { needles: out, module: { base: mod.base, size: mod.size } };
}
function ensureSchannelResolved() {
  if (state.schannelReady)
    return;
  var r = resolveSchannelNeedles();
  state.schannelNeedles = r.needles;
  state.schannelNeedleModule = r.module;
  var schan = Process.findModuleByName("schannel.dll");
  state.schannelModule = schan === null ? null : { base: schan.base, size: schan.size };
  state.schannelReady = true;
}
function emitSchannelUnpaired(kind, ssl5, secret, sslVersion, stats) {
  var key = kind + "|" + ssl5.toString() + "|" + secret;
  if (state.recorded[key] !== void 0)
    return;
  state.recorded[key] = secret;
  send({
    type: "unpaired",
    kind,
    secret,
    session_id: "",
    ssl_version: sslVersion,
    addr: ssl5.toString()
  });
  stats.emitted++;
}
function runSchannelTls12Master(ranges, stats, errors, ssl5s) {
  var tier = (schannelResolved().tiers || {}).tls12_master;
  if (!tier || !tier.enabled || state.schannelNeedles.length === 0)
    return;
  var deltaToMaster = tier.master_at - tier.needle_at;
  var sslVersion = 771;
  for (var n = 0; n < state.schannelNeedles.length; n++) {
    var pattern = pointerToScanPattern(state.schannelNeedles[n].value);
    for (var r = 0; r < ranges.length; r++) {
      var hits = scanRange(ranges[r], pattern, errors);
      for (var h = 0; h < hits.length; h++) {
        stats.schannel.tls12Candidates++;
        try {
          var hit = hits[h].address;
          var ssl5 = hit.sub(tier.needle_at);
          var bytes = readBytes(hit.add(deltaToMaster), tier.master_len);
          if (!schannelLooksLikeSecret(bytes))
            continue;
          if (ssl5s)
            ssl5s.push(ssl5);
          emitSchannelUnpaired("schannel_tls12_master", ssl5, hexBytes(bytes), sslVersion, stats);
        } catch (e) {
          errors.push("schannel tls12 " + hits[h].address + ": " + e.message);
        }
      }
    }
  }
}
function scanForPointer(ranges, value, errors, cap) {
  var pattern = pointerToScanPattern(value);
  var hits = [];
  for (var r = 0; r < ranges.length; r++) {
    var found = scanRange(ranges[r], pattern, errors);
    for (var i = 0; i < found.length; i++) {
      hits.push(found[i].address);
      if (cap && hits.length >= cap)
        return hits;
    }
  }
  return hits;
}
function bootstrapSchannelSsl5s(ranges, errors, cap) {
  var t = (schannelResolved().tiers || {}).tls12_master;
  var out = [];
  if (!t)
    return out;
  for (var n = 0; n < state.schannelNeedles.length && out.length < cap; n++) {
    var pattern = pointerToScanPattern(state.schannelNeedles[n].value);
    for (var r = 0; r < ranges.length && out.length < cap; r++) {
      var hits = scanRange(ranges[r], pattern, errors);
      for (var h = 0; h < hits.length && out.length < cap; h++) {
        var ssl5 = hits[h].address.sub(t.needle_at);
        if (schannelLooksLikeSecret(readBytes(ssl5.add(t.master_at), t.master_len)))
          out.push(ssl5);
      }
    }
  }
  return out;
}
function bootstrapCacheVftable(ranges, ssl5s, sc, errors) {
  if (state.schannelCacheVftable !== null)
    return true;
  if (state.schannelModule === null) {
    log("warn", "session_cache: schannel.dll not found; cannot validate cache items");
    return false;
  }
  var attempts = Math.min(ssl5s.length, sc.bootstrap_max_ssl5 || 4);
  for (var a = 0; a < attempts; a++) {
    var ssl5 = ssl5s[a];
    var toBddd = scanForPointer(ranges, ssl5, errors, sc.reverse_scan_cap || 64);
    for (var i = 0; i < toBddd.length; i++) {
      var bddd = toBddd[i].sub(sc.ssl5_ptr_at);
      if (!magicMatches(bddd.add(sc.bddd_magic_at), sc.bddd_magic))
        continue;
      var toItem = scanForPointer(ranges, bddd, errors, sc.reverse_scan_cap || 64);
      for (var j = 0; j < toItem.length; j++) {
        var cacheItem = toItem[j].sub(sc.bddd_ptr_at);
        var vft = readPointerOrNull(cacheItem.add(sc.vftable_at));
        if (vft === null || !pointerInModule(vft, state.schannelModule))
          continue;
        state.schannelCacheVftable = vft;
        log("info", "session_cache: derived cache vftable " + vft + " from ssl5 " + ssl5);
        return true;
      }
    }
  }
  log("warn", "session_cache: could not derive the cache vftable from " + attempts + " ssl5(s) \u2014 nothing emitted (safe).");
  return false;
}
function emitSchannelSessionCache(sidHex, masterHex, ssl5, stats) {
  var line = "RSA Session-ID:" + sidHex + " Master-Key:" + masterHex;
  var key = "sc|" + line;
  if (state.recorded[key] !== void 0)
    return;
  state.recorded[key] = masterHex;
  send({
    type: "keylog",
    line,
    tier: "schannel_session_cache",
    ssl: ssl5.toString(),
    source: "session_cache"
  });
  stats.schannel.sessionCacheEmitted++;
}
function emitSchannelCacheDump(cacheItem, ssl5, masterHex, sc, stats) {
  var key = "dump|" + cacheItem.toString();
  if (state.recorded[key] !== void 0)
    return;
  state.recorded[key] = 1;
  var win = readBytes(cacheItem, sc.dump_bytes || 288);
  send({
    type: "cachedump",
    cache_item: cacheItem.toString(),
    ssl5: ssl5.toString(),
    master: masterHex,
    session_id_at: sc.session_id_at,
    session_id_maxlen: sc.session_id_maxlen,
    bytes: win === null ? "" : hexBytes(win)
  });
  stats.schannel.sessionCacheDumped++;
}
function processCacheItem(cacheItem, sc, dumpMode, stats) {
  var vft = readPointerOrNull(cacheItem.add(sc.vftable_at));
  if (!pointerInModule(vft, state.schannelModule))
    return;
  var bddd = readPointerOrNull(cacheItem.add(sc.bddd_ptr_at));
  if (!looksLikeHeapPointer(bddd))
    return;
  if (!magicMatches(bddd.add(sc.bddd_magic_at), sc.bddd_magic))
    return;
  var ssl5 = readPointerOrNull(bddd.add(sc.ssl5_ptr_at));
  if (!looksLikeHeapPointer(ssl5))
    return;
  var needlePtr = readPointerOrNull(ssl5.add(sc.ssl5_needle_at));
  if (state.schannelNeedleModule !== null && !pointerInModule(needlePtr, state.schannelNeedleModule))
    return;
  var master = readBytes(ssl5.add(sc.master_at), sc.master_len);
  if (!schannelLooksLikeSecret(master))
    return;
  stats.schannel.cacheItems++;
  var masterHex = hexBytes(master);
  if (dumpMode) {
    emitSchannelCacheDump(cacheItem, ssl5, masterHex, sc, stats);
    return;
  }
  var sidLen = sc.session_id_maxlen;
  if (typeof sc.session_id_len_at === "number") {
    var l = readU8OrNull(cacheItem.add(sc.session_id_len_at));
    if (l !== null && l > 0 && l <= sc.session_id_maxlen)
      sidLen = l;
  }
  var sid = readBytes(cacheItem.add(sc.session_id_at), sidLen);
  if (isAllZero(sid))
    return;
  emitSchannelSessionCache(hexBytes(sid), masterHex, ssl5, stats);
}
function runSchannelSessionCache(ranges, stats, errors, ssl5s) {
  var sc = (schannelResolved().tiers || {}).session_cache;
  if (!sc || !sc.enabled)
    return;
  if (ssl5s.length === 0)
    ssl5s = bootstrapSchannelSsl5s(ranges, errors, sc.bootstrap_max_ssl5 || 4);
  if (!bootstrapCacheVftable(ranges, ssl5s, sc, errors))
    return;
  var dumpMode = sc.dump === true || sc.session_id_calibrated !== true;
  if (dumpMode && sc.dump !== true) {
    log("warn", "session_cache: session_id_at is not marked calibrated; dumping cache items to calibrate rather than emitting possibly-wrong session IDs.");
  }
  var pattern = pointerToScanPattern(state.schannelCacheVftable);
  for (var r = 0; r < ranges.length; r++) {
    var hits = scanRange(ranges[r], pattern, errors);
    for (var h = 0; h < hits.length; h++) {
      var cacheItem = hits[h].address.sub(sc.vftable_at);
      try {
        processCacheItem(cacheItem, sc, dumpMode, stats);
      } catch (e) {
        errors.push("session_cache " + cacheItem + ": " + e.message);
      }
    }
  }
}
function chainOffset(value, fallback) {
  if (typeof value === "number")
    return value;
  if (typeof value === "string") {
    var m = value.match(/\+\s*0x([0-9a-fA-F]+)/);
    if (m)
      return parseInt(m[1], 16);
  }
  return fallback;
}
function runSchannelTls13Secret(ranges, stats, errors) {
  var tier = (schannelResolved().tiers || {}).tls13_secret;
  if (!tier || !tier.enabled)
    return;
  var hyp = tier.hypothesis || {};
  var anchor = tier.anchor_tag || "3lss";
  var sizeAt = typeof tier.size_at === "number" ? tier.size_at : -1;
  var secretAt = chainOffset(tier.secret_at !== void 0 ? tier.secret_at : hyp.secret_at, 106);
  var lens = tier.secret_lens || [48, 32];
  var sslVersion = 772;
  var patterns = [asciiToScanPattern(anchor), asciiToScanPattern(reverseStr(anchor))];
  for (var p = 0; p < patterns.length; p++) {
    for (var r = 0; r < ranges.length; r++) {
      var hits = scanRange(ranges[r], patterns[p], errors);
      for (var h = 0; h < hits.length; h++) {
        stats.schannel.tls13Candidates++;
        try {
          var anchorAddr = hits[h].address;
          var declared = sizeAt >= 0 ? readU32OrNull(anchorAddr.add(sizeAt)) : null;
          var tryLens = declared === 32 || declared === 48 ? [declared] : lens;
          for (var li = 0; li < tryLens.length; li++) {
            var secret = readBytes(anchorAddr.add(secretAt), tryLens[li]);
            if (!schannelLooksLikeSecret(secret))
              continue;
            emitSchannelUnpaired("schannel_tls13_secret", anchorAddr, hexBytes(secret), sslVersion, stats);
            break;
          }
        } catch (e) {
          errors.push("schannel tls13 " + hits[h].address + ": " + e.message);
        }
      }
    }
  }
}
var SchannelEngine = {
  name: "schannel",
  runTiers: function(ranges, stats, errors) {
    ensureSchannelResolved();
    stats.schannel = {
      tls12Candidates: 0,
      tls13Candidates: 0,
      cacheItems: 0,
      sessionCacheEmitted: 0,
      sessionCacheDumped: 0
    };
    var ssl5s = [];
    runSchannelTls12Master(ranges, stats, errors, ssl5s);
    runSchannelSessionCache(ranges, stats, errors, ssl5s);
    runSchannelTls13Secret(ranges, stats, errors);
  }
};
registerEngine(SchannelEngine);

// agent/ms_agent/engines/rc4/index.ts
var _rc4S = new Uint8Array(256);
var _rc4Out = new Uint8Array(256);
var _rc4Pos = new Int32Array(256);
var _rc4U16 = new Uint8Array(8192);
function rc4Opts() {
  var pr = state.profile && state.profile.params || {};
  function num(v, d) {
    return typeof v === "number" && isFinite(v) ? v : d;
  }
  var ctHex = pr.ciphertext_sample;
  var ct = typeof ctHex === "string" && ctHex ? rc4HexToBytes(ctHex) : null;
  return {
    minKeyLen: num(pr.min_key_len, 5),
    maxKeyLen: num(pr.max_key_len, 64),
    trialPrefix: num(pr.trial_prefix, 64),
    acceptPrintableFraction: num(pr.accept_printable_fraction, 0.85),
    maxRangeBytes: num(pr.max_range_bytes, 64 * 1024 * 1024),
    maxTotalBytes: num(pr.max_total_bytes, 300 * 1024 * 1024),
    maxTrials: num(pr.max_trials, 1e6),
    maxWindowTrials: num(pr.max_window_trials, 3e5),
    maxWindowsPerRun: num(pr.max_windows_per_run, 2e4),
    maxWindowRunLen: num(pr.max_window_run_len, 256),
    maxSboxes: num(pr.max_sboxes, 64),
    maxSeen: num(pr.max_seen, 1e6),
    detectSboxes: pr.detect_sboxes !== false,
    recoverKeys: pr.recover_keys !== false,
    ciphertextSample: ct,
    // Improved-recovery params. Code fallback = today's behavior (all off); the
    // shipped profile turns them on. See friTap/memory_scanning/patterns.json.
    knownPlaintext: typeof pr.known_plaintext === "string" && pr.known_plaintext ? rc4HexToBytes(pr.known_plaintext) : null,
    sboxFirst: pr.sbox_first === true,
    sboxExactValidate: pr.sbox_exact_validate === true,
    prioritizeAnonymous: pr.prioritize_anonymous === true,
    requireExactOrAccept: pr.require_exact_or_accept === true,
    // Grouped-burst read (code fallback = today's single whole-budget burst). When on,
    // ranges are read in large groups with an early-stop check between groups so exact
    // evidence in an early (anonymous-first) group skips the tail READS, not just CPU.
    groupedRead: pr.grouped_read === true,
    readGroupBytes: num(pr.read_group_bytes, 64 * 1024 * 1024)
  };
}
function rc4HexToBytes(h) {
  h = String(h).replace(/[^0-9a-fA-F]/g, "");
  var out = new Uint8Array(h.length >> 1);
  for (var i = 0; i < out.length; i++)
    out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function rc4Ksa(key) {
  var S = new Uint8Array(256), i, j = 0, t;
  for (i = 0; i < 256; i++)
    S[i] = i;
  for (i = 0; i < 256; i++) {
    j = j + S[i] + key[i % key.length] & 255;
    t = S[i];
    S[i] = S[j];
    S[j] = t;
  }
  return S;
}
function rc4Prga(S, data) {
  var s = S.slice(), out = new Uint8Array(data.length), i = 0, j = 0, n, t;
  for (n = 0; n < data.length; n++) {
    i = i + 1 & 255;
    j = j + s[i] & 255;
    t = s[i];
    s[i] = s[j];
    s[j] = t;
    out[n] = data[n] ^ s[s[i] + s[j] & 255];
  }
  return out;
}
function rc4(key, data) {
  return rc4Prga(rc4Ksa(key), data);
}
function ksaInto(src, off, len) {
  var S = _rc4S, i, j = 0, t;
  for (i = 0; i < 256; i++)
    S[i] = i;
  for (i = 0; i < 256; i++) {
    j = j + S[i] + src[off + i % len] & 255;
    t = S[i];
    S[i] = S[j];
    S[j] = t;
  }
}
function prgaInto(data, n) {
  var s = _rc4S, i = 0, j = 0, m, t;
  for (m = 0; m < n; m++) {
    i = i + 1 & 255;
    j = j + s[i] & 255;
    t = s[i];
    s[i] = s[j];
    s[j] = t;
    _rc4Out[m] = data[m] ^ s[s[i] + s[j] & 255];
  }
}
function scoreTrial(n) {
  var o = _rc4Out, printable = 0, m, c;
  for (m = 0; m < n; m++) {
    c = o[m];
    if (c === 9 || c === 10 || c === 13 || c >= 32 && c <= 126)
      printable++;
  }
  var frac = n ? printable / n : 0, bonus = 0;
  for (m = 0; m + 3 < n; m++) {
    if (o[m] === 71 && o[m + 1] === 69 && o[m + 2] === 84 && o[m + 3] === 32) {
      bonus += 0.15;
      break;
    }
  }
  for (m = 0; m + 3 < n; m++) {
    if (o[m] === 72 && o[m + 1] === 84 && o[m + 2] === 84 && o[m + 3] === 80) {
      bonus += 0.15;
      break;
    }
  }
  return { printableFraction: frac, score: frac + bonus };
}
function rc4SelfCheck(errors) {
  if (state.rc4KatOk !== null)
    return state.rc4KatOk;
  var kat = state.profile && state.profile.kat || {};
  try {
    var got = hexBytes(rc4(rc4HexToBytes(kat.key), rc4HexToBytes(kat.plaintext)));
    var want = String(kat.ciphertext || "").toLowerCase();
    state.rc4KatOk = got === want && want.length > 0;
    if (state.rc4KatOk)
      log("info", "rc4 KAT ok (" + got + ")");
    else
      errors.push("rc4 KAT failed: " + got + " != " + want);
  } catch (e) {
    state.rc4KatOk = false;
    errors.push("rc4 KAT error: " + e.message);
  }
  return state.rc4KatOk;
}
function isPrintable(c) {
  return c >= 32 && c <= 126;
}
function scanByteSboxes(u8, base, opts) {
  var pos = _rc4Pos;
  pos.fill(-1);
  var start = 0;
  for (var r = 0; r < u8.length; r++) {
    var v = u8[r];
    if (pos[v] >= start)
      start = pos[v] + 1;
    pos[v] = r;
    if (r - start + 1 === 256)
      recordSbox(base.add(start).toString(), "byte", u8, start, opts);
  }
}
function scanIntSboxes(u8, base, opts) {
  var pos = _rc4Pos;
  pos.fill(-1);
  var start = 0, ndw = u8.length >> 2;
  for (var r = 0; r < ndw; r++) {
    var p = r * 4;
    if (u8[p + 1] !== 0 || u8[p + 2] !== 0 || u8[p + 3] !== 0) {
      start = r + 1;
      continue;
    }
    var v = u8[p];
    if (pos[v] >= start)
      start = pos[v] + 1;
    pos[v] = r;
    if (r - start + 1 === 256)
      recordSbox(base.add(start * 4).toString(), "int", u8, start * 4, opts);
  }
}
function recordSbox(addrStr, form, u8, off, opts) {
  if (state.rc4Sboxes.length >= opts.maxSboxes)
    return;
  var S = new Uint8Array(256), k;
  if (form === "byte") {
    for (k = 0; k < 256; k++)
      S[k] = u8[off + k];
  } else {
    for (k = 0; k < 256; k++)
      S[k] = u8[off + k * 4];
  }
  var identity = true;
  for (k = 0; k < 256; k++)
    if (S[k] !== k) {
      identity = false;
      break;
    }
  state.rc4Sboxes.push({ addr: addrStr, form, S, identity });
}
function buildLiveSboxes() {
  var boxes = [], b0 = [], bN = [];
  for (var s = 0; s < state.rc4Sboxes.length; s++) {
    var sb = state.rc4Sboxes[s];
    if (sb.identity)
      continue;
    boxes.push(sb.S);
    b0.push(sb.S[0]);
    bN.push(sb.S[255]);
  }
  return { boxes, b0, bN, n: boxes.length };
}
function ksaMatchesSbox(live) {
  var S = _rc4S;
  for (var k = 0; k < live.n; k++) {
    if (S[0] !== live.b0[k] || S[255] !== live.bN[k])
      continue;
    var box = live.boxes[k], ok = true;
    for (var m = 0; m < 256; m++) {
      if (S[m] !== box[m]) {
        ok = false;
        break;
      }
    }
    if (ok)
      return k;
  }
  return -1;
}
function trialKey(ctx, src, off, len, source, isWindow) {
  ctx.candidates++;
  if (ctx.stop)
    return;
  var canSbox = ctx.opts.sboxExactValidate && ctx.live !== null && ctx.live.n > 0;
  if (ctx.prefix === null && !canSbox)
    return;
  if (isWindow) {
    if (ctx.windowTrials >= ctx.opts.maxWindowTrials)
      return;
  } else if (ctx.trials >= ctx.opts.maxTrials)
    return;
  var h1 = (2166136261 ^ len) >>> 0;
  var h2 = (2166136261 ^ 2654435769 ^ len) >>> 0;
  for (var q = 0; q < len; q++) {
    var b = src[off + q];
    h1 = (h1 ^ b) >>> 0;
    h1 = Math.imul(h1, 16777619) >>> 0;
    h2 = (h2 ^ b) >>> 0;
    h2 = Math.imul(h2, 16777619) >>> 0;
  }
  var prev = ctx.seen[h1];
  if (prev === h2)
    return;
  if (prev === void 0 && ctx.seenCount < ctx.opts.maxSeen) {
    ctx.seen[h1] = h2;
    ctx.seenCount++;
  }
  if (isWindow)
    ctx.windowTrials++;
  else
    ctx.trials++;
  ksaInto(src, off, len);
  if (canSbox) {
    var mi = ksaMatchesSbox(ctx.live);
    if (mi >= 0) {
      var kx = new Uint8Array(len);
      for (var a = 0; a < len; a++)
        kx[a] = src[off + a];
      ctx.exact = { source, key: kx, keyHex: hexBytes(kx), sboxIdx: mi };
      ctx.stop = true;
      return;
    }
  }
  if (ctx.prefix === null)
    return;
  prgaInto(ctx.prefix, ctx.prefixLen);
  var kp = ctx.opts.knownPlaintext;
  if (kp !== null && kp.length <= ctx.prefixLen) {
    var match = true;
    for (var c = 0; c < kp.length; c++) {
      if (_rc4Out[c] !== kp[c]) {
        match = false;
        break;
      }
    }
    if (match) {
      var ky = new Uint8Array(len);
      for (var a2 = 0; a2 < len; a2++)
        ky[a2] = src[off + a2];
      ctx.exact = { source, key: ky, keyHex: hexBytes(ky), sboxIdx: -1 };
      ctx.stop = true;
      return;
    }
  }
  var sc = scoreTrial(ctx.prefixLen);
  if (ctx.best === null || sc.score > ctx.best.score) {
    var key = new Uint8Array(len);
    for (var i = 0; i < len; i++)
      key[i] = src[off + i];
    ctx.best = {
      source,
      key,
      keyHex: hexBytes(key),
      score: sc.score,
      printableFraction: sc.printableFraction
    };
  }
}
function runToTrials(ctx, u8, runStart, runEnd, source) {
  if (ctx.stop)
    return;
  var minL = ctx.opts.minKeyLen, maxL = ctx.opts.maxKeyLen, runLen = runEnd - runStart;
  if (runLen < minL)
    return;
  if (runLen <= maxL) {
    trialKey(ctx, u8, runStart, runLen, source, false);
    return;
  }
  if (runLen > ctx.opts.maxWindowRunLen)
    return;
  var perRun = 0, cap = ctx.opts.maxWindowsPerRun;
  for (var i = runStart; i < runEnd && perRun < cap && !ctx.stop && ctx.windowTrials < ctx.opts.maxWindowTrials; i++) {
    var maxHere = Math.min(maxL, runEnd - i);
    for (var L = minL; L <= maxHere && perRun < cap && !ctx.stop; L++) {
      trialKey(ctx, u8, i, L, source, true);
      perRun++;
    }
  }
}
function rc4DetectSboxesChunk(u8, base, opts) {
  if (!(opts.detectSboxes || opts.sboxFirst))
    return;
  if (state.rc4Sboxes.length < opts.maxSboxes)
    scanByteSboxes(u8, base, opts);
  if (state.rc4Sboxes.length < opts.maxSboxes)
    scanIntSboxes(u8, base, opts);
}
function rc4RecoverChunk(ctx, u8, base) {
  if (!ctx.opts.recoverKeys || ctx.stop)
    return;
  var off, runStart = -1;
  for (off = 0; off <= u8.length; off++) {
    var printable = off < u8.length && isPrintable(u8[off]);
    if (printable) {
      if (runStart < 0)
        runStart = off;
    } else {
      if (runStart >= 0) {
        runToTrials(ctx, u8, runStart, off, "ascii");
        runStart = -1;
        if (ctx.stop)
          return;
      }
    }
  }
  var u16Start = -1;
  for (off = 0; off + 1 < u8.length; off += 2) {
    if (ctx.stop)
      return;
    var ok = isPrintable(u8[off]) && u8[off + 1] === 0;
    if (ok) {
      if (u16Start < 0)
        u16Start = off;
    } else if (u16Start >= 0) {
      var n = off - u16Start >> 1;
      if (n > _rc4U16.length)
        n = _rc4U16.length;
      if (n >= ctx.opts.minKeyLen) {
        for (var d = 0; d < n; d++)
          _rc4U16[d] = u8[u16Start + d * 2];
        runToTrials(ctx, _rc4U16, 0, n, "utf16");
      }
      u16Start = -1;
    }
  }
}
function rc4ScanChunk(ctx, u8, base) {
  rc4DetectSboxesChunk(u8, base, ctx.opts);
  if (ctx.opts.sboxExactValidate && state.rc4Sboxes.length !== ctx.liveCount) {
    ctx.live = buildLiveSboxes();
    ctx.liveCount = state.rc4Sboxes.length;
  }
  rc4RecoverChunk(ctx, u8, base);
}
function rc4ReadOneRange(range, totalSoFar, opts) {
  var perCap = opts.maxRangeBytes, budget = opts.maxTotalBytes;
  if (totalSoFar >= budget)
    return null;
  var sz = range.size;
  if (sz > perCap)
    sz = perCap;
  if (totalSoFar + sz > budget)
    sz = budget - totalSoFar;
  var u8 = readBytes(range.base, sz);
  if (u8 === null)
    return null;
  return { base: range.base, u8, anonymous: range.file == null, size: sz };
}
function rc4BySize(a, b) {
  return a.size - b.size;
}
function rc4ReadAllFast(ranges, opts) {
  var sorted = ranges.slice().sort(rc4BySize);
  var buffers = [], total = 0;
  for (var i = 0; i < sorted.length; i++) {
    if (total >= opts.maxTotalBytes)
      break;
    var r = rc4ReadOneRange(sorted[i], total, opts);
    if (r !== null) {
      buffers.push(r);
      total += r.size;
    }
  }
  return { buffers, total };
}
function rc4OrderRanges(ranges, opts) {
  var ordered = ranges.slice();
  if (opts.prioritizeAnonymous) {
    ordered.sort(function(a, b) {
      var aa = a.file == null, bb = b.file == null;
      return aa === bb ? rc4BySize(a, b) : aa ? -1 : 1;
    });
  } else {
    ordered.sort(rc4BySize);
  }
  return ordered;
}
function rc4StreamScan(ranges, opts, ctx, phase, errors) {
  var ordered = ranges.slice();
  if (phase === "recover" && opts.prioritizeAnonymous) {
    ordered.sort(function(a, b) {
      var aa = a.file == null, bb = b.file == null;
      return aa === bb ? 0 : aa ? -1 : 1;
    });
  } else {
    ordered.sort(rc4BySize);
  }
  var total = 0, budget = opts.maxTotalBytes;
  for (var i = 0; i < ordered.length; i++) {
    if (ctx.stop)
      break;
    if (total >= budget)
      break;
    var r = rc4ReadOneRange(ordered[i], total, opts);
    if (r === null)
      continue;
    total += r.size;
    try {
      if (phase === "detect")
        rc4DetectSboxesChunk(r.u8, r.base, opts);
      else
        rc4RecoverChunk(ctx, r.u8, r.base);
    } catch (e) {
      errors.push("rc4 " + phase + " " + r.base + ": " + e.message);
    }
    r.u8 = null;
  }
  return total;
}
function emitRc4Key(keyHex, keyLen, source, stats) {
  var key = source + "|" + keyHex;
  if (state.rc4Emitted[key] !== void 0)
    return;
  state.rc4Emitted[key] = 1;
  send({
    type: "rc4_key",
    key: keyHex,
    key_len: keyLen,
    source,
    direction: "unknown",
    assoc: "-"
  });
  stats.emitted++;
}
var Rc4Engine = {
  name: "rc4",
  runTiers: function(ranges, stats, errors) {
    if (!rc4SelfCheck(errors))
      return;
    var t0 = Date.now();
    var opts = rc4Opts();
    state.rc4Sboxes = [];
    var ct = opts.ciphertextSample;
    var prefix = ct ? ct.subarray(0, Math.min(opts.trialPrefix, ct.length)) : null;
    var ctx = {
      opts,
      prefix,
      prefixLen: prefix ? prefix.length : 0,
      best: null,
      trials: 0,
      windowTrials: 0,
      candidates: 0,
      seen: {},
      seenCount: 0,
      live: null,
      liveCount: 0,
      exact: null,
      stop: false
    };
    var readTotal = 0, readDoneMs;
    if (opts.sboxFirst) {
      readTotal += rc4StreamScan(ranges, opts, ctx, "detect", errors);
      ctx.live = buildLiveSboxes();
      readDoneMs = Date.now();
      readTotal += rc4StreamScan(ranges, opts, ctx, "recover", errors);
    } else if (opts.groupedRead) {
      var orderedG = rc4OrderRanges(ranges, opts);
      var total = 0, gi = 0, budget = opts.maxTotalBytes, groupCap = opts.readGroupBytes;
      while (gi < orderedG.length && total < budget && !ctx.stop) {
        var group = [], gBytes = 0;
        while (gi < orderedG.length && total < budget && gBytes < groupCap) {
          var rr = rc4ReadOneRange(orderedG[gi], total, opts);
          gi++;
          if (rr !== null) {
            group.push(rr);
            total += rr.size;
            gBytes += rr.size;
          }
        }
        if (readDoneMs === void 0)
          readDoneMs = Date.now();
        for (var gj = 0; gj < group.length; gj++) {
          try {
            rc4ScanChunk(ctx, group[gj].u8, group[gj].base);
          } catch (e) {
            errors.push("rc4 chunk " + group[gj].base + ": " + e.message);
          }
          group[gj].u8 = null;
          if (ctx.stop)
            break;
        }
      }
      if (readDoneMs === void 0)
        readDoneMs = Date.now();
      readTotal = total;
    } else {
      var read = rc4ReadAllFast(ranges, opts);
      readDoneMs = Date.now();
      readTotal = read.total;
      for (var i = 0; i < read.buffers.length; i++) {
        try {
          rc4ScanChunk(ctx, read.buffers[i].u8, read.buffers[i].base);
        } catch (e) {
          errors.push("rc4 chunk " + read.buffers[i].base + ": " + e.message);
        }
        read.buffers[i].u8 = null;
      }
    }
    var live = 0;
    for (var s = 0; s < state.rc4Sboxes.length; s++) {
      if (state.rc4Sboxes[s].identity)
        continue;
      live++;
      emitRc4Key(hexBytes(state.rc4Sboxes[s].S), 256, "memscan-sbox", stats);
    }
    if (ctx.exact) {
      emitRc4Key(ctx.exact.keyHex, ctx.exact.key.length, "memscan-trial-exact", stats);
    } else if (ctx.best) {
      if (!opts.requireExactOrAccept || ctx.best.score >= opts.acceptPrintableFraction) {
        emitRc4Key(ctx.best.keyHex, ctx.best.key.length, "memscan-trial", stats);
      }
    }
    stats.rc4 = {
      sboxes: state.rc4Sboxes.length,
      liveSboxes: live,
      candidateKeys: ctx.candidates,
      readBytes: readTotal,
      ksaExecutions: ctx.trials + ctx.windowTrials,
      // distinct KSA runs executed
      scanMs: Date.now() - t0,
      burstReadMs: readDoneMs - t0,
      recovered: !!(ctx.exact || ctx.best),
      bestScore: ctx.exact ? 1 : ctx.best ? ctx.best.score : 0
    };
  }
};
registerEngine(Rc4Engine);

// agent/ms_agent/engines/mtproto/mtstate.ts
var mtstate = {
  profile: null,
  validators: null,
  // parsed once by configure(), see parseValidators()
  // opt-in: emit keylog lines the oracle did NOT confirm. Default false; set true
  // only when the driver's profile carries `emitUnconfirmed: true`, which the host
  // stamps on mtproto profiles for the `--ms-emit-unconfirmed` CLI flag (E4). Read
  // in mtprotoConfigure(); gates reportUnconfirmed()/confirmArtGroup() emission.
  emitUnconfirmed: false,
  externalIds: null,
  // Tier D: {authKeyIdHex: true}, supplied by the driver
  maxHitsPerScan: 0,
  // per (range, pattern) cap, see scanRange()
  needles: {},
  // auth_key_id hex -> {keyPtr, byteArray}, this session
  recorded: {},
  // "LABEL|key_id" -> key hex, for the conflict rule
  emittedLines: {},
  // complete keylog line -> true, for the dedup rule
  scanIndex: 0,
  // pass counter; ONLY reader is the legacy shouldRunTierC()
  tierCCompletedAt: null,
  // ms; when the last Tier C pass FINISHED, see shouldRunTierCNow()
  faults: 0,
  // native faults seen by the exception handler, cumulative
  handlerInstalled: false,
  // configure() is allowed to be called more than once
  mappedRanges: null,
  // per-pass address index, see buildMappedRangeIndex()
  mapsIndex: null,
  // per-pass /proc/self/maps index, see loadMapsIndex()
  // Tier E (obfuscated-transport CTR state): the resolved `_ZTV10Connection`
  // vtable address, or null when unresolved / the tier is off. Resolved once at
  // configure time (RTTI walk first, calibrated RVA as fallback) and used to build
  // the Connection-object scan needle. See resolveConnectionVtable() / runTierE().
  connectionVtable: null,
  // How connectionVtable was resolved, for diagnostics: 'rtti' (self-healed via the
  // Itanium RTTI graph — version-independent), 'rva' (calibrated fallback, build-
  // specific), 'symbol', or null (unresolved). connectionVtableRva is that anchor's
  // module RVA.
  connectionVtableSource: null,
  connectionVtableRva: null,
  // one-shot guard so the "0 Connection vtable hits" warning is logged once, not
  // on every scan pass.
  tierEWarned: false,
  // Incremental-pass memory (see scanner.ts revalidateConfirmed()). A FULL pass
  // rebuilds these from scratch; the INCREMENTAL passes in between re-read them
  // without sweeping the heap.
  //   confirmedAuthKeys:   id hex -> {id, byteArray, keyPtr, keyHex, slots:[addr…], dcId, keyType}
  //   confirmedConnections: [objBase hex, …] live Tier E Connection object bases
  //   forceFullNext:       a revalidation miss forces the next pass to re-enumerate
  confirmedAuthKeys: {},
  confirmedConnections: [],
  forceFullNext: false
};

// agent/ms_agent/engines/mtproto/endpoint.ts
var AF_INET = 2;
var AF_INET6 = 10;
var NO_ENDPOINT = "-";
function guardedReadU16(p) {
  try {
    return p.readU16();
  } catch (e) {
    return null;
  }
}
function guardedReadBytes(p, len) {
  try {
    var b = p.readByteArray(len);
    return b === null ? null : new Uint8Array(b);
  } catch (e) {
    return null;
  }
}
function bePort(b) {
  return (b[0] << 8 | b[1]) & 65535;
}
function formatIPv4(addr) {
  return addr[0] + "." + addr[1] + "." + addr[2] + "." + addr[3];
}
function formatIPv6(addr) {
  var parts = [], i;
  for (i = 0; i < 16; i += 2) {
    parts.push(((addr[i] << 8 | addr[i + 1]) & 65535).toString(16));
  }
  return parts.join(":");
}
function readConnectionEndpoint(objBase, off) {
  try {
    var v4 = off && off.endpoint_sockaddr_in;
    if (typeof v4 === "number" && guardedReadU16(objBase.add(v4)) === AF_INET) {
      var port4 = guardedReadBytes(objBase.add(v4 + 2), 2);
      var addr4 = guardedReadBytes(objBase.add(v4 + 4), 4);
      if (port4 !== null && addr4 !== null) {
        return formatIPv4(addr4) + ":" + bePort(port4);
      }
    }
    var v6 = off && off.endpoint_sockaddr_in6;
    if (typeof v6 === "number" && guardedReadU16(objBase.add(v6)) === AF_INET6) {
      var port6 = guardedReadBytes(objBase.add(v6 + 2), 2);
      var addr6 = guardedReadBytes(objBase.add(v6 + 8), 16);
      if (port6 !== null && addr6 !== null) {
        return "[" + formatIPv6(addr6) + "]:" + bePort(port6);
      }
    }
  } catch (e) {
  }
  return NO_ENDPOINT;
}

// agent/ms_agent/engines/mtproto/scanner.ts
var DEFAULT_MAX_HITS_PER_SCAN = 2e5;
var DEFAULT_TIER_D_MAX_WINDOWS = 2e5;
function hex2(u) {
  var s = "";
  for (var i = 0; i < u.length; i++)
    s += (u[i] < 16 ? "0" : "") + u[i].toString(16);
  return s;
}
function hexToScanPattern(h) {
  return h.match(/../g).join(" ");
}
function readBuffer(addr, len) {
  try {
    return addr.readByteArray(len);
  } catch (e) {
    return null;
  }
}
function readPointerOrNull2(addr) {
  try {
    return addr.readPointer();
  } catch (e) {
    return null;
  }
}
function readS32OrNull(addr) {
  try {
    return addr.readS32();
  } catch (e) {
    return null;
  }
}
function readU32OrNull2(addr) {
  try {
    return addr.readU32();
  } catch (e) {
    return null;
  }
}
function shift(p, delta) {
  return delta < 0 ? p.sub(-delta) : p.add(delta);
}
function countBy(map, key) {
  var name = String(key);
  map[name] = (map[name] || 0) + 1;
}
function log2(level, msg) {
  send({ type: "log", level, msg });
}
function parseValidators2(v) {
  return {
    minEntropyBits: v.min_shannon_entropy_bits,
    maxEntropyBits: v.max_shannon_entropy_bits,
    minDistinctBytes: v.min_distinct_bytes,
    maxDistinctBytes: v.max_distinct_bytes,
    maxZeroFraction: v.max_zero_fraction,
    pointerMin: ptr(v.pointer_min),
    tagMask: ptr(v.pointer_tag_mask)
  };
}
function untag2(p) {
  return p.and(mtstate.validators.tagMask);
}
function isAligned(p, alignment) {
  if (!alignment)
    return true;
  return untag2(p).and(alignment - 1).isNull();
}
function addressToNumber2(p) {
  return parseInt(p.toString(16), 16);
}
function findInterval(index, address) {
  if (index === null || index.length === 0)
    return null;
  var lo = 0, hi = index.length - 1;
  while (lo <= hi) {
    var mid = lo + hi >> 1;
    if (address < index[mid][0])
      hi = mid - 1;
    else if (address >= index[mid][1])
      lo = mid + 1;
    else
      return index[mid];
  }
  return null;
}
function buildMappedRangeIndex2(ranges) {
  var index = new Array(ranges.length);
  for (var i = 0; i < ranges.length; i++) {
    var start = addressToNumber2(ranges[i].base);
    index[i] = [start, start + ranges[i].size, null];
  }
  index.sort(function(a, b) {
    return a[0] - b[0];
  });
  return index;
}
function isMappedAddress2(untagged) {
  if (mtstate.mappedRanges === null)
    return Process.findRangeByAddress(untagged) !== null;
  return findInterval(mtstate.mappedRanges, addressToNumber2(untagged)) !== null;
}
function looksLikeHeapPointer2(p) {
  if (p === null || p.isNull())
    return false;
  var u = untag2(p);
  if (u.compare(mtstate.validators.pointerMin) < 0)
    return false;
  return isMappedAddress2(u);
}
function shannonEntropyBits2(counts, total) {
  var bits = 0, p;
  for (var i = 0; i < 256; i++) {
    if (counts[i] === 0)
      continue;
    p = counts[i] / total;
    bits -= p * (Math.log(p) / Math.LN2);
  }
  return bits;
}
var BYTE_COUNTS = new Array(256);
function secretStats(u8, expectedLength) {
  if (u8.length !== expectedLength)
    return null;
  var v = mtstate.validators;
  var counts = BYTE_COUNTS, i, distinct = 0;
  for (i = 0; i < 256; i++)
    counts[i] = 0;
  for (i = 0; i < u8.length; i++)
    counts[u8[i]]++;
  for (i = 0; i < 256; i++)
    if (counts[i] !== 0)
      distinct++;
  if (distinct < v.minDistinctBytes || distinct > v.maxDistinctBytes)
    return null;
  var zeros = counts[0] / u8.length;
  if (zeros > v.maxZeroFraction)
    return null;
  var bits = shannonEntropyBits2(counts, u8.length);
  if (bits < v.minEntropyBits || bits > v.maxEntropyBits)
    return null;
  return { bits, distinct, zeros };
}
function sha1LowId(buf) {
  var digest = Checksum.compute("sha1", buf);
  return digest.slice(-(mtstate.profile.constants.auth_key_id_len * 2));
}
function loadMapsIndex() {
  var text;
  try {
    text = File.readAllText("/proc/self/maps");
  } catch (e) {
    mtstate.mapsIndex = [];
    log2("warn", "cannot read /proc/self/maps (" + e.message + "); range names are unavailable, so both name lists match nothing this scan");
    return;
  }
  var lines = text.split("\n"), out = [], i, m;
  for (i = 0; i < lines.length; i++) {
    m = /^([0-9a-f]+)-([0-9a-f]+) \S+ \S+ \S+ \S+\s*(.*)$/.exec(lines[i]);
    if (m === null)
      continue;
    out.push([parseInt(m[1], 16), parseInt(m[2], 16), (m[3] || "").trim()]);
  }
  out.sort(function(a, b) {
    return a[0] - b[0];
  });
  mtstate.mapsIndex = out;
}
function labelAt(address) {
  var entry = findInterval(mtstate.mapsIndex, address);
  return entry === null ? "" : entry[2];
}
function rangeLabel(range) {
  return labelAt(addressToNumber2(range.base)) || (range.file ? range.file.path : "");
}
function matchesAny(label, needles) {
  if (!needles || needles.length === 0)
    return false;
  var haystack = label.toLowerCase();
  for (var i = 0; i < needles.length; i++) {
    if (haystack.indexOf(needles[i].toLowerCase()) !== -1)
      return true;
  }
  return false;
}
var AGENT_MODULE_PATTERNS = [/frida/i, /gum-js-loop/i, /quickjs/i];
function looksAgentOwned(text) {
  if (!text)
    return false;
  for (var i = 0; i < AGENT_MODULE_PATTERNS.length; i++) {
    if (AGENT_MODULE_PATTERNS[i].test(text))
      return true;
  }
  return false;
}
function buildAgentOwnedRanges() {
  var owned = [];
  try {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
      var m = modules[i];
      if (looksAgentOwned(m.name) || looksAgentOwned(m.path)) {
        owned.push({ base: m.base, end: m.base.add(m.size) });
      }
    }
  } catch (e) {
    log2("warn", "enumerateModules failed (" + e.message + "); the agent's own ranges cannot be excluded by address this scan");
  }
  return owned;
}
function isAgentOwnedRange(range, owned) {
  var end = range.base.add(range.size);
  for (var i = 0; i < owned.length; i++) {
    if (range.base.compare(owned[i].end) < 0 && owned[i].base.compare(end) < 0)
      return true;
  }
  return false;
}
function beginPass() {
  loadMapsIndex();
  return {
    /* protection '---' is a minimum, not a filter: it means "every mapping",
     * including the PROT_NONE guard pages findRangeByAddress also reports. */
    ranges: Process.enumerateRanges({ protection: "---", coalesce: false }),
    owned: buildAgentOwnedRanges()
  };
}
function protectionSatisfies(actual, required) {
  if (!required)
    return true;
  for (var i = 0; i < required.length; i++) {
    if (required[i] === "-")
      continue;
    if (!actual || actual[i] !== required[i])
      return false;
  }
  return true;
}
function selectRanges(cfg, pass) {
  var all = pass.ranges, owned = pass.owned;
  var eligible = [], allowed = [], i, r, label;
  for (i = 0; i < all.length; i++) {
    r = all[i];
    if (!protectionSatisfies(r.protection, cfg.protection))
      continue;
    if (cfg.require_anonymous && r.file)
      continue;
    if (cfg.max_range_bytes && r.size > cfg.max_range_bytes)
      continue;
    if (isAgentOwnedRange(r, owned))
      continue;
    label = rangeLabel(r);
    if (looksAgentOwned(label))
      continue;
    if (matchesAny(label, cfg.name_denylist))
      continue;
    eligible.push(r);
    if (matchesAny(label, cfg.name_allowlist))
      allowed.push(r);
  }
  if (allowed.length === 0) {
    log2("warn", "no range matched name_allowlist [" + (cfg.name_allowlist || []).join(", ") + "] \u2014 range names are unavailable, which means name_denylist [" + (cfg.name_denylist || []).join(", ") + "] matched nothing either. Falling back to ALL " + eligible.length + " eligible " + cfg.protection + " ranges, " + totalBytes(eligible) + " bytes now in scope; only the address-based agent-module exclusion still applies.");
    return eligible;
  }
  return allowed;
}
function totalBytes(ranges) {
  var n = 0;
  for (var i = 0; i < ranges.length; i++)
    n += ranges[i].size;
  return n;
}
function scanRange2(range, pattern, errors) {
  var hits;
  try {
    hits = Memory.scanSync(range.base, range.size, pattern);
  } catch (e) {
    errors.push("scan " + range.base + ": " + e.message);
    return [];
  }
  if (hits.length > mtstate.maxHitsPerScan) {
    errors.push("hit cap " + mtstate.maxHitsPerScan + " reached at " + range.base + ' for pattern "' + pattern + '" (' + hits.length + " hits) \u2014 truncated");
    hits = hits.slice(0, mtstate.maxHitsPerScan);
  }
  return hits;
}
function scanRanges(ranges, pattern, errors) {
  var hits = [], i, found, j;
  for (i = 0; i < ranges.length; i++) {
    found = scanRange2(ranges[i], pattern, errors);
    for (j = 0; j < found.length; j++)
      hits.push(found[j].address);
  }
  return hits;
}
function emitKeylog2(label, keyId, keyHex, line, tier, source, stats) {
  var idKey = label + "|" + keyId;
  var previous = mtstate.recorded[idKey];
  if (previous !== void 0 && previous !== keyHex) {
    log2("warn", "conflict for " + idKey + ": a different key already carries this id (SHA1 collision or corrupted read) \u2014 not emitting from " + source);
    return false;
  }
  if (mtstate.emittedLines[line] === true)
    return false;
  mtstate.recorded[idKey] = keyHex;
  mtstate.emittedLines[line] = true;
  send({ type: "keylog", line, label, tier, keyId, source });
  stats.emitted++;
  return true;
}
function emitAuthKey(keyId, keyHex, dcId, keyType, tier, source, stats) {
  var label = mtstate.profile.tiers.B_authkeyid_roundtrip.label;
  var line = label + " " + dcId + " " + keyId + " " + keyHex + " " + keyType;
  return emitKeylog2(label, keyId, keyHex, line, tier, source, stats);
}
function emitE2eKey(fingerprint, keyHex, chatId, tier, source, stats) {
  var label = mtstate.profile.tiers.C_art_secretchat_key.label;
  var line = label + " " + fingerprint + " " + keyHex + " " + chatId;
  return emitKeylog2(label, fingerprint, keyHex, line, tier, source, stats);
}
function emitObfKey(keyOutHex, ivOutHex, keyInHex, ivInHex, numOut, numIn, endpoint, tier, source, stats) {
  var label = mtstate.profile.tiers.E_connection_ctr_state.label;
  var ep = endpoint && String(endpoint).length > 0 ? endpoint : "-";
  var line = label + " " + keyOutHex + " " + ivOutHex + " " + keyInHex + " " + ivInHex + " " + numOut + " " + numIn + " " + ep;
  return emitKeylog2(label, keyOutHex, keyOutHex, line, tier, source, stats);
}
function emitUnpaired2(kind, keyId, candidate, tier) {
  send({
    type: "unpaired",
    kind,
    keyId,
    entropy: candidate.entropy,
    distinct: candidate.distinct,
    addr: candidate.keyPtr.toString(),
    tier
  });
}
function defaultKeyType() {
  var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
  return tier.role_keylog_key_type[tier.slot_roles[0]];
}
function processByteArrayCandidate(structBase, tier, stats) {
  var keyPtr = readPointerOrNull2(structBase.add(tier.key_ptr_offset));
  if (!looksLikeHeapPointer2(keyPtr))
    return null;
  stats.tierA.ptrOk++;
  var keyAddr = untag2(keyPtr);
  var buf = readBuffer(keyAddr, tier.key_len);
  if (buf === null)
    return null;
  var u8 = new Uint8Array(buf);
  var bstats = secretStats(u8, tier.key_len);
  if (bstats === null)
    return null;
  stats.tierA.entropyOk++;
  return {
    base: untag2(structBase),
    // the ByteArray — Tier B's round-trip target
    keyPtr: keyAddr,
    keyHex: hex2(u8),
    id: sha1LowId(buf),
    entropy: bstats.bits,
    distinct: bstats.distinct,
    confirmed: false
  };
}
function runTierA2(ranges, stats, errors) {
  var tier = mtstate.profile.tiers.A_bytearray_authkey;
  var candidates = [];
  if (!tier.enabled)
    return candidates;
  stats.tierA.state = "ran";
  var seenStructs = {}, seenIds = {};
  for (var a = 0; a < tier.anchors.length; a++) {
    var hits = scanRanges(ranges, tier.anchors[a].pattern, errors);
    for (var h = 0; h < hits.length; h++) {
      stats.tierA.candidates++;
      var structBase = hits[h].sub(tier.anchor_offset_in_struct);
      if (!isAligned(structBase, tier.require_alignment))
        continue;
      var key = structBase.toString();
      if (seenStructs[key] === true)
        continue;
      seenStructs[key] = true;
      stats.tierA.aligned++;
      try {
        var candidate = processByteArrayCandidate(structBase, tier, stats);
        if (candidate === null)
          continue;
        rememberNeedle2(candidate);
        if (seenIds[candidate.id] === true)
          continue;
        seenIds[candidate.id] = true;
        candidates.push(candidate);
      } catch (e) {
        errors.push("tierA " + structBase + ": " + e.message);
      }
    }
  }
  return candidates;
}
function rememberNeedle2(candidate) {
  if (mtstate.needles[candidate.id] !== void 0)
    return;
  mtstate.needles[candidate.id] = {
    keyPtr: candidate.keyPtr.toString(),
    byteArray: candidate.base.toString()
  };
}
function slotsFromIdHits(hits, candidate, tier, stats) {
  stats.tierB.idHits += hits.length;
  var slots = [], seenSlots = {};
  for (var h = 0; h < hits.length; h++) {
    var slot = hits[h].add(tier.roundtrip_ptr_offset);
    var back = readPointerOrNull2(slot);
    if (back === null || back.isNull())
      continue;
    if (!untag2(back).equals(candidate.base))
      continue;
    var key = slot.toString();
    if (seenSlots[key] === true)
      continue;
    seenSlots[key] = true;
    slots.push({ addr: addressToNumber2(untag2(slot)), slot, candidate });
  }
  return slots;
}
function confirmCandidate(candidate, tier, native, stats, errors) {
  var needle = hexToScanPattern(candidate.id);
  var slots = slotsFromIdHits(scanRanges(native, needle, errors), candidate, tier, stats);
  if (slots.length > 0)
    candidate.confirmed = true;
  return slots;
}
function groupConfirmedSlots(slots) {
  var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
  var maxPerGroup = mtstate.profile.constants.max_slots_per_datacenter;
  slots.sort(function(a, b) {
    return a.addr - b.addr;
  });
  var groups = [], current = null;
  for (var i = 0; i < slots.length; i++) {
    var previous = current === null ? null : current[current.length - 1];
    if (previous === null || slots[i].addr - previous.addr > tier.slot_group_window || current.length >= maxPerGroup) {
      current = [];
      groups.push(current);
    }
    current.push(slots[i]);
  }
  return groups;
}
function probeDatacenterId(firstSlot) {
  var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
  var c = mtstate.profile.constants;
  for (var off = 4; off <= tier.dc_id_probe_window; off += 4) {
    var value = readS32OrNull(firstSlot.sub(off));
    if (value === null)
      break;
    if (value >= c.dc_id_min && value <= c.dc_id_max)
      return value;
  }
  return 0;
}
function checkGroupDcIds(groups) {
  var ids = [], seen = {}, i, value;
  for (i = 0; i < groups.length; i++) {
    value = probeDatacenterId(groups[i][0].slot);
    ids.push(value);
    if (value !== 0 && seen[value]) {
      log2("warn", "dc_id probe produced duplicate id " + value + " across Datacenter groups; reporting dc_id 0 for all of them (the id is an informational hint and is not used for decryption)");
      return null;
    }
    seen[value] = true;
  }
  return ids;
}
function rememberConfirmedAuthKey(candidate, slotPtr, dcId, keyType) {
  var entry = mtstate.confirmedAuthKeys[candidate.id];
  if (entry === void 0) {
    entry = {
      id: candidate.id,
      byteArray: candidate.base.toString(),
      keyPtr: candidate.keyPtr.toString(),
      keyHex: candidate.keyHex,
      slots: [],
      dcId,
      keyType
    };
    mtstate.confirmedAuthKeys[candidate.id] = entry;
  }
  var s = untag2(slotPtr).toString();
  if (entry.slots.indexOf(s) === -1)
    entry.slots.push(s);
}
function emitDatacenterGroup(group, dcId, stats) {
  var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
  for (var i = 0; i < group.length; i++) {
    var role = tier.slot_roles[i] || tier.slot_roles[tier.slot_roles.length - 1];
    var candidate = group[i].candidate;
    var keyType = tier.role_keylog_key_type[role];
    emitAuthKey(candidate.id, candidate.keyHex, dcId, keyType, "B", role + "@" + group[i].slot, stats);
    rememberConfirmedAuthKey(candidate, group[i].slot, dcId, keyType);
  }
}
function runTierB2(ranges, candidates, stats, errors) {
  var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
  if (!tier.enabled)
    return;
  stats.tierB.state = "ran";
  var confirmed = [];
  for (var i = 0; i < candidates.length; i++) {
    stats.tierB.needles++;
    try {
      Array.prototype.push.apply(confirmed, confirmCandidate(candidates[i], tier, ranges, stats, errors));
    } catch (e) {
      errors.push("tierB " + candidates[i].keyPtr + ": " + e.message);
    }
  }
  stats.tierB.confirmed += confirmed.length;
  var groups = groupConfirmedSlots(confirmed);
  var dcIds = checkGroupDcIds(groups);
  for (var g = 0; g < groups.length; g++) {
    try {
      emitDatacenterGroup(groups[g], dcIds === null ? 0 : dcIds[g], stats);
    } catch (e) {
      errors.push("tierB group " + groups[g][0].slot + ": " + e.message);
    }
  }
}
function reportUnconfirmed(candidates, stats) {
  for (var i = 0; i < candidates.length; i++) {
    var candidate = candidates[i];
    if (candidate.confirmed)
      continue;
    if (mtstate.emitUnconfirmed) {
      emitAuthKey(candidate.id, candidate.keyHex, 0, defaultKeyType(), "A", "unconfirmed", stats);
    } else {
      emitUnpaired2("authkey_unconfirmed", candidate.id, candidate, "A");
    }
  }
}
function readSecretChatId(fingerprintSite) {
  var off = mtstate.profile.struct_offsets.EncryptedChat;
  var chatId = readS32OrNull(shift(fingerprintSite.sub(off.key_fingerprint), off.chat_id));
  return chatId === null ? 0 : chatId;
}
function isNonEmptyArray(value) {
  return Object.prototype.toString.call(value) === "[object Array]" && value.length > 0;
}
function offsetsOrScalar(list, scalar) {
  if (isNonEmptyArray(list))
    return list;
  return typeof scalar === "number" ? [scalar] : [];
}
function artDataOffsets(tier) {
  return offsetsOrScalar(tier.key_data_offset_candidates_from_anchor, tier.key_data_offset_from_anchor);
}
function artRefOffsets() {
  var off = mtstate.profile.struct_offsets.EncryptedChat;
  return isNonEmptyArray(off.auth_key_ref_candidates) ? off.auth_key_ref_candidates : [];
}
function describeArtBase(artBase) {
  var untagged = untag2(artBase);
  var address = addressToNumber2(untagged);
  return {
    ptr: untagged,
    low32: address % 4294967296 >>> 0,
    decodable: Math.floor(address / 4294967296) === 0
  };
}
function readOffsetSpan(hit, offsets, len) {
  var lo = offsets[0], hi = offsets[0], i;
  for (i = 1; i < offsets.length; i++) {
    if (offsets[i] < lo)
      lo = offsets[i];
    if (offsets[i] > hi)
      hi = offsets[i];
  }
  var buf = readBuffer(shift(hit, lo), hi - lo + len);
  return buf === null ? null : { buf, lo };
}
function processArtCandidate(hit, tier, stats, groups) {
  var artBase = hit.sub(tier.anchor_offset_in_struct);
  if (!isAligned(artBase, tier.require_alignment))
    return;
  var offsets = artDataOffsets(tier);
  var span = readOffsetSpan(hit, offsets, tier.key_len);
  for (var i = 0; i < offsets.length; i++) {
    var buf = span === null ? readBuffer(shift(hit, offsets[i]), tier.key_len) : span.buf.slice(offsets[i] - span.lo, offsets[i] - span.lo + tier.key_len);
    if (buf === null)
      continue;
    var u8 = new Uint8Array(buf);
    var bstats = secretStats(u8, tier.key_len);
    if (bstats === null)
      continue;
    stats.tierC.entropyOk++;
    countBy(stats.tierC.dataOffsetHits, offsets[i]);
    rememberArtGroup(groups, sha1LowId(buf), u8, shift(hit, offsets[i]), artBase, bstats);
    return;
  }
}
function rememberArtGroup(groups, fingerprint, u8, keyAddr, artBase, bstats) {
  var group = groups[fingerprint];
  if (group === void 0) {
    group = {
      fingerprint,
      keyHex: hex2(u8),
      bases: [],
      seenBases: {},
      candidate: { keyPtr: keyAddr, entropy: bstats.bits, distinct: bstats.distinct }
    };
    groups[fingerprint] = group;
  }
  var key = untag2(artBase).toString();
  if (group.seenBases[key] === true)
    return;
  group.seenBases[key] = true;
  group.bases.push(describeArtBase(artBase));
}
function closeArtRoundTrip(site, bases, offsets, tier) {
  var acceptPoisoned = tier.art_ref_accept_poisoned !== false;
  for (var i = 0; i < offsets.length; i++) {
    var value = readU32OrNull2(shift(site, offsets[i]));
    if (value === null)
      continue;
    var negated = -value >>> 0;
    for (var b = 0; b < bases.length; b++) {
      if (!bases[b].decodable)
        continue;
      if (value === bases[b].low32) {
        return { offset: offsets[i], poisoned: false, base: bases[b] };
      }
      if (acceptPoisoned && negated === bases[b].low32) {
        return { offset: offsets[i], poisoned: true, base: bases[b] };
      }
    }
  }
  return null;
}
function anyBaseIsDecodable(bases) {
  for (var i = 0; i < bases.length; i++)
    if (bases[i].decodable)
      return true;
  return false;
}
function testArtSites(sites, group, offsets, tier, stats) {
  var match = null, chosen = null;
  for (var s = 0; s < sites.length; s++) {
    stats.tierC.sitesTested++;
    var closed = closeArtRoundTrip(sites[s], group.bases, offsets, tier);
    if (closed === null)
      continue;
    stats.tierC.roundTrips++;
    if (closed.poisoned)
      stats.tierC.roundTripsPoisoned++;
    countBy(stats.tierC.roundTripByOffset, closed.offset);
    if (match !== null)
      continue;
    match = closed;
    chosen = sites[s];
  }
  return { match, chosen };
}
function confirmArtGroup(group, tier, ranges, stats, errors) {
  var sites = scanRanges(ranges, hexToScanPattern(group.fingerprint), errors);
  if (sites.length === 0) {
    if (mtstate.emitUnconfirmed) {
      emitE2eKey(group.fingerprint, group.keyHex, 0, "C", "unconfirmed", stats);
    } else {
      emitUnpaired2("e2e_unconfirmed", group.fingerprint, group.candidate, "C");
    }
    return;
  }
  stats.tierC.confirmed++;
  var roundTrip = tier.art_ref_roundtrip !== false;
  var offsets = artRefOffsets();
  var skipReason = null;
  if (roundTrip) {
    if (offsets.length === 0)
      skipReason = "no-ref-offset-in-profile";
    else if (!anyBaseIsDecodable(group.bases))
      skipReason = "base-above-32-bit";
  }
  var chosen = sites[0], match = null;
  if (roundTrip && skipReason === null) {
    var tested = testArtSites(sites, group, offsets, tier, stats);
    match = tested.match;
    if (tested.chosen !== null)
      chosen = tested.chosen;
  }
  var source = "fingerprint@" + chosen;
  if (!roundTrip) {
  } else if (skipReason !== null) {
    stats.tierC.refCheckSkipped++;
    source += " ref-check-skipped(" + skipReason + ")";
  } else if (match !== null) {
    source += " +ref@" + match.offset + (match.poisoned ? "(poisoned)" : "");
  } else {
    stats.tierC.colocatedOnly++;
    source += " colocated-only";
  }
  emitE2eKey(group.fingerprint, group.keyHex, readSecretChatId(chosen), "C", source, stats);
}
function shouldRunTierC(tier) {
  var every = tier.rescan_every;
  if (every === void 0 || every === null || every < 1)
    return true;
  return mtstate.scanIndex % every === 0;
}
function shouldRunTierCNow(tier, now) {
  var interval = tier.min_rescan_interval_ms;
  if (typeof interval === "number" && isFinite(interval) && interval >= 0) {
    if (mtstate.tierCCompletedAt === null)
      return null;
    return now - mtstate.tierCCompletedAt >= interval ? null : "interval";
  }
  return shouldRunTierC(tier) ? null : "pass-count";
}
function runTierC2(pass, stats, errors) {
  var tier = mtstate.profile.tiers.C_art_secretchat_key;
  if (!tier)
    return;
  stats.tierC.enabled = tier.enabled === true;
  if (!stats.tierC.enabled)
    return;
  var reason = shouldRunTierCNow(tier, Date.now());
  if (reason !== null) {
    stats.tierC.state = "throttled";
    stats.tierC.skipped = true;
    stats.tierC.throttledBy = reason;
    return;
  }
  stats.tierC.state = "ran";
  var ranges = selectRanges(tier.scan_regions || mtstate.profile.scan_regions, pass);
  var groups = {};
  for (var a = 0; a < tier.anchors.length; a++) {
    var hits = scanRanges(ranges, tier.anchors[a].pattern, errors);
    for (var h = 0; h < hits.length; h++) {
      stats.tierC.candidates++;
      try {
        processArtCandidate(hits[h], tier, stats, groups);
      } catch (e) {
        errors.push("tierC " + hits[h] + ": " + e.message);
      }
    }
  }
  for (var fingerprint in groups) {
    if (!groups.hasOwnProperty(fingerprint))
      continue;
    try {
      confirmArtGroup(groups[fingerprint], tier, ranges, stats, errors);
    } catch (e) {
      errors.push("tierC " + fingerprint + ": " + e.message);
    }
  }
  mtstate.tierCCompletedAt = Date.now();
}
function sweepRangeForIds(range, tier, budget, stats, errors) {
  var keyLen = tier.key_len;
  var stride = tier.stride;
  var limit = range.size - keyLen;
  for (var off = 0; off <= limit; off += stride) {
    if (budget.windows >= budget.max) {
      errors.push("tierD window cap " + budget.max + " reached at " + range.base.add(off) + " \u2014 sweep truncated");
      return false;
    }
    budget.windows++;
    var addr = range.base.add(off);
    var buf = readBuffer(addr, keyLen);
    if (buf === null)
      continue;
    var u8 = new Uint8Array(buf);
    var bstats = secretStats(u8, keyLen);
    if (bstats === null)
      continue;
    stats.tierD.candidates++;
    var id = sha1LowId(buf);
    if (mtstate.externalIds[id] !== true)
      continue;
    stats.tierD.confirmed++;
    emitAuthKey(id, hex2(u8), 0, defaultKeyType(), "D", "sweep@" + addr, stats);
  }
  return true;
}
function runTierD(ranges, stats, errors) {
  var tier = mtstate.profile.tiers.D_entropy_sweep;
  if (!tier)
    return;
  stats.tierD.enabled = tier.enabled === true;
  if (!stats.tierD.enabled)
    return;
  if (tier.require_external_ids && countKeys(mtstate.externalIds) === 0) {
    errors.push("tierD skipped: require_external_ids is set and configure() received no externalIds");
    return;
  }
  stats.tierD.state = "ran";
  var budget = {
    windows: 0,
    max: positiveOr(tier.max_windows, DEFAULT_TIER_D_MAX_WINDOWS)
  };
  for (var i = 0; i < ranges.length; i++) {
    try {
      if (!sweepRangeForIds(ranges[i], tier, budget, stats, errors))
        return;
    } catch (e) {
      errors.push("tierD " + ranges[i].base + ": " + e.message);
    }
  }
}
function findTgnetModule(tier) {
  var re;
  try {
    re = new RegExp(tier.module_name_regex || "libtmessages\\.\\d+\\.so");
  } catch (e) {
    re = /libtmessages\.\d+\.so/;
  }
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (re.test(mods[i].name) || re.test(mods[i].path))
        return mods[i];
    }
  } catch (e) {
  }
  return null;
}
function moduleReadableRanges(mod) {
  var out = [], prots = ["r--", "r-x"], p, i;
  for (p = 0; p < prots.length; p++) {
    try {
      var rs = mod.enumerateRanges(prots[p]);
      for (i = 0; i < rs.length; i++)
        out.push(rs[i]);
    } catch (e) {
    }
  }
  if (out.length === 0) {
    try {
      var lo = untag2(mod.base), hi = lo.add(mod.size);
      var all = Process.enumerateRanges({ protection: "r--", coalesce: false });
      for (var j = 0; j < all.length; j++) {
        var b = untag2(all[j].base);
        if (b.compare(lo) >= 0 && b.compare(hi) < 0)
          out.push(all[j]);
      }
    } catch (e) {
    }
  }
  return out;
}
function scanRangesAll(ranges, pattern, cap) {
  var out = [], i, j;
  for (i = 0; i < ranges.length; i++) {
    try {
      var hits = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
      for (j = 0; j < hits.length; j++) {
        out.push(hits[j].address);
        if (cap && out.length >= cap)
          return out;
      }
    } catch (e) {
    }
  }
  return out;
}
function deriveConnectionVtableViaRtti(mod, tier) {
  var mangled = tier && typeof tier.rtti_type_name_mangled === "string" && tier.rtti_type_name_mangled.length > 0 ? tier.rtti_type_name_mangled : "10Connection";
  var ranges = moduleReadableRanges(mod);
  if (ranges.length === 0)
    return null;
  var nameBytes = [0], c;
  for (c = 0; c < mangled.length; c++)
    nameBytes.push(mangled.charCodeAt(c) & 255);
  nameBytes.push(0);
  var namePattern = hexToScanPattern(hex2(new Uint8Array(nameBytes)));
  var nameHits = scanRangesAll(ranges, namePattern, 8);
  for (var n = 0; n < nameHits.length; n++) {
    var nameAddr = nameHits[n].add(1);
    var l1s = scanRangesAll(ranges, pointerToScanNeedle(nameAddr), 8);
    for (var a = 0; a < l1s.length; a++) {
      var T = l1s[a].sub(Process.pointerSize);
      var l2s = scanRangesAll(ranges, pointerToScanNeedle(T), 32);
      for (var b = 0; b < l2s.length; b++) {
        var offTop = readPointerOrNull2(l2s[b].sub(Process.pointerSize));
        if (offTop === null || !offTop.isNull())
          continue;
        var vfnSlot = l2s[b].add(Process.pointerSize);
        var vfn = readPointerOrNull2(vfnSlot);
        if (vfn === null)
          continue;
        var v = untag2(vfn), lo = untag2(mod.base), hi = lo.add(mod.size);
        if (v.compare(lo) < 0 || v.compare(hi) >= 0)
          continue;
        return vfnSlot;
      }
    }
  }
  return null;
}
function resolveConnectionVtable(profile) {
  var tier = profile.tiers && profile.tiers.E_connection_ctr_state;
  if (!tier || tier.enabled !== true)
    return null;
  var mod = findTgnetModule(tier);
  if (mod) {
    try {
      var derived = deriveConnectionVtableViaRtti(mod, tier);
      if (derived && !derived.isNull()) {
        mtstate.connectionVtableSource = "rtti";
        mtstate.connectionVtableRva = derived.sub(mod.base);
        log2("info", "[Tier E] Connection vtable resolved via RTTI at " + derived + " (rva 0x" + mtstate.connectionVtableRva.toString(16) + ", self-healing)");
        return derived;
      }
    } catch (e) {
    }
  }
  var rva = tier.vtable_ptr_rva;
  if (typeof rva === "number" && isFinite(rva) && mod) {
    try {
      mtstate.connectionVtableSource = "rva";
      mtstate.connectionVtableRva = ptr(rva);
      return mod.base.add(rva);
    } catch (e) {
    }
  }
  var symbol = tier.vtable_symbol;
  if (typeof symbol === "string" && symbol.length > 0) {
    try {
      var sym = DebugSymbol.fromName(symbol);
      if (sym && sym.address && !sym.address.isNull()) {
        mtstate.connectionVtableSource = "symbol";
        return sym.address;
      }
    } catch (e) {
    }
  }
  mtstate.connectionVtableSource = null;
  return null;
}
function pointerToScanNeedle(p) {
  var bytes = [], value = untag2(p), i;
  for (i = 0; i < Process.pointerSize; i++) {
    bytes.push(parseInt(value.and(255).toString(10), 10));
    value = value.shr(8);
  }
  return hexToScanPattern(hex2(new Uint8Array(bytes)));
}
function readAes256KeyFromSchedule(scheduleAddr) {
  var out = new Uint8Array(32), i, word;
  for (i = 0; i < 8; i++) {
    word = readU32OrNull2(scheduleAddr.add(i * 4));
    if (word === null)
      return null;
    out[i * 4 + 0] = word >>> 24 & 255;
    out[i * 4 + 1] = word >>> 16 & 255;
    out[i * 4 + 2] = word >>> 8 & 255;
    out[i * 4 + 3] = word & 255;
  }
  return out;
}
function connectionOffsetsComplete(off) {
  if (!off)
    return false;
  var fields = [
    "encrypt_key",
    "encrypt_ivec",
    "encrypt_num",
    "decrypt_key",
    "decrypt_ivec",
    "decrypt_num"
  ];
  for (var i = 0; i < fields.length; i++) {
    if (typeof off[fields[i]] !== "number")
      return false;
  }
  return true;
}
function readRawAes256Key(scheduleAddr, rawLen, byteswap) {
  if (byteswap)
    return readAes256KeyFromSchedule(scheduleAddr);
  var b = readBuffer(scheduleAddr, rawLen || 32);
  return b === null ? null : new Uint8Array(b);
}
function processConnectionCandidate(objBase, off, stats) {
  var byteswap = off.byteswap_schedule_words === true;
  var rawLen = typeof off.raw_key_len === "number" ? off.raw_key_len : 32;
  var keyOut = readRawAes256Key(shift(objBase, off.encrypt_key), rawLen, byteswap);
  var keyIn = readRawAes256Key(shift(objBase, off.decrypt_key), rawLen, byteswap);
  if (keyOut === null || keyIn === null)
    return false;
  var ivOut = readBuffer(shift(objBase, off.encrypt_ivec), 16);
  var ivIn = readBuffer(shift(objBase, off.decrypt_ivec), 16);
  if (ivOut === null || ivIn === null)
    return false;
  var numOut = readS32OrNull(shift(objBase, off.encrypt_num));
  var numIn = readS32OrNull(shift(objBase, off.decrypt_num));
  if (numOut === null || numIn === null)
    return false;
  var endpoint = readConnectionEndpoint(objBase, off);
  stats.tierE.candidates++;
  emitObfKey(hex2(keyOut), hex2(new Uint8Array(ivOut)), hex2(keyIn), hex2(new Uint8Array(ivIn)), numOut & 15, numIn & 15, endpoint, "E", "connection@" + untag2(objBase), stats);
  return true;
}
function rememberConnection(objBase) {
  var s = untag2(objBase).toString();
  if (mtstate.confirmedConnections.indexOf(s) === -1)
    mtstate.confirmedConnections.push(s);
}
function runTierE(ranges, stats, errors) {
  var tier = mtstate.profile.tiers && mtstate.profile.tiers.E_connection_ctr_state;
  if (!tier)
    return;
  stats.tierE.enabled = tier.enabled === true;
  if (!stats.tierE.enabled)
    return;
  var off = mtstate.profile.struct_offsets && mtstate.profile.struct_offsets.Connection;
  if (!connectionOffsetsComplete(off)) {
    stats.tierE.skipReason = "offsets-not-reverse-engineered";
    return;
  }
  if (mtstate.connectionVtable === null || mtstate.connectionVtable.isNull()) {
    stats.tierE.skipReason = "vtable-unresolved";
    return;
  }
  stats.tierE.state = "ran";
  stats.tierE.vtableSource = mtstate.connectionVtableSource || null;
  var needle = pointerToScanNeedle(mtstate.connectionVtable);
  var hits = scanRanges(ranges, needle, errors);
  stats.tierE.vtableHits += hits.length;
  if (hits.length === 0 && !mtstate.tierEWarned) {
    mtstate.tierEWarned = true;
    log2("warn", "[Tier E] 0 live Connection objects matched the vtable anchor " + mtstate.connectionVtable + " (source=" + (mtstate.connectionVtableSource || "?") + "). No MTPROTO_OBF_KEY will be emitted, so a mid-stream (attach) Telegram connection cannot be decrypted offline. Likely: (a) no Connection was alive during this scan \u2014 keep Telegram in the foreground and exchange a few messages; or (b) the vtable anchor is stale for this build and the RTTI walk failed \u2014 recalibrate struct_offsets.Connection / vtable_ptr_rva.");
  }
  for (var h = 0; h < hits.length; h++) {
    try {
      if (processConnectionCandidate(hits[h], off, stats))
        rememberConnection(hits[h]);
    } catch (e) {
      errors.push("tierE " + hits[h] + ": " + e.message);
    }
  }
}
function countKeys(obj) {
  var n = 0;
  for (var k in obj)
    if (obj.hasOwnProperty(k))
      n++;
  return n;
}
function positiveOr(value, fallback) {
  if (typeof value !== "number" || !isFinite(value) || value < 1)
    return fallback;
  return Math.floor(value);
}
function checkPointerSize(profile) {
  var declared = profile.match && profile.match.pointer_size;
  if (declared === Process.pointerSize)
    return;
  throw new Error("profile '" + profile.id + "' declares match.pointer_size " + declared + " but this process reports Process.pointerSize " + Process.pointerSize + "; every offset in this profile assumes an " + declared + "-byte pointer, so a target of a different width needs a different profile, not a flag.");
}
function checkArtRefOffsets(profile) {
  var tier = profile.tiers.C_art_secretchat_key;
  if (!tier || tier.enabled !== true || tier.art_ref_roundtrip === false)
    return;
  var off = profile.struct_offsets && profile.struct_offsets.EncryptedChat;
  if (off && isNonEmptyArray(off.auth_key_ref_candidates))
    return;
  throw new Error("profile '" + profile.id + "' enables C_art_secretchat_key with art_ref_roundtrip but carries no struct_offsets.EncryptedChat.auth_key_ref_candidates list, so the ART back-reference check has no offset to try and every emitted chat_id would be unverified.");
}
function normaliseExternalIds(ids) {
  var set = {};
  if (!ids || !ids.length)
    return set;
  for (var i = 0; i < ids.length; i++) {
    var id = String(ids[i]).toLowerCase().replace(/^0x/, "").replace(/\s+/g, "");
    if (id.length > 0)
      set[id] = true;
  }
  return set;
}
function mtprotoConfigure(profile) {
  checkPointerSize(profile);
  checkArtRefOffsets(profile);
  mtstate.profile = profile;
  mtstate.validators = parseValidators2(profile.validators);
  mtstate.emitUnconfirmed = profile.emitUnconfirmed === true;
  mtstate.externalIds = normaliseExternalIds(profile.externalIds);
  mtstate.maxHitsPerScan = positiveOr(profile.maxHitsPerScan, DEFAULT_MAX_HITS_PER_SCAN);
  mtstate.connectionVtable = resolveConnectionVtable(profile);
}
function fullRescanEvery() {
  var c = mtstate.profile.constants;
  return positiveOr(c && c.full_rescan_every, 8);
}
function revalidateAuthKey(entry, tier, stats) {
  var buf = readBuffer(ptr(entry.keyPtr), tier.key_len);
  if (buf === null)
    return false;
  if (sha1LowId(buf) !== entry.id)
    return false;
  var byteArray = untag2(ptr(entry.byteArray)), live = false;
  for (var i = 0; i < entry.slots.length; i++) {
    var back = readPointerOrNull2(ptr(entry.slots[i]));
    if (back !== null && !back.isNull() && untag2(back).equals(byteArray)) {
      live = true;
      break;
    }
  }
  if (!live)
    return false;
  emitAuthKey(entry.id, entry.keyHex, entry.dcId, entry.keyType, "B", "revalidated", stats);
  return true;
}
function markTierERevalidated(tierE) {
  tierE.enabled = true;
  tierE.state = "revalidated";
}
function revalidateConfirmed(stats) {
  var tierA = mtstate.profile.tiers.A_bytearray_authkey;
  for (var id in mtstate.confirmedAuthKeys) {
    if (!mtstate.confirmedAuthKeys.hasOwnProperty(id))
      continue;
    var ok = false;
    try {
      ok = revalidateAuthKey(mtstate.confirmedAuthKeys[id], tierA, stats);
    } catch (e) {
      stats.errors.push("reval authkey " + id + ": " + e.message);
    }
    if (ok) {
      stats.revalidated++;
    } else {
      stats.revalidationMisses++;
      mtstate.forceFullNext = true;
    }
  }
  var off = mtstate.profile.struct_offsets && mtstate.profile.struct_offsets.Connection;
  var vtable = mtstate.connectionVtable;
  if (mtstate.confirmedConnections.length > 0)
    markTierERevalidated(stats.tierE);
  for (var c = 0; c < mtstate.confirmedConnections.length; c++) {
    var objBase = ptr(mtstate.confirmedConnections[c]);
    var alive = false;
    try {
      var first = readPointerOrNull2(objBase);
      if (first !== null && vtable !== null && untag2(first).equals(untag2(vtable))) {
        alive = processConnectionCandidate(objBase, off, stats);
      }
    } catch (e) {
      stats.errors.push("reval conn " + objBase + ": " + e.message);
    }
    if (alive) {
      stats.revalidated++;
    } else {
      stats.revalidationMisses++;
      mtstate.forceFullNext = true;
    }
  }
}
function mtprotoScanOnce() {
  var started = Date.now();
  var stats = {
    /* `state` is the tier's 3-way answer — "off", "throttled" or "ran" —
     * and is the field to read. The older enabled/skipped/throttledBy
     * booleans are kept beside it for compatibility; throttledBy is detail
     * of "throttled". */
    tierA: { state: "off", candidates: 0, aligned: 0, ptrOk: 0, entropyOk: 0 },
    tierB: { state: "off", needles: 0, idHits: 0, confirmed: 0 },
    /* Tier C also carries the evidence counters for the ART back-reference
     * round trip. The two offset->count maps are what makes a retarget
     * VISIBLE: dataOffsetHits says which key-data offset produced the
     * blobs, roundTripByOffset which reference slot closed. */
    tierC: {
      state: "off",
      candidates: 0,
      entropyOk: 0,
      confirmed: 0,
      enabled: false,
      skipped: false,
      throttledBy: null,
      sitesTested: 0,
      roundTrips: 0,
      roundTripsPoisoned: 0,
      colocatedOnly: 0,
      refCheckSkipped: 0,
      dataOffsetHits: {},
      roundTripByOffset: {}
    },
    tierD: { state: "off", enabled: false, candidates: 0, confirmed: 0 },
    /* Tier E (obfuscated-transport CTR state) mirrors tierB/tierD: `state`
     * is the 3-way answer, `skipReason` explains an enabled-but-off tier
     * (offsets not yet reverse-engineered, or vtable unresolved). ENABLED and
     * validated on-device; when the tier is off it self-reports "off" with a
     * reason and touches nothing at runtime. On an INCREMENTAL pass that re-read
     * remembered Connections, state is "revalidated" (see markTierERevalidated). */
    tierE: { state: "off", enabled: false, skipReason: null, vtableHits: 0, candidates: 0, vtableSource: null },
    /* Incremental-pass telemetry: `mode` is the pass kind, revalidated/
     * revalidationMisses count remembered objects re-read on an incremental
     * pass (both stay 0 on a full pass). */
    mode: "full",
    revalidated: 0,
    revalidationMisses: 0,
    emitted: 0,
    faults: 0,
    durationMs: 0,
    errors: []
  };
  if (mtstate.profile === null) {
    stats.errors.push("configure() has not been called");
    return stats;
  }
  var scanIndex = mtstate.scanIndex;
  var nothingRemembered = countKeys(mtstate.confirmedAuthKeys) === 0 && mtstate.confirmedConnections.length === 0;
  var noConnectionDiscoveredYet = mtstate.confirmedConnections.length === 0;
  var fullPass = scanIndex === 0 || mtstate.forceFullNext || nothingRemembered || noConnectionDiscoveredYet || scanIndex % fullRescanEvery() === 0;
  stats.mode = fullPass ? "full" : "incremental";
  if (fullPass) {
    mtstate.confirmedAuthKeys = {};
    mtstate.confirmedConnections = [];
    var pass = beginPass();
    mtstate.mappedRanges = buildMappedRangeIndex2(pass.ranges);
    var native = selectRanges(mtstate.profile.scan_regions, pass);
    var candidates = runTierA2(native, stats, stats.errors);
    runTierB2(native, candidates, stats, stats.errors);
    reportUnconfirmed(candidates, stats);
    runTierC2(pass, stats, stats.errors);
    runTierD(native, stats, stats.errors);
    runTierE(native, stats, stats.errors);
    mtstate.forceFullNext = false;
  } else {
    revalidateConfirmed(stats);
  }
  mtstate.scanIndex++;
  stats.faults = mtstate.faults;
  stats.durationMs = Date.now() - started;
  mtstate.mappedRanges = null;
  mtstate.mapsIndex = null;
  return stats;
}

// agent/ms_agent/engines/mtproto/index.ts
var MtprotoEngine = {
  name: "mtproto",
  runTiers: function(ranges, stats, errors) {
    try {
      if (mtstate.profile !== state.profile) {
        mtprotoConfigure(state.profile);
      }
    } catch (e) {
      errors.push("mtproto configure failed: " + (e && e.message ? e.message : e));
      return;
    }
    var m = mtprotoScanOnce();
    if (m && m.errors) {
      for (var i = 0; i < m.errors.length; i++)
        errors.push(m.errors[i]);
    }
    stats.emitted = (stats.emitted || 0) + (m && m.emitted ? m.emitted : 0);
    stats.mtproto = m;
  }
};
registerEngine(MtprotoEngine);

// agent/ms_agent/core/ranges.ts
var mapsIndex = null;
function addressToNumber3(ptr2) {
  return parseInt(ptr2.toString(16), 16);
}
function nameNeedles(cfg) {
  return [].concat(cfg.name_allowlist || [], cfg.name_denylist || []);
}
function loadAnonNames(needles) {
  mapsIndex = [];
  var text;
  try {
    text = File.readAllText("/proc/self/maps");
  } catch (e) {
    log("warn", "cannot read /proc/self/maps (" + e.message + "); range names unavailable, allowlist will be skipped");
    return;
  }
  var lines = text.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.indexOf("[") === -1 && line.indexOf("/") === -1)
      continue;
    if (!matchesAny2(line, needles))
      continue;
    var m = /^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
    if (m !== null)
      mapsIndex.push([parseInt(m[1], 16), parseInt(m[2], 16), m[3].trim()]);
  }
  mapsIndex.sort(function(a, b) {
    return a[0] - b[0];
  });
}
function findInterval2(index, value) {
  var lo = 0, hi = index.length - 1;
  while (lo <= hi) {
    var mid = lo + hi >> 1;
    var e = index[mid];
    if (value < e[0])
      hi = mid - 1;
    else if (value >= e[1])
      lo = mid + 1;
    else
      return e;
  }
  return null;
}
function rangeLabel2(range) {
  if (range.file)
    return range.file.path;
  if (range.name)
    return range.name;
  if (mapsIndex === null)
    return "";
  var e = findInterval2(mapsIndex, addressToNumber3(range.base));
  return e === null ? "" : e[2];
}
function matchesAny2(label, needles) {
  if (!needles || needles.length === 0)
    return false;
  var haystack = label.toLowerCase();
  for (var i = 0; i < needles.length; i++) {
    if (haystack.indexOf(needles[i].toLowerCase()) !== -1)
      return true;
  }
  return false;
}
function isAnonymous(range) {
  return !range.file;
}
var AGENT_MODULE_PATTERNS2 = [/frida/i, /gum-js-loop/i];
function looksAgentOwned2(text) {
  if (!text)
    return false;
  for (var i = 0; i < AGENT_MODULE_PATTERNS2.length; i++) {
    if (AGENT_MODULE_PATTERNS2[i].test(text))
      return true;
  }
  return false;
}
function buildAgentOwnedRanges2() {
  var owned = [];
  try {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
      var m = modules[i];
      if (looksAgentOwned2(m.name) || looksAgentOwned2(m.path)) {
        owned.push({ base: m.base, end: m.base.add(m.size) });
      }
    }
  } catch (e) {
    log("warn", "enumerateModules failed (" + e.message + "); the agent's own ranges cannot be excluded by address this scan");
  }
  return owned;
}
function isAgentOwnedRange2(range, owned) {
  var end = range.base.add(range.size);
  for (var i = 0; i < owned.length; i++) {
    if (range.base.compare(owned[i].end) < 0 && owned[i].base.compare(end) < 0)
      return true;
  }
  return false;
}
function selectRangesWindows() {
  var cfg = state.profile.scan_regions;
  var owned = buildAgentOwnedRanges2();
  var all = Process.enumerateRanges({ protection: cfg.protection, coalesce: false });
  var eligible = [];
  for (var i = 0; i < all.length; i++) {
    var r = all[i];
    if (cfg.require_anonymous && !isAnonymous(r))
      continue;
    if (cfg.max_range_bytes && r.size > cfg.max_range_bytes)
      continue;
    if (isAgentOwnedRange2(r, owned))
      continue;
    eligible.push(r);
  }
  return eligible;
}
function selectRanges2() {
  if (Process.platform === "windows")
    return selectRangesWindows();
  var cfg = state.profile.scan_regions;
  loadAnonNames(nameNeedles(cfg));
  var owned = buildAgentOwnedRanges2();
  var all = Process.enumerateRanges({ protection: cfg.protection, coalesce: false });
  var eligible = [];
  var allowed = [];
  for (var i = 0; i < all.length; i++) {
    var r = all[i];
    if (cfg.require_anonymous && !isAnonymous(r))
      continue;
    if (cfg.max_range_bytes && r.size > cfg.max_range_bytes)
      continue;
    if (isAgentOwnedRange2(r, owned))
      continue;
    var label = rangeLabel2(r);
    if (matchesAny2(label, cfg.name_denylist))
      continue;
    eligible.push(r);
    if (matchesAny2(label, cfg.name_allowlist))
      allowed.push(r);
  }
  if (allowed.length === 0) {
    var fallback = eligible.filter(isAnonymous);
    log("warn", "no range matched name_allowlist [" + (cfg.name_allowlist || []).join(", ") + "] \u2014 range names are unavailable, which means name_denylist [" + (cfg.name_denylist || []).join(", ") + "] matched nothing either. Falling back to ALL " + fallback.length + " anonymous " + cfg.protection + " ranges, " + totalBytes2(fallback) + " bytes now in scope instead of the partition_alloc subset; scudo/guard/linker pages are no longer excluded and only the address-based agent-module exclusion still applies.");
    return fallback;
  }
  return allowed;
}
function totalBytes2(ranges) {
  return ranges.reduce(function(sum, r) {
    return sum + r.size;
  }, 0);
}

// agent/ms_agent/driver.ts
function profileEngine(profile) {
  var e = profile && profile.engine;
  return typeof e === "string" && e ? e : "boringssl";
}
function activateProfile(profile) {
  state.profile = profile;
  state.validators = profile && profile.validators ? parseValidators(profile.validators) : null;
}
function runEngineTiers(ranges, stats, errors) {
  var engine = profileEngine(state.profile);
  var impl = getEngine(engine);
  if (impl) {
    impl.runTiers(ranges, stats, errors);
    return;
  }
  errors.push('unknown engine "' + engine + '"; no tiers run for profile ' + (state.profile && state.profile.id));
}
function needsMappedIndex(profile) {
  var params = profile && profile.params || {};
  return params.needs_mapped_index !== false;
}
function scanProfileOnce(profile) {
  var started = Date.now();
  var stats = {
    // `skipped` distinguishes "Tier A ran and found nothing" from "Tier A
    // did not run this scan"; both would otherwise print as A 0/0.
    tierA: { candidates: 0, validated: 0, skipped: false },
    tierB: { candidates: 0, validated: 0 },
    tierC: { candidates: 0, validated: 0 },
    // Tier B candidates whose handshake state could not be determined;
    // see classifyHandshake(). Deliberate misses, not errors.
    indeterminateHs: 0,
    emitted: 0,
    durationMs: 0,
    errors: [],
    profileId: profile === null || profile === void 0 ? null : profile.id
  };
  if (profile === null || profile === void 0) {
    stats.errors.push("configure() has not been called");
    return stats;
  }
  if (state.profile !== profile)
    activateProfile(profile);
  state.mappedRanges = needsMappedIndex(profile) ? buildMappedRangeIndex() : null;
  var ranges = selectRanges2();
  runEngineTiers(ranges, stats, stats.errors);
  state.scanIndex++;
  stats.durationMs = Date.now() - started;
  return stats;
}

// agent/ms_agent/rpc.ts
function buildRpcExports() {
  const scanOnce = function() {
    var profiles = state.profiles !== null ? state.profiles : [state.profile];
    if (profiles.length <= 1) {
      return scanProfileOnce(profiles.length === 1 ? profiles[0] : null);
    }
    var results = [];
    for (var i = 0; i < profiles.length; i++)
      results.push(scanProfileOnce(profiles[i]));
    return results;
  };
  return {
    configure: function(profileOrProfiles) {
      try {
        var profiles = Array.isArray(profileOrProfiles) ? profileOrProfiles : [profileOrProfiles];
        state.profiles = profiles;
        installExceptionHandler();
        var totalRanges = 0;
        var totalRangeBytes = 0;
        var ids = [];
        for (var i = 0; i < profiles.length; i++) {
          activateProfile(profiles[i]);
          var ranges = selectRanges2();
          totalRanges += ranges.length;
          totalRangeBytes += totalBytes2(ranges);
          ids.push(profiles[i].id);
        }
        if (profiles.length === 1) {
          return {
            ok: true,
            profileId: profiles[0].id,
            ranges: totalRanges,
            rangeBytes: totalRangeBytes
          };
        }
        return {
          ok: true,
          profileId: ids,
          profiles: profiles.length,
          ranges: totalRanges,
          rangeBytes: totalRangeBytes
        };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    },
    scanOnce,
    needle: function() {
      if (state.needle === null)
        return null;
      return {
        value: state.needle.value.toString(),
        module: state.needle.module,
        rva: state.needle.rva
      };
    }
  };
}

// agent/memory_scan_agent.ts
rpc.exports = buildRpcExports();
