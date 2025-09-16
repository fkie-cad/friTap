export function log(str: string) {
    var message: { [key: string]: string } = {}
    message["contentType"] = "console"
    message["console"] = str
    send(message)
}


export function devlog(str: string) {
    var message: { [key: string]: string } = {}
    message["contentType"] = "console_dev"
    message["console_dev"] = str
    send(message)
}

/*
old way of logging, kept for reference and will be removed in future versions

export function devlog_error(str: string) {
    var message: { [key: string]: string } = {}
    message["contentType"] = "console_error"
    message["console_error"] = str
    send(message)
}
*/


type Level = 'debug' | 'info' | 'warn' | 'error';
const ENABLE_CALLSITE = true;   // flip off if perf matters

// Types for the returned callsite
type CallSite = { func?: string; file?: string; line?: number; col?: number };

export function parseStack(): CallSite {
  const e = new Error();
  const raw = e.stack ? String(e.stack).split("\n").slice(1) : [];

  // skip our logger + frida internals
  const SKIP = /(agent[\\/](util[\\/])?log\.)|([\\/])frida[\\/]runtime[\\/]/;

  // Patterns (column part optional)
  const P1 = /^\s*at\s+([^\s]+)\s+\((.+):(\d+)(?::(\d+))?\)\s*$/; // at fn (file:line[:col])
  const P2 = /^\s*at\s+(.+):(\d+)(?::(\d+))?\s*$/;                 // at file:line[:col]
  const P3 = /^([^\s@]+)@(.+):(\d+)(?::(\d+))?\s*$/;               // fn@file:line[:col]
  const P4 = /^\s*(.+):(\d+)(?::(\d+))?\s*$/;                      // file:line[:col]

  for (let i = 0; i < raw.length; i++) {
    const lineStr = raw[i];

    let m: RegExpMatchArray | null = null;
    let func: string | undefined = undefined;
    let file: string | undefined = undefined;
    let l: string | undefined = undefined;
    let c: string | undefined = undefined;

    if ((m = lineStr.match(P1))) { func = m[1]; file = m[2]; l = m[3]; c = m[4]; }
    else if ((m = lineStr.match(P2))) { file = m[1]; l = m[2]; c = m[3]; }
    else if ((m = lineStr.match(P3))) { func = m[1]; file = m[2]; l = m[3]; c = m[4]; }
    else if ((m = lineStr.match(P4))) { file = m[1]; l = m[2]; c = m[3]; }
    else { continue; }

    if (!file || SKIP.test(file)) continue;

    const lineNum = parseInt(l!, 10);
    const colNum = c ? parseInt(c, 10) : undefined;
    return { func, file, line: lineNum, col: colNum };
  }
  return {};
}

function emit(level: Level, msg: string, extra?: Record<string, unknown>) {
  const cs = ENABLE_CALLSITE ? parseStack() : {};
  const ts = new Date().toISOString();
  if (typeof msg !== "string" || msg.length === 0) return;

  const file = (cs.file ? String(cs.file).replace(/^.*[\\/]/, "") : undefined);

  const payload: Record<string, unknown> = {
    contentType: `console_${level}`,
    level,
    time: ts,
    message: msg,
    ...(file ? { file, line: cs.line, col: cs.col, func: cs.func } : {}),
    ...(extra ?? {}),
  };
  send(payload);
}


// Public API
export const devlog_debug = (m: string, extra?: Record<string, unknown>) => emit('debug', m, extra);
export const devlog_info  = (m: string, extra?: Record<string, unknown>) => emit('info',  m, extra);
export const devlog_warn  = (m: string, extra?: Record<string, unknown>) => emit('warn',  m, extra);
export const devlog_error = (m: string, extra?: Record<string, unknown>) => emit('error', m, extra);
