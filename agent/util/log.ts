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
const ISO = () => new Date().toISOString();

function parseStack(depth: number) {
  // depth=0: this function, 1: devlog_*, 2: your call site
  const err = new Error();
  if (!err.stack) return {};
  const lines = err.stack.split('\n').slice(depth + 1); // skip frames
  // V8/Node/Chromium style: "    at fn (file:line:col)"
  const re1 = /^\s*at\s+(.*?)\s+\((.*?):(\d+):(\d+)\)\s*$/;
  // Safari/Firefox/Frida style: "fn@file:line:col" or "at file:line:col"
  const re2 = /^(?:\s*at\s+)?(.*?):(\d+):(\d+)\s*$/;

  for (const l of lines) {
    let m = l.match(re1);
    if (m) {
      return { func: m[1], file: m[2], line: Number(m[3]), col: Number(m[4]) };
    }
    m = l.match(re2);
    if (m) {
      return { file: m[1], line: Number(m[2]), col: Number(m[3]) };
    }
  }
  return {};
}

// ANSI colors (Node/Frida terminals). In browsers they’ll be literal (fine).
const C = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
};

function levelTag(level: Level) {
  switch (level) {
    case 'debug': return `${C.blue}DEBUG${C.reset}`;
    case 'info':  return ` INFO `;
    case 'warn':  return `${C.yellow}WARN ${C.reset}`;
    case 'error': return `${C.red}ERROR${C.reset}`;
  }
}

function formatCallsite(cs: Partial<ReturnType<typeof parseStack>>) {
  if (!cs.file || !cs.line) return '';
  const short = cs.file.replace(/^.*[\\/]/, ''); // basename
  const fn = cs.func ? ` ${C.magenta}${cs.func}${C.reset}` : '';
  return `${C.dim}(${short}:${cs.line}:${cs.col ?? 0})${fn}${C.reset}`;
}

function emit(level: Level, msg: string, extra?: Record<string, unknown>) {
  const cs = ENABLE_CALLSITE ? parseStack(2) : {};
  const ts = ISO();
  const line = `${C.dim}${ts}${C.reset} ${levelTag(level)} ${msg} ${formatCallsite(cs)}`.trim();

  // Pretty to console (optional)
  // eslint-disable-next-line no-console
  (level === 'error' ? console.error :
   level === 'warn'  ? console.warn  :
   level === 'info'  ? console.info  : console.log)(line);

  // Structured payload (your original "send" contract)
  const payload: Record<string, unknown> = {
    contentType: `console_${level}`,
    level,
    time: ts,
    message: msg,
    ...('file' in cs && { file: cs.file, line: cs.line, col: cs.col, func: (cs as any).func }),
    ...(extra ?? {}),
  };
  send(payload);
}

// Public API
export const devlog_debug = (m: string, extra?: Record<string, unknown>) => emit('debug', m, extra);
export const devlog_info  = (m: string, extra?: Record<string, unknown>) => emit('info',  m, extra);
export const devlog_warn  = (m: string, extra?: Record<string, unknown>) => emit('warn',  m, extra);
export const devlog_error = (m: string, extra?: Record<string, unknown>) => emit('error', m, extra);
