// Process-wide libc socket observer as one CModule, shared by the socket fd tracker, the
// unwanted-fd eviction and the QUICHE UDP peer recovery. The listeners are C because a JS listener
// on libc can deadlock: Frida's GLib does I/O on app threads while holding its gmain lock, and the
// listener then waits for the JS lock, held by a thread that is waiting for gmain.

import { log, devlog } from "../util/log.js";

export const SOCK_STREAM = 1;
export const SOCK_DGRAM = 2;

// getsockopt(SO_TYPE) level/name and ENOTSOCK differ per platform; the SOCK_* types are portable.
const IS_DARWIN = Process.platform === "darwin";
export const SOL_SOCKET = IS_DARWIN ? 0xffff : 1;
export const SO_TYPE = IS_DARWIN ? 0x1008 : 3;
const ENOTSOCK = IS_DARWIN ? 38 : 88;
const EBADF = 9;

/** Deepest per-thread SSL scope stack; a missed onLeave must not grow it forever. */
export const MAX_SCOPE_DEPTH = 16;

/** libc I/O entry points the fd tracker hooks (both backends). */
export const SOCKET_IO_FUNCTIONS = ["recvfrom", "recv", "recvmsg", "sendto", "send", "sendmsg", "read", "write"];

/** bionic's close() calls it, and so does libcore's Linux_close without going through close(). */
const FDSAN_CLOSE = "android_fdsan_close_with_tag";

/** The libc function every fd close passes through: fdsan's close when exported, else close. */
export function fdCloseFunction(): string {
    return Module.findGlobalExportByName(FDSAN_CLOSE) !== null ? FDSAN_CLOSE : "close";
}

/** Closed fds since the consumer's last drain, or "lost" when the ring overran it. */
export type ClosedFdDrain = number[] | "lost";

/** Readers of the closed-fd ring; each has its own cursor. */
export const CLOSED_FD_CONSUMER = { socketFdTracker: 0, unwantedFds: 1 } as const;
type ClosedFdConsumer = typeof CLOSED_FD_CONSUMER[keyof typeof CLOSED_FD_CONSUMER];
const CLOSED_FD_CONSUMERS = 2;

const CLOSED_FD_RING_SIZE = 4096;
const UDP_PEER_RING_SIZE = 64;
const SOCKADDR_SLOT_SIZE = 32;                       // >= sizeof (struct sockaddr_in6)
const FD_CACHE_SIZE = 65536;
const THREAD_TABLE_SLOTS = 4096;

const C_SOURCE = `
#include <glib.h>
#include <gum/guminterceptor.h>

#define THREAD_PROBES 32

#define KIND_UNKNOWN 0
#define KIND_STREAM 1
#define KIND_DGRAM 2
#define KIND_OTHER_SOCKET 3
#define KIND_NOT_SOCKET 4
#define KIND_BAD_FD 5                  /* probe result only, never cached */

typedef int (* GetsockoptFn) (int fd, int level, int name, void * optval, unsigned int * optlen);
typedef int * (* ErrnoFn) (void);

/* gen: the fd's generation when noted; a close() or dup2() over the fd bumps it. */
typedef struct { gpointer ssl; gint fd; guint gen; } FtScope;
typedef struct { gint type; } FtSocketInvocation;
typedef struct { gint fd; gint kind; gconstpointer addr; guint len; } FtConnectInvocation;
typedef struct { gint source; gint target; guint8 target_kind; } FtDupInvocation;

/* One JS-allocated block passed in as the ft_state symbol: a CModule's own globals are not
   writable on every platform (macOS/iOS map the image read-only). */
typedef struct
{
  /* JS reads these without the lock to skip empty drains; keep them first. */
  volatile guint closed_head;
  volatile guint closed_tail[CLOSED_CONSUMERS];
  volatile guint udp_head;
  volatile guint udp_tail;
  guint big_fd_gen;                    /* generation shared by all fds >= FD_CACHE_SIZE */
  GMutex lock;
  GetsockoptFn getsockopt;
  ErrnoFn errno_location;
  gint closed_ring[CLOSED_RING_SIZE];
  guint8 udp_ring[UDP_RING_SIZE][SOCKADDR_SLOT];
  volatile guint8 fd_kind[FD_CACHE_SIZE];
  guint16 fd_gen[FD_CACHE_SIZE];
  gsize tids[THREAD_SLOTS];            /* 0 = empty slot */
  gint last_fd[THREAD_SLOTS];          /* -1 = none */
  guint last_gen[THREAD_SLOTS];
  gint depth[THREAD_SLOTS];
  FtScope scopes[THREAD_SLOTS][MAX_SCOPE_DEPTH];
} FtState;

extern FtState ft_state;

static gint
ft_int_arg (GumInvocationContext * ic, guint n)
{
  return (gint) (gsize) gum_invocation_context_get_nth_argument (ic, n);
}

static gint
ft_return_value (GumInvocationContext * ic)
{
  return (gint) (gsize) gum_invocation_context_get_return_value (ic);
}

static guint
ft_gen (gint fd)
{
  return (fd < FD_CACHE_SIZE) ? ft_state.fd_gen[fd] : ft_state.big_fd_gen;
}

/* fd if it has not been closed since it was noted at gen, else -1. Caller holds the lock. */
static gint
ft_valid_fd (gint fd, guint gen)
{
  return (fd >= 0 && ft_gen (fd) == gen) ? fd : -1;
}

static void
ft_reset_slot (guint slot, gsize tid)
{
  ft_state.tids[slot] = tid;
  ft_state.last_fd[slot] = -1;
  ft_state.depth[slot] = 0;
}

/* Caller holds the lock. Returns the slot index, or -1 when absent and !create. Never deletes:
   a full probe window evicts the home slot (that thread's state is simply forgotten). */
static gint
ft_thread_slot (gsize tid, gboolean create)
{
  guint home = (guint) ((tid * 2654435761u) % THREAD_SLOTS);
  guint i;

  for (i = 0; i != THREAD_PROBES; i++)
  {
    guint slot = (home + i) % THREAD_SLOTS;
    if (ft_state.tids[slot] == tid)
      return (gint) slot;
    if (ft_state.tids[slot] == 0)
    {
      if (!create)
        return -1;
      ft_reset_slot (slot, tid);
      return (gint) slot;
    }
  }
  if (!create)
    return -1;
  ft_reset_slot (home, tid);
  return (gint) home;
}

static guint8
ft_kind_from_type (gint type)
{
  if (type == FT_SOCK_STREAM)
    return KIND_STREAM;
  if (type == FT_SOCK_DGRAM)
    return KIND_DGRAM;
  return KIND_OTHER_SOCKET;
}

/* getsockopt(SO_TYPE), without the lock. ENOTSOCK is definitive; EBADF only says the fd is not
   open right now. */
static guint8
ft_probe_kind (gint fd)
{
  gint type = 0;
  unsigned int len = sizeof (type);

  if (ft_state.getsockopt == NULL)
    return KIND_UNKNOWN;
  if (ft_state.getsockopt (fd, FT_SOL_SOCKET, FT_SO_TYPE, &type, &len) == 0)
    return ft_kind_from_type (type);
  if (ft_state.errno_location != NULL && *ft_state.errno_location () == FT_ENOTSOCK)
    return KIND_NOT_SOCKET;
  if (ft_state.errno_location != NULL && *ft_state.errno_location () == FT_EBADF)
    return KIND_BAD_FD;
  return KIND_UNKNOWN;
}

/* Cached kinds are read without the lock (one byte). A probed kind is cached unless the fd was
   closed while probing. */
static guint8
ft_kind (gint fd)
{
  guint8 kind;
  guint gen;

  if (fd < FD_CACHE_SIZE && (kind = ft_state.fd_kind[fd]) != KIND_UNKNOWN)
    return kind;
  gen = ft_gen (fd);
  kind = ft_probe_kind (fd);
  if (kind != KIND_UNKNOWN && kind != KIND_BAD_FD && fd < FD_CACHE_SIZE)
  {
    g_mutex_lock (&ft_state.lock);
    if (ft_state.fd_gen[fd] == gen)
      ft_state.fd_kind[fd] = kind;
    g_mutex_unlock (&ft_state.lock);
  }
  return kind;
}

static void
ft_note_stream_io (gsize tid, gint fd, gboolean scoped)
{
  gint slot;
  guint gen;

  g_mutex_lock (&ft_state.lock);
  gen = ft_gen (fd);
  slot = ft_thread_slot (tid, TRUE);
  ft_state.last_fd[slot] = fd;
  ft_state.last_gen[slot] = gen;
  if (scoped && ft_state.depth[slot] > 0)
  {
    FtScope * scope = &ft_state.scopes[slot][ft_state.depth[slot] - 1];
    scope->fd = fd;
    scope->gen = gen;
  }
  g_mutex_unlock (&ft_state.lock);
}

/* Kind of an fd about to be closed, probed while it is still open. Not cached: it is forgotten
   right after. Without this every file close would be pushed and overrun the ring. */
static guint8
ft_closing_kind (gint fd)
{
  guint8 kind;

  if (fd < FD_CACHE_SIZE && (kind = ft_state.fd_kind[fd]) != KIND_UNKNOWN)
    return kind;
  return ft_probe_kind (fd);
}

/* Caller holds the lock; kind is ft_closing_kind (fd). The fd number may now name another file:
   new generation, unknown kind, and every possibly-socket fd is reported to the closed-fd
   consumers. */
static void
ft_forget_fd (gint fd, guint8 kind)
{
  if (fd < FD_CACHE_SIZE)
  {
    ft_state.fd_kind[fd] = KIND_UNKNOWN;
    ft_state.fd_gen[fd]++;
  }
  else
  {
    ft_state.big_fd_gen++;
  }
  if (kind == KIND_NOT_SOCKET || kind == KIND_BAD_FD)
    return;
  ft_state.closed_ring[ft_state.closed_head % CLOSED_RING_SIZE] = fd;
  ft_state.closed_head++;
}

static void
ft_push_udp_peer (const guint8 * addr, guint len)
{
  guint8 * slot;
  guint i;

  if (len > SOCKADDR_SLOT)
    len = SOCKADDR_SLOT;
  g_mutex_lock (&ft_state.lock);
  slot = ft_state.udp_ring[ft_state.udp_head % UDP_RING_SIZE];
  for (i = 0; i != len; i++)
    slot[i] = addr[i];
  for (; i != SOCKADDR_SLOT; i++)
    slot[i] = 0;
  ft_state.udp_head++;
  g_mutex_unlock (&ft_state.lock);
}

/* ── libc listeners ─────────────────────────────────────────────────────────────────────── */

void
ft_socket_on_enter (GumInvocationContext * ic)
{
  FtSocketInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtSocketInvocation);
  inv->type = ft_int_arg (ic, 1);
}

void
ft_socket_on_leave (GumInvocationContext * ic)
{
  FtSocketInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtSocketInvocation);
  gint fd = ft_return_value (ic);

  if (fd < 0 || fd >= FD_CACHE_SIZE)
    return;
  g_mutex_lock (&ft_state.lock);
  ft_state.fd_kind[fd] = ft_kind_from_type (inv->type & 0x7f);
  g_mutex_unlock (&ft_state.lock);
}

void
ft_connect_on_enter (GumInvocationContext * ic)
{
  FtConnectInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtConnectInvocation);

  inv->fd = ft_int_arg (ic, 0);
  inv->addr = gum_invocation_context_get_nth_argument (ic, 1);
  inv->len = (guint) ft_int_arg (ic, 2);
  inv->kind = (inv->fd >= 0) ? ft_kind (inv->fd) : KIND_UNKNOWN;
  if (inv->kind == KIND_STREAM)
    ft_note_stream_io (gum_invocation_context_get_thread_id (ic), inv->fd, FALSE);
}

void
ft_connect_on_leave (GumInvocationContext * ic)
{
  FtConnectInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtConnectInvocation);

  /* The kernel read len bytes at addr for a successful connect(), so they are mapped. */
  if (inv->kind != KIND_DGRAM || inv->addr == NULL || ft_return_value (ic) != 0)
    return;
  ft_push_udp_peer ((const guint8 *) inv->addr, inv->len);
}

void
ft_close_on_enter (GumInvocationContext * ic)
{
  gint fd = ft_int_arg (ic, 0);
  guint8 kind;

  if (fd < 0)
    return;
  kind = ft_closing_kind (fd);
  g_mutex_lock (&ft_state.lock);
  ft_forget_fd (fd, kind);
  g_mutex_unlock (&ft_state.lock);
}

void
ft_dup_on_enter (GumInvocationContext * ic)
{
  FtDupInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtDupInvocation);
  inv->source = ft_int_arg (ic, 0);
  inv->target = ft_int_arg (ic, 1);
  inv->target_kind = (inv->target >= 0) ? ft_closing_kind (inv->target) : KIND_UNKNOWN;
}

/* dup2/dup3 close the target fd without calling close(). */
void
ft_dup_on_leave (GumInvocationContext * ic)
{
  FtDupInvocation * inv = GUM_IC_GET_INVOCATION_DATA (ic, FtDupInvocation);

  if (ft_return_value (ic) < 0 || inv->target < 0 || inv->source == inv->target)
    return;
  g_mutex_lock (&ft_state.lock);
  ft_forget_fd (inv->target, inv->target_kind);
  g_mutex_unlock (&ft_state.lock);
}

void
ft_io_on_enter (GumInvocationContext * ic)
{
  gint fd = ft_int_arg (ic, 0);

  if (fd < 0 || ft_kind (fd) != KIND_STREAM)
    return;
  ft_note_stream_io (gum_invocation_context_get_thread_id (ic), fd, TRUE);
}

/* ── exported to JS (NativeFunction, scheduling: exclusive) ─────────────────────────────── */

gsize
ft_state_size (void)
{
  return sizeof (FtState);
}

/* Zeroes the state block (a zeroed GMutex is a valid unlocked mutex); runs before any attach. */
void
ft_init (gpointer getsockopt_impl, gpointer errno_impl)
{
  guint8 * bytes = (guint8 *) &ft_state;
  gsize i;

  for (i = 0; i != sizeof (FtState); i++)
    bytes[i] = 0;
  ft_state.getsockopt = (GetsockoptFn) getsockopt_impl;
  ft_state.errno_location = (ErrnoFn) errno_impl;
}

void
ft_scope_push (gsize tid, gpointer ssl)
{
  gint slot, i;

  g_mutex_lock (&ft_state.lock);
  slot = ft_thread_slot (tid, TRUE);
  if (ft_state.depth[slot] >= MAX_SCOPE_DEPTH)
  {
    for (i = 1; i < ft_state.depth[slot]; i++)        /* drop a stale frame whose onLeave never ran */
      ft_state.scopes[slot][i - 1] = ft_state.scopes[slot][i];
    ft_state.depth[slot]--;
  }
  ft_state.scopes[slot][ft_state.depth[slot]].ssl = ssl;
  ft_state.scopes[slot][ft_state.depth[slot]].fd = -1;
  ft_state.depth[slot]++;
  g_mutex_unlock (&ft_state.lock);
}

/* Pops ssl's scope (and any stale frames above it); returns its fd, or -1 (no I/O, no scope, or
   the fd was closed since). */
gint
ft_scope_pop (gsize tid, gpointer ssl)
{
  gint slot, i, fd = -1;

  g_mutex_lock (&ft_state.lock);
  slot = ft_thread_slot (tid, FALSE);
  if (slot >= 0)
  {
    for (i = ft_state.depth[slot] - 1; i >= 0; i--)
    {
      if (ft_state.scopes[slot][i].ssl == ssl)
        break;
    }
    if (i >= 0)
    {
      fd = ft_valid_fd (ft_state.scopes[slot][i].fd, ft_state.scopes[slot][i].gen);
      ft_state.depth[slot] = i;
    }
  }
  g_mutex_unlock (&ft_state.lock);
  return fd;
}

gint
ft_recover (gsize tid)
{
  gint slot, fd = -1;

  g_mutex_lock (&ft_state.lock);
  slot = ft_thread_slot (tid, FALSE);
  if (slot >= 0)
    fd = ft_valid_fd (ft_state.last_fd[slot], ft_state.last_gen[slot]);
  g_mutex_unlock (&ft_state.lock);
  return fd;
}

void
ft_closed_skip (guint consumer)
{
  g_mutex_lock (&ft_state.lock);
  ft_state.closed_tail[consumer] = ft_state.closed_head;
  g_mutex_unlock (&ft_state.lock);
}

/* Copies the consumer's pending closed fds into out (CLOSED_RING_SIZE entries). Returns the count,
   or -1 when the ring overran the consumer (it must then forget every fd it caches). */
gint
ft_drain_closed (guint consumer, gint * out)
{
  guint pending, n;

  g_mutex_lock (&ft_state.lock);
  pending = ft_state.closed_head - ft_state.closed_tail[consumer];
  if (pending > CLOSED_RING_SIZE)
  {
    ft_state.closed_tail[consumer] = ft_state.closed_head;
    g_mutex_unlock (&ft_state.lock);
    return -1;
  }
  for (n = 0; n != pending; n++)
    out[n] = ft_state.closed_ring[(ft_state.closed_tail[consumer] + n) % CLOSED_RING_SIZE];
  ft_state.closed_tail[consumer] = ft_state.closed_head;
  g_mutex_unlock (&ft_state.lock);
  return (gint) pending;
}

void
ft_udp_skip (void)
{
  g_mutex_lock (&ft_state.lock);
  ft_state.udp_tail = ft_state.udp_head;
  g_mutex_unlock (&ft_state.lock);
}

/* Copies the sockaddrs of successful UDP connect()s since the last drain into out
   (UDP_RING_SIZE slots), oldest first; on overrun only the newest UDP_RING_SIZE. */
gint
ft_drain_udp_peers (guint8 * out)
{
  guint pending, n, i;

  g_mutex_lock (&ft_state.lock);
  pending = ft_state.udp_head - ft_state.udp_tail;
  if (pending > UDP_RING_SIZE)
    pending = UDP_RING_SIZE;
  for (n = 0; n != pending; n++)
  {
    const guint8 * slot = ft_state.udp_ring[(ft_state.udp_head - pending + n) % UDP_RING_SIZE];
    for (i = 0; i != SOCKADDR_SLOT; i++)
      out[n * SOCKADDR_SLOT + i] = slot[i];
  }
  ft_state.udp_tail = ft_state.udp_head;
  g_mutex_unlock (&ft_state.lock);
  return (gint) pending;
}
`;

function buildCSource(): string {
    const defines: Array<[string, number]> = [
        ["FT_SOL_SOCKET", SOL_SOCKET], ["FT_SO_TYPE", SO_TYPE], ["FT_ENOTSOCK", ENOTSOCK], ["FT_EBADF", EBADF],
        ["FT_SOCK_STREAM", SOCK_STREAM], ["FT_SOCK_DGRAM", SOCK_DGRAM],
        ["MAX_SCOPE_DEPTH", MAX_SCOPE_DEPTH], ["CLOSED_CONSUMERS", CLOSED_FD_CONSUMERS],
        ["CLOSED_RING_SIZE", CLOSED_FD_RING_SIZE], ["UDP_RING_SIZE", UDP_PEER_RING_SIZE],
        ["SOCKADDR_SLOT", SOCKADDR_SLOT_SIZE], ["FD_CACHE_SIZE", FD_CACHE_SIZE],
        ["THREAD_SLOTS", THREAD_TABLE_SLOTS],
    ];
    return defines.map(([name, value]) => `#define ${name} ${value}`).join("\n") + C_SOURCE;
}

/** Upper bound for sizeof(FtState) on 32/64-bit targets; checked against ft_state_size(). */
const STATE_BYTES =
    256 +                                                    // cursors, GMutex, function pointers
    CLOSED_FD_RING_SIZE * 4 +
    UDP_PEER_RING_SIZE * SOCKADDR_SLOT_SIZE +
    FD_CACHE_SIZE * 3 +                                      // fd_kind + fd_gen
    THREAD_TABLE_SLOTS * (8 + 4 + 4 + 4) +                   // tids, last_fd, last_gen, depth
    THREAD_TABLE_SLOTS * MAX_SCOPE_DEPTH * 16 +              // scopes
    4096;                                                    // alignment slack

/** Byte offsets of the cursors JS reads without the lock (the head of FtState). */
const CLOSED_HEAD_OFFSET = 0;
const CLOSED_TAIL_OFFSET = 4;
const UDP_HEAD_OFFSET = CLOSED_TAIL_OFFSET + 4 * CLOSED_FD_CONSUMERS;
const UDP_TAIL_OFFSET = UDP_HEAD_OFFSET + 4;

type ListenerGroup = "close" | "socket" | "io";
type NativeCallbacks = { onEnter?: NativePointer; onLeave?: NativePointer };
type AttachedGroup = { listeners: InvocationListener[]; names: string[] };

const ERRNO_LOCATION_EXPORTS = ["__errno_location", "__errno", "__error"];

function findErrnoLocation(): NativePointer {
    for (const name of ERRNO_LOCATION_EXPORTS) {
        const address = Module.findGlobalExportByName(name);
        if (address !== null) return address;
    }
    return NULL;
}

export class NativeSocketObserver {
    private readonly attachedGroups = new Map<ListenerGroup, AttachedGroup>();
    private readonly closedFdBuffer = Memory.alloc(CLOSED_FD_RING_SIZE * 4);
    private readonly udpPeerBuffer = Memory.alloc(UDP_PEER_RING_SIZE * SOCKADDR_SLOT_SIZE);
    private readonly scopePush: NativeFunction<void, [number, NativePointer]>;
    private readonly scopePop: NativeFunction<number, [number, NativePointer]>;
    private readonly recoverFd: NativeFunction<number, [number]>;
    private readonly closedSkip: NativeFunction<void, [number]>;
    private readonly drainClosed: NativeFunction<number, [number, NativePointer]>;
    private readonly udpSkip: NativeFunction<void, []>;
    private readonly drainUdp: NativeFunction<number, [NativePointer]>;

    /** Kept alive for the process lifetime: the listeners point into this module and its state. */
    constructor(private readonly cm: CModule, private readonly state: NativePointer) {
        const exclusive: NativeFunctionOptions = { scheduling: "exclusive" };
        this.scopePush = new NativeFunction(cm.ft_scope_push, "void", ["size_t", "pointer"], exclusive);
        this.scopePop = new NativeFunction(cm.ft_scope_pop, "int", ["size_t", "pointer"], exclusive);
        this.recoverFd = new NativeFunction(cm.ft_recover, "int", ["size_t"], exclusive);
        this.closedSkip = new NativeFunction(cm.ft_closed_skip, "void", ["uint"], exclusive);
        this.drainClosed = new NativeFunction(cm.ft_drain_closed, "int", ["uint", "pointer"], exclusive);
        this.udpSkip = new NativeFunction(cm.ft_udp_skip, "void", [], exclusive);
        this.drainUdp = new NativeFunction(cm.ft_drain_udp_peers, "int", ["pointer"], exclusive);
    }

    /** libc functions with a native listener attached (for the debug log). */
    get hookedFunctions(): string[] {
        return [...this.attachedGroups.values()].flatMap(group => group.names);
    }

    /** close()/dup2() reporting for `consumer`, from now on. */
    armClosedFdConsumer(consumer: ClosedFdConsumer): boolean {
        if (!this.attachGroups(["close"])) return false;
        this.closedSkip(consumer);
        return true;
    }

    /** Thread/SSL-scope -> stream fd tracking plus the tracker's closed-fd reporting. */
    armSocketFdTracking(): boolean {
        return this.attachGroups(["close", "socket", "io"]) &&
               this.armClosedFdConsumer(CLOSED_FD_CONSUMER.socketFdTracker);
    }

    /** Recording of successful UDP connect() peers, from now on. */
    armUdpPeerRecording(): boolean {
        if (!this.attachGroups(["close", "socket"])) return false;
        this.udpSkip();
        return true;
    }

    enterScope(tid: number, ssl: NativePointer): void {
        this.scopePush(tid, ssl);
    }

    leaveScope(tid: number, ssl: NativePointer): number {
        return this.scopePop(tid, ssl);
    }

    recover(tid: number): number {
        return this.recoverFd(tid);
    }

    drainClosedFds(consumer: ClosedFdConsumer): ClosedFdDrain {
        const tail = this.state.add(CLOSED_TAIL_OFFSET + 4 * consumer).readU32();
        if (tail === this.state.add(CLOSED_HEAD_OFFSET).readU32()) return [];
        const count = this.drainClosed(consumer, this.closedFdBuffer);
        if (count < 0) return "lost";
        if (count === 0) return [];
        return Array.from(new Int32Array(this.closedFdBuffer.readByteArray(count * 4)!));
    }

    /** sockaddrs of the UDP connect()s since the last drain, oldest first; valid until the next drain. */
    drainUdpPeers(): NativePointer[] {
        if (this.state.add(UDP_TAIL_OFFSET).readU32() === this.state.add(UDP_HEAD_OFFSET).readU32()) return [];
        const count = this.drainUdp(this.udpPeerBuffer);
        const peers: NativePointer[] = [];
        for (let i = 0; i < count; i++) peers.push(this.udpPeerBuffer.add(i * SOCKADDR_SLOT_SIZE));
        return peers;
    }

    /** All or nothing: on failure, detaches the groups this call attached (not ones armed before). */
    private attachGroups(groups: ListenerGroup[]): boolean {
        const attachedNow: ListenerGroup[] = [];
        for (const group of groups) {
            if (this.attachedGroups.has(group)) continue;
            try {
                this.attachedGroups.set(group, attachAll(listenerPlan(this.cm, group)));
                attachedNow.push(group);
            } catch (e) {
                warnJsFallback(`attaching the ${group} listeners failed: ${e}`);
                for (const done of attachedNow) this.detachGroup(done);
                return false;
            }
        }
        return true;
    }

    private detachGroup(group: ListenerGroup): void {
        for (const listener of this.attachedGroups.get(group)?.listeners ?? []) listener.detach();
        this.attachedGroups.delete(group);
    }
}

function listenerPlan(cm: CModule, group: ListenerGroup): Array<[string, NativeCallbacks]> {
    switch (group) {
        case "close":
            return [
                [fdCloseFunction(), { onEnter: cm.ft_close_on_enter }],
                ["dup2", { onEnter: cm.ft_dup_on_enter, onLeave: cm.ft_dup_on_leave }],
                ["dup3", { onEnter: cm.ft_dup_on_enter, onLeave: cm.ft_dup_on_leave }],
            ];
        case "socket":
            return [
                ["socket", { onEnter: cm.ft_socket_on_enter, onLeave: cm.ft_socket_on_leave }],
                ["connect", { onEnter: cm.ft_connect_on_enter, onLeave: cm.ft_connect_on_leave }],
            ];
        case "io":
            return SOCKET_IO_FUNCTIONS.map((name): [string, NativeCallbacks] => [name, { onEnter: cm.ft_io_on_enter }]);
    }
}

/** Attaches every exported target; on failure detaches what it attached and rethrows. */
function attachAll(plan: Array<[string, NativeCallbacks]>): AttachedGroup {
    const attached: AttachedGroup = { listeners: [], names: [] };
    try {
        for (const [name, callbacks] of plan) {
            const address = Module.findGlobalExportByName(name);
            if (address === null) continue;
            attached.listeners.push(Interceptor.attach(address, callbacks as any));
            attached.names.push(name);
        }
    } catch (e) {
        for (const listener of attached.listeners) listener.detach();
        throw e;
    }
    return attached;
}

function createObserver(): NativeSocketObserver {
    if (typeof CModule === "undefined") throw new Error("CModule is not available in this runtime");
    const state = Memory.alloc(STATE_BYTES);
    const cm = new CModule(buildCSource(), { ft_state: state });
    const exclusive: NativeFunctionOptions = { scheduling: "exclusive" };
    const stateSize = Number(new NativeFunction(cm.ft_state_size, "size_t", [], exclusive)());
    if (stateSize > STATE_BYTES) throw new Error(`native state needs ${stateSize} bytes, only ${STATE_BYTES} reserved`);
    new NativeFunction(cm.ft_init, "void", ["pointer", "pointer"], exclusive)(
        Module.findGlobalExportByName("getsockopt") ?? NULL, findErrnoLocation());
    return new NativeSocketObserver(cm, state);
}

let _observer: NativeSocketObserver | null | undefined;
let _fallbackWarned = false;

function warnJsFallback(reason: string): void {
    devlog(`[native-socket-observer] ${reason}`);
    if (_fallbackWarned) return;
    _fallbackWarned = true;
    log("[!] friTap: Frida CModule is unavailable in this process; falling back to JavaScript libc " +
        "hooks for socket tracking. With Java hooks active (--attribute-sdk) these can occasionally " +
        "freeze the app; if it hangs, rerun without --attribute-sdk.");
}

/** The shared observer, compiled on first use; null when CModule is unusable (use JS listeners). */
export function nativeSocketObserver(): NativeSocketObserver | null {
    if (_observer === undefined) {
        try {
            _observer = createObserver();
        } catch (e) {
            _observer = null;
            warnJsFallback(`CModule unusable: ${e instanceof Error ? e.message : String(e)}`);
        }
    }
    return _observer;
}

/** Test-only: forget the compiled observer and the fallback warning. */
export function resetNativeSocketObserverForTests(): void {
    _observer = undefined;
    _fallbackWarned = false;
}
