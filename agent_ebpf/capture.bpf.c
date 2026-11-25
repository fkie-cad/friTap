#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include "events.h"
#include "registers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct capture_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct cpu_state);
} state SEC(".maps");

static __always_inline struct cpu_state *local_state(void)
{
    unsigned int key = 0;
    return bpf_map_lookup_elem(&state, &key);
}

static __always_inline void record_loss(void)
{
    struct cpu_state *cpu = local_state();
    if (cpu)
        cpu->lost++;
}

struct call {
    unsigned long long ssl;
    const void *buffer;
    const unsigned long *result_size;
    unsigned int depth;
    unsigned int reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned long long);
    __type(value, struct call);
} reads SEC(".maps"), writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned long long);
    __type(value, unsigned long long);
} connections SEC(".maps");

#ifdef FRITAP_PERF
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct tls_event);
} scratch SEC(".maps");
#else
#ifndef BUFFER_SIZE
#define BUFFER_SIZE (4 * 1024 * 1024)
#endif
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BUFFER_SIZE);
} events SEC(".maps");
#endif

static __always_inline int read_user(void *destination, unsigned int size, const void *source)
{
#ifdef FRITAP_PERF
    unsigned long address = (unsigned long)source;
#if defined(__TARGET_ARCH_arm64)
    /* Strip the architectural top-byte tag on user pointers. */
    address &= (1ULL << 56) - 1;
#endif
    /* The legacy helper can also read kernel addresses. Limit it to the
     * lower address range even when the target supplies the pointer. */
    const unsigned long user_limit = 1ULL << 56;
    if (!address || address >= user_limit || size > user_limit - address)
        return -EFAULT;
    source = (const void *)address;
#endif
    /* libbpf rewrites this call to the legacy helper on kernels that
     * predate the separate userspace read helper, including stock 5.4. */
    return bpf_probe_read_user(destination, size, source);
}

static __always_inline int scoped(unsigned long long thread)
{
    unsigned int key = 0;
    struct capture_config *settings = bpf_map_lookup_elem(&config, &key);
    return settings && settings->enabled && thread >> 32 == settings->pid;
}

static __always_inline int enter(void *map, void *ssl, const void *buffer,
                                 const unsigned long *result_size)
{
    unsigned long long thread = bpf_get_current_pid_tgid();
    if (!scoped(thread))
        return 0;
    struct call *active = bpf_map_lookup_elem(map, &thread);
    if (active) {
        active->depth++;
        return 0;
    }
    struct call call = {
        .ssl = (unsigned long long)ssl, .buffer = buffer,
        .result_size = result_size, .depth = 1,
    };
    if (bpf_map_update_elem(map, &thread, &call, BPF_NOEXIST))
        record_loss();
    return 0;
}

static __always_inline unsigned long long connection_id(unsigned long long ssl)
{
    unsigned long long *id = bpf_map_lookup_elem(&connections, &ssl);
    if (id)
        return *id;
    struct cpu_state *cpu = local_state();
    if (!cpu)
        return 0;
    /* Each CPU owns its counter. Probes run with migration disabled. */
    unsigned long long candidate = (++cpu->next_connection << 32) | bpf_get_smp_processor_id();
    bpf_map_update_elem(&connections, &ssl, &candidate, BPF_NOEXIST);
    id = bpf_map_lookup_elem(&connections, &ssl);
    return id ? *id : 0;
}

static __always_inline int send_chunk(struct pt_regs *ctx, const struct tls_event_header *header,
                                     const void *buffer, unsigned long long size)
{
    /* Keep the bound on the register passed to the verifier-checked helper. */
    asm volatile("" : "+r"(size));
    if (!size || size > MAX_PAYLOAD)
        return -EINVAL;
#ifdef FRITAP_PERF
    unsigned int key = 0;
    struct tls_event *event = bpf_map_lookup_elem(&scratch, &key);
#else
    struct tls_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
#endif
    if (!event)
        return -ENOMEM;
    event->header = *header;
    event->header.length = size;
    if (read_user(event->payload, size, buffer)) {
#ifndef FRITAP_PERF
        bpf_ringbuf_discard(event, 0);
#endif
        return -EFAULT;
    }
#ifdef FRITAP_PERF
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                                 __builtin_offsetof(struct tls_event, payload) + size);
#else
    bpf_ringbuf_submit(event, 0);
    return 0;
#endif
}

static __always_inline int leave(struct pt_regs *ctx, void *map, unsigned int write,
                                unsigned int extended)
{
    int result = RESULT(ctx);
    unsigned long long thread = bpf_get_current_pid_tgid();
    if (!scoped(thread))
        return 0;
    struct call *entry = bpf_map_lookup_elem(map, &thread);
    if (!entry)
        return 0;
    if (entry->depth > 1) {
        entry->depth--;
        return 0;
    }
    struct call call = *entry;
    bpf_map_delete_elem(map, &thread);
    if (result <= 0)
        return 0;
    unsigned long size = (unsigned int)result;
    if (extended && read_user(&size, sizeof(size), call.result_size))
        goto dropped;
    if (!size)
        return 0;
    unsigned long long id = connection_id(call.ssl);
    if (!id)
        goto dropped;
    struct tls_event_header header = {
        .timestamp = bpf_ktime_get_ns(), .thread = thread, .connection = id,
        .write = write, .extended = extended,
    };
    for (unsigned int chunk = 0; chunk < MAX_CHUNKS && size; chunk++) {
        unsigned long part = size > MAX_PAYLOAD ? MAX_PAYLOAD : size;
        header.chunk = chunk;
        int error = send_chunk(ctx, &header, call.buffer + chunk * MAX_PAYLOAD, part);
#ifdef FRITAP_PERF
        if (error == -ENOSPC) {
            struct cpu_state *cpu = local_state();
            if (cpu)
                cpu->perf_overflow++;
            return 0;
        }
#endif
        if (error)
            goto dropped;
        size -= part;
    }
    if (!size)
        return 0;
dropped:
    record_loss();
    return 0;
}

SEC("uprobe") int read_enter(struct pt_regs *ctx)
{
    return enter(&reads, (void *)ARG1(ctx), (void *)ARG2(ctx), 0);
}

SEC("uretprobe") int read_leave(struct pt_regs *ctx)
{
    return leave(ctx, &reads, 0, 0);
}

SEC("uprobe") int write_enter(struct pt_regs *ctx)
{
    return enter(&writes, (void *)ARG1(ctx), (void *)ARG2(ctx), 0);
}

SEC("uretprobe") int write_leave(struct pt_regs *ctx)
{
    return leave(ctx, &writes, 1, 0);
}

SEC("uprobe") int read_ex_enter(struct pt_regs *ctx)
{
    return enter(&reads, (void *)ARG1(ctx), (void *)ARG2(ctx), (void *)ARG4(ctx));
}

SEC("uretprobe") int read_ex_leave(struct pt_regs *ctx)
{
    return leave(ctx, &reads, 0, 1);
}

SEC("uprobe") int write_ex_enter(struct pt_regs *ctx)
{
    return enter(&writes, (void *)ARG1(ctx), (void *)ARG2(ctx), (void *)ARG4(ctx));
}

SEC("uretprobe") int write_ex_leave(struct pt_regs *ctx)
{
    return leave(ctx, &writes, 1, 1);
}

SEC("uprobe") int free_ssl(struct pt_regs *ctx)
{
    if (scoped(bpf_get_current_pid_tgid())) {
        unsigned long long key = ARG1(ctx);
        bpf_map_delete_elem(&connections, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
