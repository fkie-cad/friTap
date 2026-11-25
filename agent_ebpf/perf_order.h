#ifndef FRITAP_EBPF_PERF_ORDER_H
#define FRITAP_EBPF_PERF_ORDER_H

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "events.h"

#ifndef PERF_QUEUE_CAPACITY
#define PERF_QUEUE_CAPACITY 4096
#endif
#define PERF_REORDER_NS 100000000ULL

struct perf_queue {
    struct tls_event *heap[PERF_QUEUE_CAPACITY];
    size_t count;
    struct tls_event_header last;
    unsigned long long lost;
};

static int earlier(const struct tls_event_header *a, const struct tls_event_header *b)
{
    if (a->timestamp != b->timestamp)
        return a->timestamp < b->timestamp;
    if (a->thread != b->thread)
        return a->thread < b->thread;
    return a->chunk < b->chunk;
}

static int queue_sample(struct perf_queue *queue, const void *data, size_t size)
{
    struct tls_event_header header;
    const size_t prefix = offsetof(struct tls_event, payload);
    if (size < prefix)
        return -EPROTO;
    memcpy(&header, data, sizeof(header));
    const size_t used = prefix + header.length;
    /* PERF_SAMPLE_RAW can include trailing alignment bytes. */
    if (!header.length || header.length > MAX_PAYLOAD || size < used || size - used > 7)
        return -EPROTO;
    if (earlier(&header, &queue->last) || queue->count == PERF_QUEUE_CAPACITY) {
        queue->lost++;
        return 0;
    }

    struct tls_event *event = malloc(used);
    if (!event)
        return -ENOMEM;
    memcpy(event, data, used);
    size_t pos = queue->count++;
    while (pos && earlier(&header, &queue->heap[(pos - 1) / 2]->header)) {
        queue->heap[pos] = queue->heap[(pos - 1) / 2];
        pos = (pos - 1) / 2;
    }
    queue->heap[pos] = event;
    return 0;
}

static struct tls_event *queue_pop(struct perf_queue *queue)
{
    struct tls_event *first = queue->heap[0];
    struct tls_event *last = queue->heap[--queue->count];
    size_t pos = 0;
    while (2 * pos + 1 < queue->count) {
        size_t child = 2 * pos + 1;
        if (child + 1 < queue->count &&
            earlier(&queue->heap[child + 1]->header, &queue->heap[child]->header))
            child++;
        if (!earlier(&queue->heap[child]->header, &last->header))
            break;
        queue->heap[pos] = queue->heap[child];
        pos = child;
    }
    queue->heap[pos] = last;
    return first;
}

static int queue_flush(struct perf_queue *queue, unsigned long long cutoff,
                       int (*deliver)(const struct tls_event *))
{
    while (queue->count && queue->heap[0]->header.timestamp <= cutoff) {
        struct tls_event *event = queue_pop(queue);
        queue->last = event->header;
        int error = deliver(event);
        free(event);
        if (error)
            return error;
    }
    return 0;
}

static unsigned long long transport_loss(const struct cpu_state *cpu, unsigned long long notified)
{
    /* The same overflow can appear in both counters. A final overflow may
     * never receive a PERF_RECORD_LOST notification before detach. */
    return cpu->lost + (cpu->perf_overflow > notified ? cpu->perf_overflow : notified);
}

/* The probe has valid map parameters. Resource and permission errors remain
 * fatal and are reported at the probe stage. */
enum event_transport {
    TRANSPORT_RING,
    TRANSPORT_PERF,
};

static int select_transport(int probe_error)
{
    if (!probe_error)
        return TRANSPORT_RING;
    if (probe_error == EINVAL || probe_error == EOPNOTSUPP || probe_error == ENOSYS)
        return TRANSPORT_PERF;
    return -probe_error;
}

#endif
