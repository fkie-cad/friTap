#include <assert.h>
#include <limits.h>
#include <stddef.h>

#define PERF_QUEUE_CAPACITY 4
#include "perf_order.h"

static unsigned char delivered[4];
static size_t count;

static int collect(const struct tls_event *event)
{
    assert(count < sizeof(delivered));
    delivered[count++] = event->payload[0];
    return 0;
}

static void sample(struct perf_queue *queue, unsigned long long time,
                   unsigned int thread, unsigned int chunk, unsigned char value)
{
    struct tls_event record = {
        .header = { .timestamp = time, .thread = thread, .chunk = chunk, .length = 1 },
        .payload = { value },
    };
    /* Perf sample data may start at an unaligned address. */
    unsigned char raw[offsetof(struct tls_event, payload) + 8];
    memcpy(raw + 1, &record, sizeof(raw) - 1);
    assert(queue_sample(queue, raw + 1, sizeof(raw) - 1) == 0);
}

int main(void)
{
    assert(select_transport(0) == TRANSPORT_RING);
    assert(select_transport(EINVAL) == TRANSPORT_PERF);
    assert(select_transport(EOPNOTSUPP) == TRANSPORT_PERF);
    assert(select_transport(ENOSYS) == TRANSPORT_PERF);
    assert(select_transport(EPERM) == -EPERM);
    assert(select_transport(EACCES) == -EACCES);
    assert(select_transport(ENOMEM) == -ENOMEM);

    struct perf_queue queue = {0};
    /* A poll can drain one CPU's complete buffer before another's. */
    sample(&queue, 20, 2, 0, 'd');
    sample(&queue, 10, 1, 1, 'b');
    sample(&queue, 10, 2, 0, 'c');
    sample(&queue, 10, 1, 0, 'a');
    sample(&queue, 30, 1, 0, 'x');
    assert(queue.lost == 1);
    assert(queue_flush(&queue, 10, collect) == 0);
    assert(count == 3 && queue.count == 1);
    sample(&queue, 10, 1, 0, 'x');
    assert(queue.lost == 2);
    assert(queue_flush(&queue, ULLONG_MAX, collect) == 0);
    assert(count == 4 && !memcmp(delivered, "abcd", count));

    struct cpu_state cpu = { .lost = 3, .perf_overflow = 10 };
    assert(transport_loss(&cpu, 0) == 13);
    assert(transport_loss(&cpu, 7) == 13);
    assert(transport_loss(&cpu, 10) == 13);
    assert(transport_loss(&cpu, 12) == 15);
    struct cpu_state other = { .perf_overflow = 5 };
    assert(transport_loss(&cpu, 12) + transport_loss(&other, 0) == 20);
    return 0;
}
