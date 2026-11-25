#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct fixture {
    int port;
    int count;
    int pause_after;
    int extended;
    int worker;
    int connections;
    int result;
};

static int gate(const char *label)
{
    puts(label);
    fflush(stdout);
    return getchar() == '\n';
}

static int transfer(struct fixture *fixture, SSL *ssl)
{
    const char request[] = "owned fixture request\n";
    const char expected[] = "owned fixture response\n";
    static unsigned char large[40000];
    memset(large, 'x', sizeof(large));
    const void *data = fixture->extended ? (const void *)large : request;
    size_t len = fixture->extended ? sizeof(large) : sizeof(request) - 1;
    if (fixture->extended == 2)
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    if (fixture->extended) {
        char unused[32];
        size_t received = 99;
        int fd = SSL_get_fd(ssl);
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK))
            return 8;
        int retry = SSL_read_ex(ssl, unused, sizeof(unused), &received);
        int error = SSL_get_error(ssl, retry);
        if (fcntl(fd, F_SETFL, flags) || retry || error != SSL_ERROR_WANT_READ)
            return 8;
    }
    for (int i = 0; i < fixture->count; i++) {
        size_t sent = 0, received = 0;
        char response[128];
        if (fixture->extended) {
            while (sent < len) {
                size_t chunk = 0;
                if (!SSL_write_ex(ssl, (const char *)data + sent, len - sent, &chunk) || !chunk)
                    return 4;
                if (!sent && fixture->extended == 2 && chunk >= len)
                    return 9;
                sent += chunk;
            }
            if (!SSL_read_ex(ssl, response, sizeof(response), &received))
                return 4;
        } else {
            int written = SSL_write(ssl, data, len);
            int read = written > 0 ? SSL_read(ssl, response, sizeof(response)) : -1;
            if (written <= 0 || read <= 0)
                return 4;
            sent = written;
            received = read;
        }
        if (sent != len || received != sizeof(expected) - 1 ||
            memcmp(response, expected, received))
            return 5;
    }
    return 0;
}

struct worker_call {
    struct fixture *fixture;
    SSL *ssl;
};

static void *transfer_on_worker(void *arg)
{
    struct worker_call *call = arg;
    call->fixture->result = transfer(call->fixture, call->ssl);
    return NULL;
}

static int exchange(struct fixture *fixture, SSL_CTX *ctx, int number)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(fixture->port),
        .sin_addr = { htonl(INADDR_LOOPBACK) },
    };
    SSL *ssl = SSL_new(ctx);
    if (fd < 0 || !ssl || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        !SSL_set_fd(ssl, fd) || SSL_connect(ssl) != 1)
        return 2;
    if (!number && !gate("paused"))
        return 3;

    int result = 0;
    if (fixture->worker == 2) {
        struct worker_call call = { fixture, ssl };
        pthread_t thread;
        if (pthread_create(&thread, NULL, transfer_on_worker, &call) ||
            pthread_join(thread, NULL))
            return 7;
        result = fixture->result;
    } else {
        result = transfer(fixture, ssl);
    }
    if (fixture->pause_after && !gate("exchanged"))
        return 6;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return result;
}

static void *run(void *arg)
{
    struct fixture *fixture = arg;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    fixture->result = ctx ? 0 : 2;
    for (int i = 0; !fixture->result && i < fixture->connections; i++)
        fixture->result = exchange(fixture, ctx, i);
    SSL_CTX_free(ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 7)
        return 1;
    struct fixture fixture = {
        .port = atoi(argv[1]), .count = atoi(argv[2]),
        .pause_after = atoi(argv[3]), .extended = atoi(argv[4]),
        .worker = atoi(argv[5]), .connections = atoi(argv[6]),
    };
    if (fixture.worker == 1) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, run, &fixture) || pthread_join(thread, NULL))
            return 7;
    } else {
        run(&fixture);
    }
    return fixture.result;
}
