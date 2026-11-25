#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 5)
        return 1;
    const int count = argc == 5 ? atoi(argv[3]) : 1;
    const int extended = argc == 5 ? atoi(argv[4]) : 0;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1)
        return 2;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = { htonl(INADDR_LOOPBACK) },
    };
    socklen_t addrlen = sizeof(addr);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, addrlen) ||
        listen(listener, 1) || getsockname(listener, (struct sockaddr *)&addr, &addrlen))
        return 3;
    printf("%u\n", ntohs(addr.sin_port));
    fflush(stdout);

    int client = accept(listener, NULL, NULL);
    SSL *ssl = SSL_new(ctx);
    if (client < 0 || !ssl || !SSL_set_fd(ssl, client) || SSL_accept(ssl) != 1)
        return 4;
    const char request[] = "owned fixture request\n";
    const char response[] = "owned fixture response\n";
    char received[40000];
    size_t length = extended ? sizeof(received) : sizeof(request) - 1;
    for (int i = 0; i < count; i++) {
        size_t offset = 0;
        while (offset < length) {
            int read = SSL_read(ssl, received + offset, length - offset);
            if (read <= 0)
                return 5;
            offset += read;
        }
        if (extended) {
            for (size_t byte = 0; byte < length; byte++)
                if (received[byte] != 'x')
                    return 6;
        } else if (memcmp(received, request, length)) {
            return 6;
        }
        if (SSL_write(ssl, response, sizeof(response) - 1) != (int)sizeof(response) - 1)
            return 6;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(client);
    close(listener);
    return 0;
}
