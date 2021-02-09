#include <openssl/err.h>
#include <openssl/ssl.h>

#include "common.h"
#include "sslinterface.h"

#define BUF_SIZE 512

SSL_CTX *ctx;

static SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void ssl_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_context();
    configure_context(ctx);
}
void ssl_cleanup(void) {
    EVP_cleanup();
}
//Read for incoming messages and echo them back
void echo_connection(int client_fd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    char buf[BUF_SIZE];
    memset(buf, 0x0, BUF_SIZE);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    while (SSL_read(ssl, buf, BUF_SIZE) > 0) {
        printf("[*] Inbound: %s", buf);
        SSL_write(ssl, buf, BUF_SIZE);
        memset(buf, 0x0, BUF_SIZE);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return;
}