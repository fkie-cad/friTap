#include <openssl/err.h>
#include <openssl/ssl.h>

#include "common.h"
#include "sslinterface.h"

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

static void configure_context(SSL_CTX *ctx, char *current_path) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    char cert_path[BUF_SIZE];
    snprintf(cert_path, BUF_SIZE, "%s/%s", current_path, "cert.pem");
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    char key_path[BUF_SIZE];
    snprintf(key_path, BUF_SIZE, "%s/%s", current_path, "key.pem");
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void ssl_init(char *current_path) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_context();
    configure_context(ctx, current_path);
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