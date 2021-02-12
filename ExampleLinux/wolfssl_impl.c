#include <wolfssl/ssl.h>

#include "common.h"
#include "sslinterface.h"

// Most of this is taken from https://www.wolfssl.com/docs/wolfssl-manual/ch11/

WOLFSSL_CTX* ctx;

static WOLFSSL_CTX* create_context() {
    WOLFSSL_CTX* ctx;
    /* Create the WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");

        exit(EXIT_FAILURE);
    }
    return ctx;
}

static void configure_context(WOLFSSL_CTX* ctx, char* current_path) {
    /* Load server certificates into WOLFSSL_CTX */

    char cert_path[BUF_SIZE];
    snprintf(cert_path, BUF_SIZE, "%s/%s", current_path, "cert.pem");
    if (wolfSSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", cert_path);
        exit(EXIT_FAILURE);
    }
    /* Load keys */
    char key_path[BUF_SIZE];
    snprintf(key_path, BUF_SIZE, "%s/%s", current_path, "key.pem");
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", cert_path);
        exit(EXIT_FAILURE);
    }
    return;
}
void ssl_init(char* current_path) {
    wolfSSL_Init(); /* Initialize wolfSSL */
    ctx = create_context();
    configure_context(ctx, current_path);
}

void ssl_cleanup(void) {
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}

void echo_connection(int client_fd) {
    /*Create WOLFSSL object */

    WOLFSSL* ssl;

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }

    wolfSSL_set_fd(ssl, client_fd);
    char buf[BUF_SIZE];
    memset(buf, 0x0, BUF_SIZE);
    while (wolfSSL_read(ssl, buf, BUF_SIZE) > 0) {
        printf("[*] Inbound: %s", buf);
        wolfSSL_write(ssl, buf, BUF_SIZE);
        memset(buf, 0x0, BUF_SIZE);
    }
    wolfSSL_free(ssl);
}