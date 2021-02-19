#include <assert.h>
#include <gnutls/gnutls.h>

#include "common.h"
#include "sslinterface.h"

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd) \
    do {                      \
        rval = cmd;           \
    } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

//Most of this is taken from https://www.gnutls.org/manual/html_node/Echo-server-with-X_002e509-authentication.html

static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;

static void logfunc(int loglevel, const char* msg) {
    printf("%s", msg);
}

void ssl_init(char* current_path) {
    CHECK(gnutls_global_init());
    CHECK(gnutls_certificate_allocate_credentials(&x509_cred));

    char cert_path[BUF_SIZE];
    snprintf(cert_path, BUF_SIZE, "%s/%s", current_path, "cert.pem");
    char key_path[BUF_SIZE];
    snprintf(key_path, BUF_SIZE, "%s/%s", current_path, "key.pem");
    CHECK(gnutls_certificate_set_x509_key_file(x509_cred, cert_path,
                                               key_path,
                                               GNUTLS_X509_FMT_PEM));

    CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));
}
void ssl_cleanup(void) {
    gnutls_certificate_free_credentials(x509_cred);
    gnutls_priority_deinit(priority_cache);

    gnutls_global_deinit();
}

//Read for incoming messages and echo them back
void echo_connection(int client_fd) {
    gnutls_session_t session;
    int ret;
    char buffer[BUF_SIZE + 1];
    CHECK(gnutls_init(&session, GNUTLS_SERVER));
    CHECK(gnutls_priority_set(session, priority_cache));
    CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));
    gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    gnutls_transport_set_int(session, client_fd);
    LOOP_CHECK(ret, gnutls_handshake(session));
    if (ret < 0) {
        gnutls_deinit(session);
        fprintf(stderr, "[*] Handshake has failed (%s)\n\n", gnutls_strerror(ret));
        return;
    }
    printf("[*] Handshake was completed\n");
    for (;;) {
        LOOP_CHECK(ret, gnutls_record_recv(session, buffer, BUF_SIZE));

        if (ret == 0) {
            printf("\n- Peer has closed the GnuTLS connection\n");
            break;
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
            fprintf(stderr, "*** Warning: %s\n",
                    gnutls_strerror(ret));
        } else if (ret < 0) {
            fprintf(stderr,
                    "\n*** Received corrupted "
                    "data(%d). Closing the connection.\n\n",
                    ret);
            break;
        } else if (ret > 0) {
            /* echo data back to the client
                                 */
            printf("[*] Inbound: %s", buffer);
            CHECK(gnutls_record_send(session, buffer, ret));
        }
    }
    printf("\n");
    /* do not wait for the peer to close the connection.
                 */
    LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));

    gnutls_deinit(session);
}