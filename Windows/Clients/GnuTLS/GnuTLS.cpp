#include "GnuTLS.h"



void GNUTLS_init() {
	gnutls_global_init();
}

void GNUTLS_cleanup() {
	gnutls_global_deinit();
}

int tcp_connect(const char* hostname, int port){
    struct sockaddr_in addr;
    int sd = socket(AF_INET, SOCK_STREAM, 6);
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);

    int err = connect(sd, (struct sockaddr*)&addr, sizeof(addr));
    if (err < 0) {
        fprintf(stderr, "Connect error\n");
        exit(1);
    }

    return sd;
}

void GNUTLS_setup_and_connect(GNUTLS_Connection* connection, const char* hostname, int port) {
    const char* errptr = NULL;
	gnutls_session_t session;
    WSADATA wsa;
    int result;
    gnutls_certificate_credentials_t xcred;

    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_certificate_set_x509_system_trust(xcred);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
    }

    

    result = gnutls_init(&session, GNUTLS_CLIENT);
    printf("GNUTLS_INIT: %d\n", result);

    result = gnutls_set_default_priority(session);
    printf("GNUTLS_PRIORITY_DEFAULT: %d\n", result);

    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    connection->socket = tcp_connect(hostname, port);
   
    gnutls_transport_set_int(session, connection->socket);
    gnutls_handshake_set_timeout(session,
        GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    gnutls_handshake(session);
    gnutls_record_send(session, "Ya yeet!", strlen("Ya yeet!"));
}

int main() {

    GNUTLS_Connection* connection = (GNUTLS_Connection*)malloc(sizeof(GNUTLS_Connection));

    GNUTLS_init();
    GNUTLS_setup_and_connect(connection, HOSTNAME, 443);
    GNUTLS_cleanup();

}