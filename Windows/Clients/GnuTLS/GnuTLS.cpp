#include "GnuTLS.h"

void GNUTLS_init() {
	gnutls_global_init();
}

void GNUTLS_cleanup(GNUTLS_Connection* connection) {
    
    gnutls_deinit(connection->session);
    gnutls_certificate_free_credentials(connection->xcred);
    gnutls_global_deinit();
    free(connection);
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
    WSADATA wsa;
    int result;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
    }

    gnutls_certificate_allocate_credentials(&connection->xcred);
    gnutls_certificate_set_x509_system_trust(connection->xcred);

    result = gnutls_init(&connection->session, GNUTLS_CLIENT);

    result = gnutls_set_default_priority(connection->session);

    gnutls_credentials_set(connection->session, GNUTLS_CRD_CERTIFICATE, connection->xcred);

    connection->socket = tcp_connect(hostname, port);
   
    gnutls_transport_set_int(connection->session, connection->socket);
    gnutls_handshake_set_timeout(connection->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    gnutls_handshake(connection->session);
    
}

char* GNUTLS_get_response(GNUTLS_Connection* connection) {

    unsigned long responseBufferSize = 0;
    char* responseBuffer = (char*)malloc(1);
    if (responseBuffer == NULL) printf("Allocating space for responseBuffer failed!");
    responseBuffer[0] = '\0';

    while (1) {
        //Neuen temporären Buffer erstellen
        char* tempBuffer = (char*)malloc(TMP_BUFFER_SIZE);
        if (tempBuffer == NULL) printf("Couldnt allocate memory for tempBuffer...");

        int readBytesCount = gnutls_record_recv(connection->session, tempBuffer, TMP_BUFFER_SIZE);


        if (readBytesCount <= 0) {
            //Wenn keine Daten gelesen wurden, dann hänge hinten ein nullterm-Char dran und gebe reponseBuffer-Pointer zurück
            char* returnBuffer = (char*)realloc(responseBuffer, responseBufferSize + 1);
            if (returnBuffer == NULL) printf("Couldnt realloc memory for returnBuffer...");
            returnBuffer[responseBufferSize] = '\0';
            return returnBuffer;
        }

        //Wenn neue Daten gelesen wurden, dann erweitere ResponseBuffer und schreibe neue Daten hinein
        char* tempResponseBuffer = (char*)realloc(responseBuffer, responseBufferSize + readBytesCount);
        if (tempResponseBuffer == NULL) printf("Couldnt realloc memory for tempResponseBuffer...");
        responseBuffer = tempResponseBuffer;
        memcpy(responseBuffer + responseBufferSize, tempBuffer, readBytesCount);
        responseBufferSize += readBytesCount;
        free(tempBuffer);

    }
}

void GNUTLS_run() {
    printf("GnuTLS %s\n-------------------\n", GNUTLS_VERSION);
    GNUTLS_init();

    GNUTLS_Connection* connection = (GNUTLS_Connection*)malloc(sizeof(GNUTLS_Connection));
    while (1) {
        GNUTLS_setup_and_connect(connection, HOSTNAME, 443);
        int sendBytes = gnutls_record_send(connection->session, MSG, strlen(MSG));
        char* response = GNUTLS_get_response(connection);
        printf("%s\n", response);
        Sleep(3000);
    }

    GNUTLS_cleanup(connection);
}

int main() {

    GNUTLS_run();

   

}