// NSS.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "NSS.h"


int main(){
    NSS_run();
}

SECStatus nss_auth_cert_hook(void* arg, PRFileDesc* fd, PRBool checksig,
    PRBool isServer)
{
    /* Bypass */
    return SECSuccess;
}

int tcp_connect(const char* hostname, int port) {
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

void NSS_setup_and_connect(NSS_Connection* connection, const char* hostname, int port) {
    int socket = tcp_connect(hostname, port);
    if (!(connection->tcpSocket = PR_ImportTCPSocket(socket)))
        printf("Unable to convert socket:\n%s", SECU_ErrorString(PR_GetError()));
    if (!(connection->sslSocket = SSL_ImportFD(NULL, connection->tcpSocket)))
        printf("unable to enable SSL socket:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_OptionSet(connection->sslSocket, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE)) != SECSuccess)
        printf("Unable to setup handshake mode:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_OptionSet(connection->sslSocket, SSL_ENABLE_FDX, PR_TRUE)) != SECSuccess)
        printf("Unable to setup full duplex mode:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_SetURL(connection->sslSocket, hostname)) != SECSuccess)
        printf("Unable to register target host:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_AuthCertificateHook(connection->sslSocket, nss_auth_cert_hook, NULL)) != SECSuccess)
        printf("Unable to register certificate check hook:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_ResetHandshake(connection->sslSocket, PR_FALSE)) != SECSuccess)
        printf("Unable to renegotiation TLS (1/2):\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_ForceHandshake(connection->sslSocket)) != SECSuccess)
        printf("Unable to renegotiation TLS (2/2):\n%s", SECU_ErrorString(PR_GetError()));

}

char* NSS_get_response(NSS_Connection* connection) {

    unsigned long responseBufferSize = 0;
    char* responseBuffer = (char*)malloc(1);
    if (responseBuffer == NULL) printf("Allocating space for responseBuffer failed!");
    responseBuffer[0] = '\0';

    while (1) {
        //Neuen temporären Buffer erstellen
        char* tempBuffer = (char*)malloc(TMP_BUFFER_SIZE);
        if (tempBuffer == NULL) printf("Couldnt allocate memory for tempBuffer...");

        int readBytesCount = PR_Read(connection->sslSocket, tempBuffer, TMP_BUFFER_SIZE);


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

void NSS_init() {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
    }
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
    if (NSS_NoDB_Init(NULL) != SECSuccess)
        printf("Unable to initialize NSS:\n%s", SECU_ErrorString(PR_GetError()));
}

void NSS_run() {
    printf("NSS %s\n-------------------\n", NSS_Version);
    NSS_init();
    NSS_Connection* connection = (NSS_Connection*)malloc(sizeof(NSS_Connection));
    while (1) {

        NSS_setup_and_connect(connection, HOSTNAME, PORT);
        if ((err = PR_Write(connection->sslSocket, SEND_MSG, strlen(SEND_MSG))) != strlen(SEND_MSG))
            printf("SSL write request failed:\n%s", SECU_ErrorString(PR_GetError()));
        char* response = NSS_get_response(connection);
        printf("%s\n", response);
        SSL_ClearSessionCache();
        PR_Close(connection->sslSocket);
        Sleep(3000);
    }
}

void NSS_cleanup() {
    SSL_ClearSessionCache();
    NSS_Shutdown();
    PR_Cleanup();
}