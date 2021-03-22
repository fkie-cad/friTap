#include "WolfSSL.h"

void report_and_exit(const char* msg) {
    perror(msg);
    exit(-1);
}

void WOLFSSL_init() {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
        exit(1);
    }
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    wolfSSL_load_error_strings();
}


void WOLFSSL_setup_and_connect(WOLFSSL_Connection* connection, char* hostname) {

    connection->context = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (connection->context == NULL) report_and_exit("Couldnt initialize WolfSSL context...");

    connection->ssl = wolfSSL_new(connection->context);
    if (connection->ssl == NULL) report_and_exit("Couldnt initialize WolfSSL ssl...");

    connection->socketDescriptor = socket(AF_INET, SOCK_STREAM, 6);
    memset(&connection->server, 0, sizeof(connection->server));
    connection->server.sin_family = AF_INET;
    connection->server.sin_addr.s_addr = inet_addr(hostname);
    connection->server.sin_port = htons(443);

    /* connect to socket */
    connect(connection->socketDescriptor, (struct sockaddr*)&connection->server, sizeof(connection->server));
    
    //Disable certificate verification
    wolfSSL_set_verify(connection->ssl, SSL_VERIFY_NONE, NULL);
    
    if (wolfSSL_set_fd(connection->ssl, connection->socketDescriptor) != SSL_SUCCESS) {
        char buffer[80];
        wolfSSL_ERR_error_string(wolfSSL_get_error(connection->ssl, 0), buffer);
        printf("%s\n", buffer);
    }

    if (wolfSSL_connect(connection->ssl) == SSL_FATAL_ERROR) {
        char buffer[80];
        wolfSSL_ERR_error_string(wolfSSL_get_error(connection->ssl, 0), buffer);
        printf("%s\n", buffer);
    }
   
}

char* WOLFSSL_get_response(WOLFSSL_Connection* connection) {
    unsigned long responseBufferSize = 0;
    char* responseBuffer = (char*)malloc(1);
    if (responseBuffer == NULL) report_and_exit("GetResponse...");
    responseBuffer[0] = '\0';

    while (1) {
        //Neuen temporären Buffer erstellen
        char* tempBuffer = (char*)malloc(TMP_BUFFER_SIZE);
        if (tempBuffer == NULL) report_and_exit("Couldnt allocate memory for tempBuffer...");

        int readBytesCount = wolfSSL_read(connection->ssl, tempBuffer, TMP_BUFFER_SIZE);


        if (readBytesCount <= 0) {
            //Wenn keine Daten gelesen wurden, dann hänge hinten ein nullterm-Char dran und gebe reponseBuffer-Pointer zurück
            char* returnBuffer = (char*)realloc(responseBuffer, responseBufferSize + 1);
            if (returnBuffer == NULL) report_and_exit("Couldnt realloc memory for returnBuffer...");
            returnBuffer[responseBufferSize] = '\0';
            return returnBuffer;
        }

        //Wenn neue Daten gelesen wurden, dann erweitere ResponseBuffer und schreibe neue Daten hinein
        char* tempResponseBuffer = (char*)realloc(responseBuffer, responseBufferSize + readBytesCount);
        if (tempResponseBuffer == NULL) report_and_exit("Couldnt realloc memory for tempResponseBuffer...");
        responseBuffer = tempResponseBuffer;
        memcpy(responseBuffer + responseBufferSize, tempBuffer, readBytesCount);
        responseBufferSize += readBytesCount;
        free(tempBuffer);
    }
}

void WOLFSSL_cleanup(WOLFSSL_Connection* connection) {
    wolfSSL_free(connection->ssl);
    wolfSSL_CTX_free(connection->context);
    wolfSSL_Cleanup();
    free(connection);
}


void WOLFSSL_run() {
    const char* message = "Ya yeet!";
    printf("WolfSSL 4.7 Feb 2021\n");
    printf("%p\n", wolfSSL_CTX_free);
    WOLFSSL_init();
    WOLFSSL_Connection* con;
    while (1) {
        con = (WOLFSSL_Connection*)malloc(sizeof(WOLFSSL_Connection));
        if (con == NULL) report_and_exit("Couldnt allocate memory for WolfSSL connection...");

        WOLFSSL_setup_and_connect(con, (char*)"127.0.0.1");

        int writtenBytesCount = wolfSSL_write(con->ssl, message, strlen(message));
        printf("Request: %s\n", message);

        char* response = WOLFSSL_get_response(con);
        printf("Response: %s\n", response);
        
        WOLFSSL_cleanup(con);
        Sleep(3000);
    }
    

}

int main() {
    WOLFSSL_run();
}
