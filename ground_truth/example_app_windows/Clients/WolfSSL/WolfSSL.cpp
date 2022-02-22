#define OPENSSL_EXTRA true
#define DEBUG true
#include "WolfSSL.h"



HINSTANCE wolfSSL;
typedef int(__stdcall* _wolfSSL_Init)(WOLFSSL*, void*, int);
_wolfSSL_Init wRead;
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
    wolfSSL_load_error_strings();
}

typedef unsigned char ByteData;
ByteData HexChar(char c)
{
    if ('0' <= c && c <= '9') return (ByteData)(c - '0');
    if ('A' <= c && c <= 'F') return (ByteData)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (ByteData)(c - 'a' + 10);
    return (ByteData)(-1);
}

void BinToHex(const ByteData* buff, int length, char* output, int outLength)
{
    char binHex[] = "0123456789ABCDEF";

    if (!output || outLength < 4) return (void)(-6);
    *output = '\0';

    if (!buff || length <= 0 || outLength <= 2 * length)
    {
        memcpy(output, "ERR", 4);
        return (void)(-7);
    }

    for (; length > 0; --length, outLength -= 2)
    {
        ByteData byte = *buff++;

        *output++ = binHex[(byte >> 4) & 0x0F];
        *output++ = binHex[byte & 0x0F];
    }
    if (outLength-- <= 0) return (void)(-8);
    *output++ = '\0';
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
        printf("Setfd: %s\n", buffer);
    }


    if (wolfSSL_connect(connection->ssl) == SSL_FATAL_ERROR) {
        char buffer[80];
        wolfSSL_ERR_error_string(wolfSSL_get_error(connection->ssl, 0), buffer);
        printf("Connect: %s\n", buffer);
    }
    
#ifdef DEBUG
    WOLFSSL_SESSION* session = wolfSSL_get_session(connection->ssl);
    int bufferSz = wolfSSL_SESSION_get_master_key(session, NULL, 0);
    printf("Needed length: %d\n", bufferSz);
    unsigned char* buffer = (unsigned char*)malloc(bufferSz);
    int ret = wolfSSL_SESSION_get_master_key(session, buffer, bufferSz);
    printf("%.48s\n", buffer);
#endif // DEBUG

    
   
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
    printf("WolfSSL 4.7 Feb 2021\n");
    WOLFSSL_init();
    WOLFSSL_Connection* con;
    while (1) {
        con = (WOLFSSL_Connection*)malloc(sizeof(WOLFSSL_Connection));
        if (con == NULL) report_and_exit("Couldnt allocate memory for WolfSSL connection...");

        WOLFSSL_setup_and_connect(con, (char*)HOSTNAME);

        int writtenBytesCount = wolfSSL_write(con->ssl, SEND_MSG, strlen(SEND_MSG));
        printf("Request: %s\n", SEND_MSG);

        char* response = WOLFSSL_get_response(con);
        
        //printf("Response: %s\n", response);
        
        WOLFSSL_cleanup(con);
        Sleep(3000);
    }
    

}

int main() {
    WOLFSSL_run();
}
