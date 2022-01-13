#include "OpenSSL.h"

void report_and_exit(const char* msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void OPENSSL_init() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
}

void OPENSSL_BIO_cleanup(SSL_CTX* ctx, BIO* bio) {
    SSL_CTX_free(ctx);
    BIO_free(bio);
}

void OPENSSL_cleanup(OPENSSL_Connection* connection) {
    SSL_CTX_free(connection->context);
    SSL_free(connection->ssl);
}

void OPENSSL_BIO_setup_and_connect(OPENSSL_Connection* connection, const char* hostname, int port) {
    connection->method = TLS_client_method();                                       // Methoden der TLS 1.2 Suite
    if (connection->method == NULL) report_and_exit("Couldnt load TLS 1.2 suite...");

    connection->context = SSL_CTX_new(connection->method);                             // Neuen Kontext mit TLS 1.2 Suite initialisieren
    if (connection->context == NULL) report_and_exit("Couldnt initialize context...");

    connection->bio = BIO_new_ssl_connect(connection->context);                        // Neues I/O-Objekt mit Verschlüsselung erstellen
    if (connection->bio == NULL) report_and_exit("Couldnt initialize bio...");

    connection->host = (char*)malloc(strlen(hostname) + 1);                           // Hostnamen festlegen
    if (connection->host == NULL) report_and_exit("Couldnt set hostname...");
    strcpy(connection->host, hostname);

    BIO_get_ssl(connection->bio, &connection->ssl);                                   // Zeiger von SSL auf BIO setzen
    SSL_set_mode(connection->ssl, SSL_MODE_AUTO_RETRY); 
    BIO_set_conn_hostname(connection->bio, connection->host);                         // Hostnamen in BIO setzen
    BIO_set_conn_port(connection->bio, "443");                                       // Port in BIO setzen
   
    //Versuche zu verbinden, wenn nicht dann räume auf
    if (BIO_do_connect(connection->bio) <= 0) {
        OPENSSL_BIO_cleanup(connection->context, connection->bio);
        report_and_exit("Unable to connect to host...");
    }


}

void OPENSSL_setup_and_connect(OPENSSL_Connection* connection, const char* hostname, int port) {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
    }
    
    struct sockaddr_in addr;
    //struct hostent* host = gethostbyname(hostname);
    connection->socket = socket(AF_INET, SOCK_STREAM, 6);
    printf("Socket: %d", connection->socket);
    printf("Sock error: %d ---", WSAGetLastError());
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);

    connection->method = TLS_client_method();
    connection->context = SSL_CTX_new(connection->method);
    if (connection->context == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    connect(connection->socket, (struct sockaddr*)&addr, sizeof(addr));
    printf("%d",WSAGetLastError());
        //close(connection->socket);
        //report_and_exit("Connection...");

   


    connection->ssl = SSL_new(connection->context);
    SSL_set_fd(connection->ssl, connection->socket);
    if (SSL_connect(connection->ssl) != 1) {
        ERR_print_errors_fp(stderr);
    }

}

//Verifizierung des Zertifikats erstmal rausgenommen
/*if (!SSL_CTX_load_verify_locations(ctx,
    //    "C:/Users/Crypt0n/Desktop/SSLCerts", 
    //    "C:/Users/Crypt0n/Desktop/SSLCerts")) 
    //    report_and_exit("SSL_CTX_load_verify_locations...");

    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK)
        fprintf(stderr,
            "##### Certificate verification error (%i) but continuing...\n",
            (int)verify_flag);
*/
char* OPENSSL_BIO_get_response(OPENSSL_Connection* connection) {
    
    unsigned long responseBufferSize = 0;
    char* responseBuffer = (char*) malloc(1);
    if (responseBuffer == NULL) report_and_exit("GetResponse...");
    responseBuffer[0] = '\0';

    while (1) {
        //Neuen temporären Buffer erstellen
        char* tempBuffer = (char*)malloc(TMP_BUFFER_SIZE);
        if (tempBuffer == NULL) report_and_exit("Couldnt allocate memory for tempBuffer...");

        int readBytesCount = BIO_read(connection->bio, tempBuffer, TMP_BUFFER_SIZE);
        
        
        if (readBytesCount <= 0) {
            //Wenn keine Daten gelesen wurden, dann hänge hinten ein nullterm-Char dran und gebe reponseBuffer-Pointer zurück
            char* returnBuffer = (char*)realloc(responseBuffer, responseBufferSize+1);
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

char* OPENSSL_get_response(OPENSSL_Connection* connection) {

    unsigned long responseBufferSize = 0;
    char* responseBuffer = (char*)malloc(1);
    if (responseBuffer == NULL) report_and_exit("GetResponse...");
    responseBuffer[0] = '\0';

    while (1) {
        //Neuen temporären Buffer erstellen
        char* tempBuffer = (char*)malloc(TMP_BUFFER_SIZE);
        if (tempBuffer == NULL) report_and_exit("Couldnt allocate memory for tempBuffer...");

        int readBytesCount = SSL_read(connection->ssl, tempBuffer, TMP_BUFFER_SIZE);


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

void OPENSSL_run() {

    char request[1024];
    //const char* hostname = "localhost";

    printf("OpenSSL 1.1.1j 16 Feb 2021\n");
    OPENSSL_init();
    printf("Trying an HTTPS connection to %s...\n", HOSTNAME);
    
    OPENSSL_Connection* con = (OPENSSL_Connection*)malloc(sizeof(OPENSSL_Connection));
    if (con == NULL) report_and_exit("Couldnt allocate memory for new OPENSSL_Connection");
    sprintf(request,"Ya yeet!");

    while (1) {
        OPENSSL_setup_and_connect(con, HOSTNAME, 443);
        SSL_write(con->ssl, SEND_MSG, strlen(SEND_MSG));
        char* response = OPENSSL_get_response(con);
        printf("%s\n", response);
        OPENSSL_cleanup(con);
        Sleep(3000);
    }
}


int main(int argc, char* argv[]) {
    OPENSSL_run();
    return 0;
}