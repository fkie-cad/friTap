//-------OPENSSL-------
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/applink.c>

//-------WINDOWS-------
#include <stdio.h>
#include <stdlib.h>
#include <memory.h> 
#include <string.h>
#include <windows.h>


#define HOSTNAME "localhost"
#define TMP_BUFFER_SIZE 1024

typedef struct SSL_Connection {
    const SSL_METHOD* method;
    SSL_CTX* context;
    BIO* bio;
    SSL* ssl = NULL;
    char* host;
}SSL_Connection;



void report_and_exit(const char* msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void OPENSSL_init() {
    SSL_load_error_strings();
    SSL_library_init();
}

void OPENSSL_cleanup(SSL_CTX* ctx, BIO* bio) {
    SSL_CTX_free(ctx);
    BIO_free_all(bio);
}

void OPENSSL_setup_and_connect(SSL_Connection * connection, const char* hostname, int port) {
    connection->method = TLSv1_2_client_method();                                       // Methoden der TLS 1.2 Suite
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
        OPENSSL_cleanup(connection->context, connection->bio);
        report_and_exit("Unable to connect to host...");
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
char* OPENSSL_get_response(SSL_Connection* connection) {
    
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

void OPENSSL_run() {

    char request[1024];
    //const char* hostname = "localhost";

    printf("OpenSSL 1.1.1j 16 Feb 2021\n");
    OPENSSL_init();
    printf("Trying an HTTPS connection to %s...\n", HOSTNAME);
    
    SSL_Connection* con = (SSL_Connection*)malloc(sizeof(SSL_Connection));
    if (con == NULL) report_and_exit("Couldnt allocate memory for new SSL_Connection");

    sprintf(request,"Ya yeet!");

    while (1) {
        OPENSSL_setup_and_connect(con, HOSTNAME, 3000);
        BIO_puts(con->bio, request);
        char* response = OPENSSL_get_response(con);
        printf("%s\n", response);
        OPENSSL_cleanup(con->context, con->bio);
        Sleep(3000);
    }
}


int main(int argc, char* argv[]) {
    //if (argc <= 1) report_and_exit("Invalid amount of given arguments!");
    int option = 1;

    switch (option) {
        case 1:
            OPENSSL_run();
            break;
        case 2:
            printf("Option 2 ausgwählt!");
            break;
    }


    return 0;
}