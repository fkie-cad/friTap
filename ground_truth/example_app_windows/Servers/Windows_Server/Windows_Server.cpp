#include "Windows_Server.h"


// Create the SSL socket and intialize the socket address structure
int OpenListener(int listeningPort){
    WSADATA wsa;
    int socketD;    //Socket descriptor
    struct sockaddr_in addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0){
        printf("Failed to initialize WSA. Error: %d\n", WSAGetLastError());
        return 1;
    }

    
    socketD = socket(AF_INET, SOCK_STREAM, 6);
    if (socketD == INVALID_SOCKET) {
        perror("Failed to open socket!\n");
        abort();
    }

    printf("Socket descriprot: %d\n", socketD);

    bzero(&addr, sizeof(addr));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listeningPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socketD, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        perror("Failed to bind port!\n");
        abort();
    }

    if (listen(socketD, 10) != 0){
        perror("Failed to configure listening port!\n");
        abort();
    }
    printf("Listening socket initialized!");
    return socketD;
}

SSL_CTX* InitServerCTX(void){
    const SSL_METHOD* method;
    SSL_CTX* ctx;
    OpenSSL_add_all_algorithms();  
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile){
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)){
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl){
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    
    if (cert != NULL){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl){
    char buf[1024] = { 0 };
    int sd, bytes;
    const char* ServerResponse = "Just a response!";
    const char* cpValidMessage = "Ya yeet!";
    if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else{
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg:%s\n", buf);
        
        if (bytes > 0){
            if (strcmp(cpValidMessage, buf) == 0){
                SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
            }
            else
            {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    closesocket(sd);          /* close connection */
}
int main(int count, char* Argc[]){
    SSL_CTX* ctx;
    int server;

    // Initialize the SSL library
    SSL_library_init();
    ctx = InitServerCTX();
    LoadCertificates(ctx, (char*) "mycert.pem", (char*)"mycert.pem"); /* load certs */
    server = OpenListener(atoi("443"));    /* create server socket */

    while (1){
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL* ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), addr.sin_port);
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    closesocket(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
