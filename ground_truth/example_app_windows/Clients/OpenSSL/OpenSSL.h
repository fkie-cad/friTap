#pragma once
//-------OpenSSL-------
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <applink.c>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(suppress : 4996)
typedef struct OPENSSL_Connection {
    const SSL_METHOD* method;
    SSL_CTX* context;
    BIO* bio;
    SSL* ssl = NULL;
    char* host;
    int socket;
}OPENSSL_Connection;

//-------WINDOWS-------
#include <stdio.h>
#include <stdlib.h>
#include <memory.h> 
#include <string.h>
#include <windows.h>

const char* SEND_MSG = "GET / HTTP/1.1\r\nHost: www.google.de\r\nConnection: close\r\n\r\n"; //Get Request for google main page
#define HOSTNAME "216.58.212.163"
#define TMP_BUFFER_SIZE 1024
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)