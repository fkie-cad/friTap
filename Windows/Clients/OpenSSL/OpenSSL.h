#pragma once
//-------OpenSSL-------
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/applink.c>

typedef struct OPENSSL_Connection {
    const SSL_METHOD* method;
    SSL_CTX* context;
    BIO* bio;
    SSL* ssl = NULL;
    char* host;
}OPENSSL_Connection;

//-------WINDOWS-------
#include <stdio.h>
#include <stdlib.h>
#include <memory.h> 
#include <string.h>
#include <windows.h>


#define HOSTNAME "localhost"
#define TMP_BUFFER_SIZE 1024