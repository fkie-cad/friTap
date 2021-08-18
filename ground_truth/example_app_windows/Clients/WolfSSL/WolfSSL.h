#pragma once
#include <wolfssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h> 
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#pragma warning(disable:4996)
#pragma comment(lib, "ws2_32.lib")
#define TMP_BUFFER_SIZE 1024
typedef struct WOLFSSL_Connection {
    WOLFSSL_CTX* context;
    WOLFSSL* ssl;
    int socketDescriptor;
    struct sockaddr_in server;
}WOLFSSL_Connection;
const char* SEND_MSG = "GET / HTTP/1.1\r\nHost: www.google.de\r\nConnection: close\r\n\r\n"; //Get Request for google main page
#define HOSTNAME "216.58.212.163"
void WOLFSSL_cleanup(WOLFSSL_Connection* connection);