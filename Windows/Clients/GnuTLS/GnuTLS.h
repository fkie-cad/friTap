#include <windows.h>
#include <stdio.h>
#include <gnutls/gnutls.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(suppress : 4996)
#define CHECK(x) assert((x)>=0)
#define HOSTNAME "127.0.0.1"


typedef struct GNUTLS_Connection {
    int socket;
}GNUTLS_Connection;

void GNUTLS_init();
void GNUTLS_cleanup();
void GNUTLS_setup_and_connect(GNUTLS_Connection* connection, const char* hostname, int port);