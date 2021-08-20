#include <windows.h>
#include <stdio.h>
#include <gnutls.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(suppress : 4996)
#define CHECK(x) assert((x)>=0)
#define HOSTNAME "127.0.0.1"//"216.58.212.163" HTTP request to google not working
#define GNUTLS_VERSION "7.3.0"
#define TMP_BUFFER_SIZE 1024
#define MSG "GET / HTTP/1.1\r\nHost: www.google.de\r\nConnection: close\r\n\r\n"

typedef struct GNUTLS_Connection {
    int socket;
    gnutls_session_t session;
    gnutls_certificate_credentials_t xcred;
}GNUTLS_Connection;

int tcp_connect(const char* ip, int port);
void GNUTLS_init();
void GNUTLS_cleanup();
void GNUTLS_run();
void GNUTLS_setup_and_connect(GNUTLS_Connection* connection, const char* hostname, int port);