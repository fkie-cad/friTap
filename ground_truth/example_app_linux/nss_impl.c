#include <nspr/prinit.h>
#include <nspr/private/pprio.h>
#include <nss/nss.h>
#include <nss/ssl.h>
//#include <prinit.h>

#include "common.h"
#include "sslinterface.h"

void ssl_init(char* current_path) {
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSS_Init(current_path);
    NSS_SetDomesticPolicy();
}
void ssl_cleanup(void) {
    NSS_Shutdown();
}
//Read for incoming messages and echo them back
void echo_connection(int client_fd) {
    PRFileDesc* nsprsocket = PR_ImportTCPSocket(client_fd);
    if (nsprsocket == NULL) {
        perror("Failed to import tcp socket\n");
        exit(EXIT_FAILURE);
    }
    PRFileDesc* sslsocket = SSL_ImportFD(NULL, nsprsocket);
    if (sslsocket == NULL) {
        perror("Failed to import ssl socket\n");
        exit(EXIT_FAILURE);
    }
    char buf[BUF_SIZE];
    memset(buf, 0x0, BUF_SIZE);
    int retcode = 1337;
    while (retcode = PR_Read(sslsocket, buf, BUF_SIZE) > 0) {
        printf("Inside read loop\n");
        fflush(stdout);
        printf("[*] Inbound: %s", buf);
        PR_Write(sslsocket, buf, BUF_SIZE);
        memset(buf, 0x0, BUF_SIZE);
    }
    printf("%d", retcode);
    PR_Close(sslsocket);
    return;
}
