/*
This is a simple sslserver which accepts all requests and echos your message back to you.
It implements different ssl libraries which are configured at compiletime
*/
#include "common.h"
#include "sslinterface.h"

//Convenience function for creating a socket, taken from https://wiki.openssl.org/index.php/Simple_TLS_Server
int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

static void short_to_path(char *full_path) {
    char *exec_name = strstr(full_path, "/sslserver");
    *exec_name = 0x0;
    return;
}

int main(int argc, char **argv) {
    int port, sock;
    if (argc != 2) {
        perror("Usage: ./sslserver <port>");
        exit(EXIT_FAILURE);
    }
    port = atoi(argv[1]);
    short_to_path(argv[0]);
    ssl_init(argv[0]);
    sock = create_socket(port);
    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        int client_fd = accept(sock, (struct sockaddr *)&addr, &len);
        if (client_fd < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("[*] Incoming connection from %s:%d\n", inet_ntoa(addr.sin_addr), addr.sin_port);
        echo_connection(client_fd);
        printf("[*] Connection closed\n");
        close(client_fd);
    }
    //This actually can never happen because of endless loop, but who knows
    close(sock);
    ssl_cleanup();
    return EXIT_SUCCESS;
}