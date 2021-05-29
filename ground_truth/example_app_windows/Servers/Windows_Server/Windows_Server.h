#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <applink.c>
#pragma comment(lib, "Ws2_32.lib")
#define FAIL    -1
typedef int socklen_t;
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)