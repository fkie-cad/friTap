#pragma once
#include "mbedtls/ssl.h"
#define MBEDTLS_ERR_NET_SOCKET_FAILED                     -0x0042  /**< Failed to open a socket. */
#define MBEDTLS_ERR_NET_CONNECT_FAILED                    -0x0044  /**< The connection to the given server / port failed. */
#define MBEDTLS_ERR_NET_BIND_FAILED                       -0x0046  /**< Binding of the socket failed. */
#define MBEDTLS_ERR_NET_LISTEN_FAILED                     -0x0048  /**< Could not listen on the socket. */
#define MBEDTLS_ERR_NET_ACCEPT_FAILED                     -0x004A  /**< Could not accept the incoming connection. */
#define MBEDTLS_ERR_NET_RECV_FAILED                       -0x004C  /**< Reading information from the socket failed. */
#define MBEDTLS_ERR_NET_SEND_FAILED                       -0x004E  /**< Sending information through the socket failed. */
#define MBEDTLS_ERR_NET_CONN_RESET                        -0x0050  /**< Connection was reset by peer. */
#define MBEDTLS_ERR_NET_UNKNOWN_HOST                      -0x0052  /**< Failed to get an IP address for the given hostname. */
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  -0x0043  /**< Buffer is too small to hold the data. */
#define MBEDTLS_ERR_NET_INVALID_CONTEXT                   -0x0045  /**< The context is invalid, eg because it was free()ed. */
#define MBEDTLS_ERR_NET_POLL_FAILED                       -0x0047  /**< Polling the net context failed. */
#define MBEDTLS_ERR_NET_BAD_INPUT_DATA                    -0x0049  /**< Input invalid. */

#define MBEDTLS_NET_LISTEN_BACKLOG         10 /**< The backlog that listen() should use. */

#define MBEDTLS_NET_PROTO_TCP 0 /**< The TCP transport protocol */
#define MBEDTLS_NET_PROTO_UDP 1 /**< The UDP transport protocol */

#define MBEDTLS_NET_POLL_READ  1 /**< Used in \c mbedtls_net_poll to check for pending data  */
#define MBEDTLS_NET_POLL_WRITE 2 /**< Used in \c mbedtls_net_poll to check if write possible */
