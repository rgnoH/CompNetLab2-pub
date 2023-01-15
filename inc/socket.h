/**
  * @file socket . h
  * @brief POSIX - compatible socket library supporting TCP protocol on
    IPv4 .
  */

#ifndef _SOCKET_H_
#define _SOCKET_H_

#include "inc.h"
#include <sys/types.h>
// #include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "tcp.h"

#define SOCKET_OFFSET 10000 //offset of socket fd
#define CONNECT_THRESHOLD 20
#define ACCEPT_THRESHOLD 20


/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html)
*/
int __wrap_socket(int domain , int type , int protocol);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html)
*/
int __wrap_bind(int socket , const struct sockaddr *address,
    socklen_t address_len);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html)
*/
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html)
*/
int __wrap_connect(int socket, const struct sockaddr *address,
    socklen_t address_len);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html)
*/
int __wrap_accept(int socket, struct sockaddr *address,
    socklen_t *address_len);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/read.html)
*/
ssize_t __wrap_read(int fildes, void* buf, size_t nbyte);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/write.html)
*/
ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html)
*/
int __wrap_close(int fildes);

/**
 * @see [POSIX.1-2017: socket](http://pubs.opengroup.org/onlinepubs/9699919799/functions/getaddrinfo.html)
 * @param node a valid IPv4 address or NULL
 * @param service a valid port number or NULL
 * @param hints == NULL, or .ai_family == AF_INET, .ai_socktype == IPPROTO_TCP,
 *                          .ai_flags == 0 
 * @brief not work for other parameter types
 */
int __wrap_getaddrinfo(const char *node , const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res);

int findSocket(const struct in_addr ip, const int port);

#endif