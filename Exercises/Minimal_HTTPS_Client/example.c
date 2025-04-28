#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    const char *hostname = argv[1];
    const char *portnum = "443";

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Resolve hostname
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, portnum, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    // Create socket and connect
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // Setup SSL
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return 1;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect() failed\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    // Build and send HTTP request
    char request[1024];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n", hostname);

    SSL_write(ssl, request, strlen(request));

    // Read and print the response
    char buf[4096];
    int bytes;
    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, bytes, stdout);
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
    freeaddrinfo(res);

    return 0;
}

