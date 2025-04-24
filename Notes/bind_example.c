#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>  // For IPPROTO_TCP

struct addrinfo hints, *res, *p;
int sockfd;
int status;

// Load up address structs with getaddrinfo:
memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE;  // Fill in my IP for me

// Get address info for the port
status = getaddrinfo(NULL, "3490", &hints, &res);
if (status != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return 1;
}

// Try each address until we successfully bind
for (p = res; p != NULL; p = p->ai_next) {
    // If you want to prioritize IPv6 (to allow both IPv6 and IPv4 connections):
    if (p->ai_family == AF_INET6) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;  // Try next address if socket creation fails
        }

        // Bind to the address
        status = bind(sockfd, p->ai_addr, p->ai_addrlen);
        if (status == -1) {
            perror("bind");
            close(sockfd);
            continue;  // Try next address if bind fails
        }

        break;  // If bind is successful, exit the loop
    }
    // If the first node is AF_INET (IPv4) and you are okay with just IPv4 connections:
    else if (p->ai_family == AF_INET) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;  // Try next address if socket creation fails
        }

        // Bind to the address
        status = bind(sockfd, p->ai_addr, p->ai_addrlen);
        if (status == -1) {
            perror("bind");
            close(sockfd);
            continue;  // Try next address if bind fails
        }

        break;  // If bind is successful, exit the loop
    }
}

// If no bind was successful, exit
if (p == NULL) {
    fprintf(stderr, "Failed to bind to any address\n");
    return 1;
}

// Now the socket is bound, and you can listen and accept connections
listen(sockfd, 5);
printf("Server is listening on port 3490...\n");

// Close the socket after usage
close(sockfd);

