#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]){
    if (argc != 2){
        fprintf(stderr, "usage error: %s <example.com>", argv[0] );
        return 1;
    }

    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status;

    if ((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0){
        fprintf(stderr, "Error getting address info: %s\n", gai_strerror(status));
        return 1;
    }
    for (p = res; p != NULL; p = p->ai_next) {
        void *address;
        char *ip_ver;
        char ipstr[INET6_ADDRSTRLEN];

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
            address = &(ipv4->sin_addr);
            ip_ver = "ipv4";
        }
        else if (p->ai_family == AF_INET6){
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) p->ai_addr;
            address = &(ipv6->sin6_addr);
            ip_ver = "ipv6";
        }
        inet_ntop(p->ai_family, address, ipstr, sizeof(ipstr));
        printf("%s: %s\n", ip_ver, ipstr);
    }
    freeaddrinfo(res);
    return 0;
}
