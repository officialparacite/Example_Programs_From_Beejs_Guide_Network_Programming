#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF 256

int main(int argc, char* argv[]){
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status;

    if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int sockFd;
    for (p = res; p != NULL; p = p->ai_next) {
        sockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sockFd == -1) continue;

        if (connect(sockFd, p->ai_addr, p->ai_addrlen) != -1) break;

        close(sockFd);
    }

    freeaddrinfo(res);

    if (p == NULL) {
        fprintf(stderr, "could not connect\n");
        exit(EXIT_FAILURE);
    }

    char msg[BUF];
    char msg_recv[BUF];
    while(1) {
        if (fgets(msg, BUF, stdin) == NULL) break;

        ssize_t msgLen = strlen(msg);
        if (send(sockFd, msg, msgLen, 0) == -1) {
            perror("send");
            break;
        }

        ssize_t bytesRecv;
        bytesRecv = recv(sockFd, msg_recv, BUF, 0);
        if (bytesRecv == -1) {
            perror("recv");
            break;
        }

        msg_recv[bytesRecv] = '\0';

        printf("%s\n", msg_recv);
    }
    close(sockFd);
    exit(EXIT_SUCCESS);
}


