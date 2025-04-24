#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF 256

int main(int argc, char* argv[]){
    if (argc != 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status;

    if ((status = getaddrinfo(NULL, argv[1], &hints, &res)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int sockFd;
    for (p = res; p != NULL; p = p->ai_next){
        sockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockFd == -1) continue;

        if (bind(sockFd, p->ai_addr, p->ai_addrlen) == 0) break;

        close(sockFd);
    }

    freeaddrinfo(res);

    if (p == NULL) {
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }

    if (listen(sockFd, 5) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    int newFd;
    struct sockaddr_storage client;
    memset(&client, 0, sizeof(client));
    socklen_t clientSize = sizeof(client);

    newFd = accept(sockFd, (struct sockaddr *) &client, &clientSize);
    if (newFd == -1) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    while (1) {
        ssize_t bytesRecv;
        char msg[BUF];

        bytesRecv = recv(newFd, msg, BUF, 0);
        if (bytesRecv == -1) {
            perror("recv");
            break;
        }

        if (bytesRecv == 0) {
            printf("client disconnected...\n");
            break;
        }

        msg[bytesRecv] = '\0';

        ssize_t bytesSend;

        bytesSend = send(newFd, msg, bytesRecv, 0);
        if (bytesSend == -1) {
            perror("send");
            break;
        }
    }
    close(newFd);
}
