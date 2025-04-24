#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>

#define BUF_SIZE 1024

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage Error: %s <port> <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    struct addrinfo hints, *result, *resultPointer;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status;
    if ((status = getaddrinfo(NULL, argv[1], &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int sockFd;
    for (resultPointer = result; resultPointer; resultPointer = resultPointer->ai_next) {
        if (resultPointer->ai_family != AF_INET6) continue;

        sockFd = socket(resultPointer->ai_family, resultPointer->ai_socktype, resultPointer->ai_protocol);

        if (sockFd == -1) continue;

        int no = 0;
        if (setsockopt(sockFd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) == -1) {
            perror("setsockopt IPV6_V6ONLY");
            close(sockFd);
            continue;
        }

        else if (bind(sockFd, resultPointer->ai_addr, resultPointer->ai_addrlen) == 0) break;

        close(sockFd);
    }
    if (resultPointer == NULL) {
        fprintf(stderr, "Failed to bind socket\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);

    if (listen(sockFd, 5) == -1) {
        perror("listen\n");
        exit(EXIT_FAILURE);
    }

    printf("server running on port: %s\n", argv[1]);

    while (1) {
        int clientFd;
        struct sockaddr_storage clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        clientFd = accept(sockFd, (struct sockaddr *) &clientAddr, &clientAddrLen);
        if (clientFd == -1) {
            perror("accept");
            continue;
        }

        char buf[BUF_SIZE];
        ssize_t bytesRecv = recv(clientFd, buf, BUF_SIZE - 1, 0);
        if (bytesRecv == -1) {
            perror("recv");
            close(clientFd);
            continue;
        }
        else buf[bytesRecv] = '\0';

        fprintf(stdout, "Request: %s\n", buf);

        int fileFd;
        fileFd = open(argv[2], O_RDONLY);
        if (fileFd == -1) {
        const char *notFound = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found\n";
        send(clientFd, notFound, strlen(notFound), 0);
        close(clientFd);
        continue;
        }

        const char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        if (send(clientFd, header, strlen(header), 0) == -1) {
            perror("send header");
            close(fileFd);
            close(clientFd);
            continue;
        }

        char fileBuf[BUF_SIZE];
        ssize_t bytesRead;
        ssize_t bytesSent;
        while ((bytesRead = read(fileFd, fileBuf, BUF_SIZE)) != 0) {
            if (bytesRead == -1) {
                perror("read");
                break;
            }
            bytesSent = send(clientFd, fileBuf, bytesRead, 0);
            if (bytesSent == -1) {
                perror("send");
                break;
            }
        }

    close(fileFd);
    close(clientFd);

    }

    close(sockFd);

    return 0;
}
