#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define BUF_SIZE 1024

void urlParser(const char* url, char* hostname, char* path);
int connectToHost(const char* hostname, const char* port);
void sendRequest(int fd, const void *buf, size_t len);

int main(int argc, char* argv[]) {
    int follow_redirects = 0;
    char *port = "80";

    int opt;
    while ((opt = getopt(argc, argv, "rp:")) != -1) {
        switch (opt) {
            case 'r':
                follow_redirects = 1;
                break;
            case 'p':
                port = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-r] [-p <port>] URL\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected URL after options\n");
        exit(EXIT_FAILURE);
    }

    char currentUrl[BUF_SIZE];
    snprintf(currentUrl, BUF_SIZE, "%s", argv[optind]);

    int redirect_count = 0;

    do {
        char hostname[BUF_SIZE];
        char path[BUF_SIZE];
        urlParser(currentUrl, hostname, path);

        int sockFd = connectToHost(hostname, port);

        char request[BUF_SIZE];
        snprintf(request, sizeof(request),
                 "GET /%s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Connection: close\r\n"
                 "\r\n", path, hostname);

        sendRequest(sockFd, request, strlen(request));

        ssize_t bytesRead;
        char *response = malloc(BUF_SIZE + 1); // Dynamic allocation for response
        response[BUF_SIZE] = '\0';

        int redirect = 0;
        while ((bytesRead = read(sockFd, response, BUF_SIZE - 1)) > 0) {
            response[bytesRead] = '\0';

            if (follow_redirects &&
                (strstr(response, "HTTP/1.1 301") || strstr(response, "HTTP/1.1 302"))) {
                char* location = strcasestr(response, "Location:");
                if (location) {
                    location += strlen("Location:");
                    while (*location == ' ' || *location == '\t') location++;
                    sscanf(location, "%s", currentUrl);
                    redirect = 1;
                    break;
                }
            }

            if (!follow_redirects) {
                if (write(STDOUT_FILENO, response, bytesRead) == -1) {
                    perror("write");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (bytesRead == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        free(response); // Free dynamically allocated response buffer
        close(sockFd);

        if (redirect) {
            redirect_count++;
            if (redirect_count > 5) {
                fprintf(stderr, "Too many redirects, giving up\n");
                exit(EXIT_FAILURE);
            }
        }

        if (!redirect) {
            break;
        }

    } while (follow_redirects);

    exit(EXIT_SUCCESS);
}

void urlParser(const char* url, char* hostname, char* path) {
    if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        url += 8;
    }

    char* slash = strchr(url, '/');
    if (slash != NULL) {
        *slash = '\0';
        strcpy(hostname, url);
        strcpy(path, slash + 1);
    } else {
        strcpy(hostname, url);
        path[0] = '\0';
    }
}

int connectToHost(const char* hostname, const char* port) {
    struct addrinfo hints, *res, *p;
    int sockFd;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockFd == -1) continue;

        if (connect(sockFd, p->ai_addr, p->ai_addrlen) == 0) break;

        close(sockFd);
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect socket\n");
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    return sockFd;
}

void sendRequest(int fd, const void *buf, size_t len) {
    ssize_t bytesWrote = write(fd, buf, len);
    if (bytesWrote == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }
}
