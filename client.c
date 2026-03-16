#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXLINE 4096
#define SERV_PORT 8080

int main(int argc, char **argv)
{
    int sockfd;

    struct sockaddr_in servaddr;

    SSL_CTX *ctx;
    SSL *ssl;

    char sendline[MAXLINE];
    char recvline[MAXLINE];

    if (argc != 2)
    {
        printf("Usage: ./client <ServerIP>\n");
        exit(1);
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    SSL_connect(ssl);

    printf("Connected to secure server\n");

    /* LOGIN */

    printf("Enter login command (LOGIN username password):\n");

    fgets(sendline, MAXLINE, stdin);

    SSL_write(ssl, sendline, strlen(sendline));

    SSL_read(ssl, recvline, MAXLINE);

    printf("%s\n", recvline);

    if (strncmp(recvline, "Authentication Successful", 25) != 0)
    {
        printf("Login failed. Closing connection.\n");
        close(sockfd);
        return 0;
    }

    while (1)
    {
        printf("Enter command (CMD <command> or EXIT): ");

        fgets(sendline, MAXLINE, stdin);

        SSL_write(ssl, sendline, strlen(sendline));

        if (strncmp(sendline, "EXIT", 4) == 0)
            break;

        bzero(recvline, MAXLINE);

        SSL_read(ssl, recvline, MAXLINE);

        printf("Server Output:\n%s\n", recvline);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(sockfd);

    SSL_CTX_free(ctx);

    return 0;
}