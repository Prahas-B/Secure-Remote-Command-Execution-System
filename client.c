#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

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

    struct timeval start, end;
    double time_taken;

    if(argc != 2)
    {
        printf("Usage: ./client <ServerIP>\n");
        exit(1);
    }

    /* SSL Initialization */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());

    /* Create Socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        printf("Socket creation failed\n");
        exit(1);
    }

    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

    /* Connect to Server */
    if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0)
    {
        printf("Connection to server failed\n");
        exit(1);
    }

    /* SSL Connection */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,sockfd);

    if(SSL_connect(ssl) <= 0)
    {
        printf("SSL connection failed\n");
        close(sockfd);
        exit(1);
    }

    printf("Connected to Secure Server\n");

    /* LOGIN PHASE */
    printf("Enter login command (LOGIN username password):\n");
    fgets(sendline,MAXLINE,stdin);

    SSL_write(ssl,sendline,strlen(sendline));

    bzero(recvline,MAXLINE);
    SSL_read(ssl,recvline,MAXLINE);

    if(strncmp(recvline,"Authentication Successful",25) == 0)
    {
        printf("Login Successful\n");
    }
    else if(strncmp(recvline,"Authentication Failed",21) == 0)
    {
        printf("Invalid Username or Password\n");
        close(sockfd);
        return 0;
    }
    else
    {
        printf("Invalid LOGIN format. Use: LOGIN username password\n");
        close(sockfd);
        return 0;
    }

    /* COMMAND LOOP */
    while(1)
    {
        printf("Enter command (CMD <command> or EXIT): ");
        fgets(sendline,MAXLINE,stdin);

        if(strcmp(sendline,"\n") == 0)
        {
            printf("Empty command. Try again.\n");
            continue;
        }

        gettimeofday(&start, NULL);

        SSL_write(ssl,sendline,strlen(sendline));

        if(strncmp(sendline,"EXIT",4) == 0)
            break;

        bzero(recvline,MAXLINE);

        if(SSL_read(ssl,recvline,MAXLINE) <= 0)
        {
            printf("Server not responding\n");
            break;
        }

        gettimeofday(&end, NULL);

        time_taken = (end.tv_sec - start.tv_sec) * 1000.0;
        time_taken += (end.tv_usec - start.tv_usec) / 1000.0;

        printf("Server Output:\n%s\n",recvline);
        printf("Response Time: %.3f ms\n", time_taken);
    }

    /* Close Connections */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    printf("Connection closed\n");

    return 0;
} // this code is client.c after adding authentication handling, edge case handling such as invalid login, empty commands, and response time measurement
