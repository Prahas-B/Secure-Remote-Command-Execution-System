#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXLINE 4096
#define SERV_PORT 8080
#define LISTENQ 10

/* -------- Authentication Function -------- */

int authenticate(char *username, char *password)
{
    FILE *fp;
    char u[100], p[100];

    fp = fopen("users.txt", "r");

    if(fp == NULL)
        return 0;

    while(fscanf(fp,"%s %s",u,p) != EOF)
    {
        if(strcmp(username,u)==0 && strcmp(password,p)==0)
        {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

/* -------- Client Handler -------- */

void handle_client(SSL *ssl)
{
    char recvline[MAXLINE];
    char sendline[MAXLINE];

    char username[100];
    char password[100];

    int authenticated = 0;

    /* -------- LOGIN PHASE -------- */

    bzero(recvline, MAXLINE);

    SSL_read(ssl, recvline, MAXLINE);

    if(sscanf(recvline,"LOGIN %s %s",username,password) != 2)
    {
        SSL_write(ssl,"Invalid LOGIN format\n",21);
        return;
    }

    if(authenticate(username,password))
    {
        authenticated = 1;
        SSL_write(ssl,"Authentication Successful\n",26);
        printf("User %s logged in\n",username);
    }
    else
    {
        SSL_write(ssl,"Authentication Failed\n",22);
        printf("Login failed for %s\n",username);
        return;
    }

    /* -------- COMMAND LOOP -------- */

    while(authenticated)
    {
        bzero(recvline,MAXLINE);

        int n = SSL_read(ssl,recvline,MAXLINE);

        if(n <= 0)
            break;

        if(strncmp(recvline,"EXIT",4)==0)
        {
            printf("Client disconnected\n");
            break;
        }

        if(strncmp(recvline,"CMD",3)==0)
        {
            char command[1024];

            sscanf(recvline,"CMD %[^\n]",command);

            FILE *fp = popen(command,"r");

            if(fp == NULL)
            {
                SSL_write(ssl,"Command execution failed\n",25);
                continue;
            }

            bzero(sendline,MAXLINE);

            fread(sendline,1,MAXLINE-1,fp);

            SSL_write(ssl,sendline,strlen(sendline));

            pclose(fp);
        }
        else
        {
            SSL_write(ssl,"Unknown command\n",16);
        }
    }
}

/* -------- MAIN SERVER -------- */

int main()
{
    int listenfd, connfd;
    pid_t childpid;

    socklen_t clilen;
    struct sockaddr_in servaddr, cliaddr;

    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL Initialization */

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());

    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_use_certificate_file(ctx,"server.crt",SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx,"server.key",SSL_FILETYPE_PEM);

    /* Create socket */

    listenfd = socket(AF_INET,SOCK_STREAM,0);

    bzero(&servaddr,sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERV_PORT);

    bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

    listen(listenfd,LISTENQ);

    printf("Secure Server running on port %d...\n",SERV_PORT);

    while(1)
    {
        clilen = sizeof(cliaddr);

        connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&clilen);

        if((childpid = fork()) == 0)
        {
            close(listenfd);

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl,connfd);

            if(SSL_accept(ssl) <= 0)
            {
                ERR_print_errors_fp(stderr);
            }
            else
            {
                printf("SSL connection established\n");
                handle_client(ssl);
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);

            close(connfd);

            exit(0);
        }

        close(connfd);
    }

    SSL_CTX_free(ctx);

    return 0;
}