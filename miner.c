
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include "tls.h"



int make_connection(uint8_t *random)
{
    // TCP connect
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    struct hostent *he = gethostbyname("ericw.us");
    memset(&sin, 0, sizeof(sin));
    sin.sin_family  = he->h_addrtype;
    sin.sin_port    = htons(443);
    sin.sin_addr    = *(((struct in_addr **)he->h_addr_list)[0]);

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf("Error: connect\n");
        return 1;
    }

    // Send client hello, with given client random
    uint8_t *client_hello;
    size_t client_hello_len = make_client_hello(random, &client_hello);

    // Todo check length (real todo: make all this event driven)
    send(sock, client_hello, client_hello_len, 0);
    free(client_hello);

    // receive server hello, cert, server keyx
    uint8_t *server_hello;
    size_t server_hello_len = receive_tls_record(sock, &server_hello);

    uint8_t *cert;
    size_t cert_len = receive_tls_record(sock, &cert);

    uint8_t *server_keyx;
    size_t server_keyx_len = receive_tls_record(sock, &server_keyx);

    // verify server keyx with cert
    struct server_hello shello;
    if (parse_server_hello(server_hello, server_hello_len, &shello) < 0) {
        printf("bad server hello\n");
        return -1;
    }

    int i;
    printf("server random: ");
    for (i=0; i<32; i++) {
        printf("%02x", shello.random[i]);
    }
    printf("\n");

}



int main()
{
    uint8_t random[32];
    memset(random, 0xAA, 32);
    make_connection(random);

    return 0;
}
