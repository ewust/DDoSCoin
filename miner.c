
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include "tls.h"

// 32-byte prev_block_hash (SHA256(prev_block))
// 32-byte merkle_root
// 32-byte nonce
// TODO: precompute hash over first two, only append hash of nonce (length-extend)
// for faster computation!
void generate_client_random(uint8_t *prev_block_hash, uint8_t *merkle_root,
                            uint8_t *nonce, uint8_t **client_random)
{
    *client_random = malloc(SHA256_DIGEST_LENGTH);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, prev_block_hash, 32);
    SHA256_Update(&ctx, merkle_root, 32);
    SHA256_Update(&ctx, nonce, 32);
    SHA256_Final(*client_random, &ctx);
}


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

    uint8_t *s_keyx;
    size_t server_keyx_len = receive_tls_record(sock, &s_keyx);

    // verify server keyx with cert
    struct server_hello shello;
    if (parse_server_hello(server_hello, server_hello_len, &shello) < 0) {
        printf("bad server hello\n");
        return -1;
    }


    struct server_keyx sk;
    memset(&sk, 0, sizeof(sk));
    if (parse_server_keyex(s_keyx, server_keyx_len, shello.cipher_suite, &sk) < 0) {
        printf("bad server keyx\n");
        return -1;
    }

    // TODO get this from cert instead (and verify cert)
    //EVP_PKEY *pkey;
    FILE *fp = fopen("./ericw.us.pub", "rb");
    //PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
    RSA *pkey = NULL;
    PEM_read_RSA_PUBKEY(fp, &pkey, NULL, NULL);
    if (pkey == NULL) {
        printf("Error couldn't read public key\n");
        return -1;
    }

    verify_server_keyex(random, shello.random, &sk, pkey);

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
