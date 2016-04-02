#include "tls.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <assert.h>

size_t make_client_hello(uint8_t *random, uint8_t **client_hello)
{
    *client_hello = malloc(400);
    uint8_t *p = *client_hello;


    w1(p, TLS_RECORD_TYPE_HANDSHAKE);
    w2(p, TLS_RECORD_VERSION_1_0);

    // We'll write this later
    uint8_t *rec_hdr_len = p;
    p += 2;

    w1(p, TLS_HANDSHAKE_TYPE_CLIENT_HELLO);

    // We'll write this later, too
    uint8_t *hs_hdr_len = p;
    p += 3;

    w2(p, TLS_RECORD_VERSION_1_2);

    // Client random
    memcpy(p, random, 32);
    p += 32;

    // Session ID length
    w1(p, 0x00);

    // cipher suite length
    w2(p, 0x0004);

    // Cipher suites
    w2(p, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    w2(p, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    // Compression method length
    w1(p, 0x01);

    // no compression
    w1(p, TLS_COMPRESSION_NULL);

    // We'll come back to this
    uint8_t *extensions_len = p;
    p += 2;

    // Extension: ec_point_format
    w2(p, TLS_EXT_EC_POINT_FORMAT);
    w2(p, 0x0004);  // length
    w1(p, 0x03);    // ec point format length
    w1(p, 0x00);    // uncompressed
    w1(p, 0x01);    // compressed prime
    w1(p, 0x02);    // compressed char2

    // Extensions elliptic_curves
    w2(p, TLS_EXT_ELLIPTIC_CURVES);
    w2(p, 0x0004);  // length
    w2(p, 0x0002);  // elliptic curve length
    w2(p, TLS_CURVE_secp256r1);

    // Session ticket?

    // Extension: signature algorithms
    w2(p, TLS_EXT_SIGNATURE_ALGORITHMS);
    w2(p, 0x0004);  // length
    w2(p, 0x0002);  // signature algorithms length
    w2(p, TLS_SIG_SHA512_RSA);

    // Write lengths
    wlen2(p, extensions_len);
    wlen3(p, hs_hdr_len);
    wlen2(p, rec_hdr_len);

    return (p - *client_hello);
}

// Assumes blocking sock
int recvall(int sock, void *buf, size_t len)
{
    size_t so_far = 0;
    uint8_t *p = buf;
    while (so_far < len) {
        size_t got = recv(sock, &p[so_far], len - so_far, 0);
        if (got < 0) {
            return -1;
        }
        so_far += got;
    }
    return 0;
}

size_t receive_tls_record(int sock, uint8_t **record)
{
    struct tls_record_header rec_hdr;

    recvall(sock, &rec_hdr, sizeof(rec_hdr));
    size_t len = ntohs(rec_hdr.length);
    *record = malloc(len);
    recvall(sock, *record, len);

    return len;
}

size_t get_tls_record(struct evbuffer *input, uint8_t **record)
{
    struct tls_record_header hdr;
    *record = NULL;

    if (evbuffer_get_length(input) < sizeof(hdr)) {
        return 0;
    }

    evbuffer_copyout(input, &hdr, sizeof(hdr));
    hdr.version = ntohs(hdr.version);
    hdr.length = ntohs(hdr.length);

    // No int overflow on 5 + 16-bit number...right?!?
    if (evbuffer_get_length(input) < (sizeof(hdr) + hdr.length)) {
        return 0;
    }

    // remove the length you read
    evbuffer_drain(input, sizeof(hdr));

    *record = malloc(sizeof(hdr) + hdr.length);
    assert(*record != NULL);


    // Copy in the contents
    size_t ret = evbuffer_remove(input, *record, hdr.length);
    if (ret != hdr.length) {
        printf("evbuffer_remove failed in get_tls_record, got %lu bytes, wanted %d\n", ret, hdr.length);
        free(*record);
        *record = NULL;
        return 0;
    }

    return ret;
}




// This will count extensions, but not parse them (we have to count how many there
// are before we allocate, so we make a dumb 2-pass in parse_tls_extensions on the
//  off-chance you care about extensions. If not, it's just one pass, and we don't
// even parse over the extensions data at all. This means
// following this function, sh->num_extensions and sh->extensions won't be set
// (only sh->extensions_data).
int parse_server_hello(uint8_t *server_hello, size_t len, struct server_hello *sh)
{

    uint8_t *p = server_hello;

    if (r1_safe(server_hello, p, len) != TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
        printf("not a server hello\n");
        return -1;
    }

    // handshake length
    r3_safe(server_hello, p, len);

    sh->version = r2_safe(server_hello, p, len);

    // zero-copy server random
    sh->random = p;
    p += 32;

    // zero-copy session id
    sh->session_id_len = r1_safe(server_hello, p, len);
    sh->session_id = p;
    p += sh->session_id_len;

    sh->cipher_suite = r2_safe(server_hello, p, len);
    sh->compression_method = r1_safe(server_hello, p, len);

    size_t ext_len = r2_safe(server_hello, p, len);
    sh->extensions_data = p;
    p += ext_len;

    // This technically shouldn't be the check...sometimes records
    // can contain multiple handshakes :/
    if ((p - server_hello) != len) {
        return -1;
    }

    return 0;
}


int parse_tls_extensions(struct server_hello *sh)
{

    if (sh->extensions != NULL || sh->extensions_data == NULL) {
        return -1;
    }

    uint8_t *ext_start  = sh->extensions_data;
    size_t  ext_len     = sh->extensions_len;

    sh->num_extensions = 0;

    // First pass: Count extensions
    uint8_t *p = ext_start;
    while ((p - sh->extensions_data) < sh->extensions_len) {
        r2_safe(ext_start, p, ext_len);
        size_t len = r2_safe(ext_start, p, ext_len);
        p += len;
        sh->num_extensions++;
    }

    // Check for integer overflow, and allocate
    if ((sh->num_extensions * sizeof(struct tls_extension)) < sh->num_extensions) {
        return -1;
    }
    sh->extensions = malloc(sh->num_extensions*sizeof(struct tls_extension));


    // Second pass: actually parse them
    p = ext_start;
    int i = 0;
    while ((p - ext_start) < ext_len) {
        sh->extensions[i]->type     = r2_safe(ext_start, p, ext_len);
        sh->extensions[i]->length   = r2_safe(ext_start, p, ext_len);
        sh->extensions[i]->data     = p;
        p += sh->extensions[i]->length;
        i++;
    }

    if ((p - ext_start) != ext_len) {
        return -1;
    }
    return 0;
}

int parse_server_keyex(uint8_t *server_keyx, size_t len, uint16_t cipher_suite,
                    struct server_keyx *sk)
{
    uint8_t *p = server_keyx;
    if (r1_safe(server_keyx, p, len) != TLS_HANDSHAKE_TYPE_SERVER_KEYX) {
        return -1;
    }

    uint32_t hs_len = r3_safe(server_keyx, p, len);

    if (cipher_suite != TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
        // Only support this for now :(
        return -1;
    }

    sk->server_dh_params = p;

    sk->curve_type = r1_safe(server_keyx, p, len);
    sk->named_curve = r2_safe(server_keyx, p, len);
    sk->public_point_len = r1_safe(server_keyx, p, len);
    sk->public_point = p;
    p += sk->public_point_len;

    sk->server_dh_params_len = (p - sk->server_dh_params);


    sk->sig_alg = r2_safe(server_keyx, p, len);

    sk->sig_len = r2_safe(server_keyx, p, len);
    sk->sig = p;
    p += sk->sig_len;

    if ((p - server_keyx) != len) {
        return -1;
    }

    return 0;
}

int verify_server_keyex(uint8_t *crandom, uint8_t *srandom,
                    struct server_keyx *sk, RSA *key)
{


    // TODO: support other things besides RSA/SHA512: base off sk->sig_algs
    // RSA on the signature to get the expected hash
    uint8_t out_buf[2048];
    size_t out_len = RSA_public_decrypt(sk->sig_len, sk->sig,
                                        out_buf, key, RSA_PKCS1_PADDING);

    // We could parse the ASN, or, we could just look at the last 64-bytes...
    uint8_t *sig_digest = &out_buf[out_len - SHA512_DIGEST_LENGTH];

    // Calculate hash
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, crandom, 32);
    SHA512_Update(&ctx, srandom, 32);
    SHA512_Update(&ctx, sk->server_dh_params, sk->server_dh_params_len);
    SHA512_Final(digest, &ctx);

    // Don't need to be safe, no secrets here
    if (memcmp(sig_digest, digest, SHA512_DIGEST_LENGTH) == 0) {
        printf("success!\n");
        return 1;
    } else {
        return 0;
    }
}
