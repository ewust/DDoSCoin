#ifndef TLS_H
#define TLS_H


#include <unistd.h>
#include <stdint.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>

#define TLS_RECORD_TYPE_HANDSHAKE   0x16
#define TLS_RECORD_VERSION_1_0      0x0301
#define TLS_RECORD_VERSION_1_1      0x0302
#define TLS_RECORD_VERSION_1_2      0x0303

#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO 0x02
#define TLS_HANDSHAKE_TYPE_CERT         0x0b
#define TLS_HANDSHAKE_TYPE_SERVER_KEYX  0x0c

/* Cipher suites */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xc02f
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV       0x00ff

#define TLS_COMPRESSION_NULL    0x00

/* Extensions */
#define TLS_EXT_EC_POINT_FORMAT     0x000b
#define TLS_EXT_ELLIPTIC_CURVES     0x000a
#define TLS_EXT_SIGNATURE_ALGORITHMS    0x000d

#define TLS_CURVE_secp256r1     0x0017
#define TLS_SIG_SHA512_RSA  0x0601

struct tls_record_header {
    uint8_t     type;
    uint16_t    version;
    uint16_t    length;
} __attribute__((packed));


struct tls_handshake_header {
    uint8_t     type;
    uint8_t     length[3];
    uint16_t    version;
} __attribute__((packed));

// Up until the variable fields
struct tls_client_hello {
    struct tls_record_header    rec_hdr;
    struct tls_handshake_header hs_hdr;

    uint8_t                     random[32];
    uint8_t                     session_id_length;
} __attribute__((packed));


struct tls_extension {
    uint16_t    type;
    uint8_t     length;
    uint8_t     *data;
};

struct server_hello {
    uint16_t    version;
    uint8_t     *random;

    uint8_t     *session_id;
    size_t      session_id_len;

    uint16_t    cipher_suite;
    uint8_t     compression_method;

    size_t      extensions_len;
    uint8_t     *extensions_data;
    int         num_extensions;
    struct tls_extension **extensions;
};

struct server_keyx {
    uint8_t     *server_dh_params;
    size_t      server_dh_params_len;

    // ECDHE/named curve specific
    uint8_t     curve_type;
    uint16_t    named_curve;
    uint8_t     public_point_len;
    uint8_t     *public_point;


    uint16_t    sig_alg;
    size_t      sig_len;
    uint8_t     *sig;

};




// This is a GCC statement expression; allows us to bail (with a return -1)
// if some condition isn't met (i.e. you're reading off the end of the buffer)
// but otherwise return a value. Sort of like an inline function, but with the ability
// to exit the parent function if needed.
#define r1_safe(base, p, len) ({ if ((p - base) + 1 > len) { return -1; } \
                                        *p++; })
#define r2_safe(base, p, len) ({ if ((p - base) + 2 > len) { return -1; } \
                                        uint16_t ret = ntohs(*(uint16_t*)p); \
                                        p += 2; \
                                        ret; })
#define r3_safe(base, p, len) ({ if ((p - base) + 3 > len) { return -1; } \
                                        uint32_t ret = ((p[0] << 16) | (p[1] << 8) | p[2]); \
                                        p += 3; \
                                        ret; })
#define r4_safe(base, p, len) ({ if ((p - base) + 4 > len) { return -1; } \
                                        uint32_t ret = ntohl(*(uint32_t*)p); \
                                        p += 4; \
                                        ret; })


#define w1(p, d) *p++ = (uint8_t)d
#define w2(p, d) do { *((uint16_t*)p) = htons(d); p += 2; } while (0)
#define w3(p, d) do { *p++ = ((d >> 16) & 0xff); \
                      *p++ = ((d >> 8) & 0xff); \
                      *p++ = (d & 0xff);} while (0)
#define w4(p, d) do { *((uint32_t*)p) = htonl(d); p += 4; } while (0)


// Macros for writing lengths
#define wlen2(p, l)  w2(l, (p - l - 2))
#define wlen3(p, l)  do { int tmp = (p - l - 3);  w3(l, tmp); } while (0)

// Pretty sure the original wlen3 (w3(l, (p - l -3))) tickles a gcc bug:
// For some reason, the p++ causes d to decrease by one each time.
// perhaps it's trying to reuse a register, and is offsetting it? perhaps my bug?


size_t make_client_hello(uint8_t *random, uint8_t **client_hello);

size_t receive_tls_record(int sock, uint8_t **record);
size_t get_tls_record(struct evbuffer *input, uint8_t **record);

int parse_server_hello(uint8_t *server_hello, size_t len, struct server_hello *sh);

int parse_tls_extensions(struct server_hello *sh);


int parse_server_keyex(uint8_t *server_keyx, size_t len, uint16_t cipher_suite,
                    struct server_keyx *sk);





#endif


