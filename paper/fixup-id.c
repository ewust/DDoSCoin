
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <string.h>

// Increment a 32-nibble hex number at offset
void increment(uint8_t *data, size_t offset)
{
    offset += 31;

    while (1) {
        data[offset]++;


        if (data[offset] > '9' && data[offset] < 'A') {
            data[offset] = 'A';
        }

        if (data[offset] > 'F') {
            data[offset] = '0';
            offset--;
        } else {
            break;
        }
    }
}

// For some reason, memmem doesn't want to work on my system :(
// So I implement a naive version here.
void *my_memmem(void *haystack, size_t haystack_len, void *needle, size_t needle_len)
{
    size_t i = 0;
    uint8_t *p = haystack;
    while (i < haystack_len - needle_len) {
        if (memcmp(p++, needle, needle_len) == 0) {
            return (p - 1);
        }
        i++;
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    uint8_t *data;

    FILE *f = fopen(argv[1], "r");
    fseek(f, 0L, SEEK_END);
    size_t sz = ftell(f);
    data = malloc(sz);
    rewind(f);
    fread(data, sz, 1, f);
    fclose(f);
    printf("Read %zu bytes\n", sz);


    // Find "/ID [<"
    char *str = "/ID [<";
    uint8_t *offset = my_memmem(data, sz, str, strlen(str));
    printf("data: %p, str: %p, offset: %p\n", data, str, offset);
    uint8_t *offset2 = my_memmem(offset, sz - (offset - data), ">]", 2);


    size_t offset_n1 = (offset - data) + 6;
    size_t offset_n2 = offset_n1 + 35;

    printf("offset 1: %zu, offset 2: %zu\n", offset_n1, offset_n2);
    uint8_t md[SHA_DIGEST_LENGTH];

    uint8_t min_md[SHA_DIGEST_LENGTH];
    SHA1(data, sz, min_md);
    size_t i = 0;

    int j;
    for (j=0; j<SHA_DIGEST_LENGTH; j++) {
        printf("%02x", min_md[j]);
    }
    printf("\n");
    while (1) {
        i++;
        //printf("%zu\n", i);
        increment(data, offset_n1);
        increment(data, offset_n2);

        SHA1(data, sz, md);
        if (memcmp(md, min_md, SHA_DIGEST_LENGTH) < 0) {

            for (j=0; j<SHA_DIGEST_LENGTH; j++) {
                printf("%02x", md[j]);
            }
            printf(" found after %zu iterations\n", i);
            memcpy(min_md, md, SHA_DIGEST_LENGTH);

            f = fopen(argv[1], "w");
            fwrite(data, sz, 1, f);
            fclose(f);
        }

    }

    //*/
}
