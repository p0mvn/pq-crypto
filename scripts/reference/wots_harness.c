#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wots.h"

enum { N = 32, LEN = 67, BYTES = N * LEN };

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

static void read_hex(const char *directory, const char *name, unsigned char out[BYTES]) {
    char path[4096];
    require(snprintf(path, sizeof(path), "%s/%s", directory, name) < (int)sizeof(path), "path too long");
    FILE *file = fopen(path, "r");
    require(file != NULL, path);
    for (size_t i = 0; i < BYTES; i++) {
        unsigned int value;
        require(fscanf(file, "%2x", &value) == 1, "fixture too short or invalid");
        out[i] = (unsigned char)value;
    }
    int c;
    do { c = fgetc(file); } while (c == '\n' || c == '\r' || c == ' ' || c == '\t');
    require(c == EOF, "fixture contains trailing content");
    fclose(file);
}

int main(int argc, char **argv) {
    require(argc == 2 || argc == 3, "usage: check_reference fixtures [Rust-signatures]");
    xmss_params params = {0};
    params.func = XMSS_SHA2;
    params.n = N;
    params.padding_len = N;
    params.wots_w = 16;
    params.wots_log_w = 4;
    params.wots_len1 = 64;
    params.wots_len2 = 3;
    params.wots_len = LEN;
    params.wots_sig_bytes = BYTES;
    unsigned char secret[N], public_seed[N], expected[BYTES], pk[BYTES];
    for (int i = 0; i < N; i++) { secret[i] = i; public_seed[i] = 31-i; }
    uint32_t addr[8] = {0};
    wots_pkgen(&params, pk, secret, public_seed, addr);
    read_hex(argv[1], "verifying_key_endpoints.hex", expected);
    require(memcmp(pk, expected, BYTES) == 0, "C public endpoints differ from saved endpoints");
    puts("PASS: all 67 C-generated public endpoints match saved fixtures");
    const char *names[] = {"zero", "maximum", "patterned", "mixed", "alternating"};
    unsigned char digests[5][N] = {{0}};
    for (int i = 0; i < N; i++) {
        digests[1][i] = 255; digests[2][i] = i;
        digests[3][i] = 0xa7; digests[4][i] = 0x0f;
    }
    for (int test = 0; test < 5; test++) {
        char name[128];
        unsigned char signature[BYTES], fixture[BYTES], reconstructed[BYTES];
        snprintf(name, sizeof(name), "signature_%s.hex", names[test]);
        read_hex(argv[1], name, fixture);
        memset(addr, 0, sizeof(addr));
        wots_sign(&params, signature, digests[test], secret, public_seed, addr);
        require(memcmp(signature, fixture, BYTES) == 0, "C signature differs from saved signature");
        /* Reconstruction is the unmodified reference wots_pk_from_sig. */
        memset(addr, 0, sizeof(addr));
        wots_pk_from_sig(&params, reconstructed, fixture, digests[test], public_seed, addr);
        require(memcmp(reconstructed, expected, BYTES) == 0, "C reconstruction differs from expected key");
        if (argc == 3) {
            unsigned char rust_signature[BYTES];
            read_hex(argv[2], name, rust_signature);
            require(memcmp(rust_signature, signature, BYTES) == 0, "Rust signature differs from C signature");
            memset(addr, 0, sizeof(addr));
            wots_pk_from_sig(&params, reconstructed, rust_signature, digests[test], public_seed, addr);
            require(memcmp(reconstructed, expected, BYTES) == 0, "C reconstruction of Rust signature failed");
        }
        for (int message = 0; message < 5; message++) {
            memset(addr, 0, sizeof(addr));
            wots_pk_from_sig(&params, reconstructed, fixture, digests[message], public_seed, addr);
            require((memcmp(reconstructed, expected, BYTES) == 0) == (test == message), "C cross-digest result incorrect");
        }
        fixture[0] ^= 1;
        memset(addr, 0, sizeof(addr));
        wots_pk_from_sig(&params, reconstructed, fixture, digests[test], public_seed, addr);
        require(memcmp(reconstructed, expected, BYTES) != 0, "C accepted altered signature");
        printf("PASS: %s: 67 signature elements, reconstruction, five digests, tampering%s\n", names[test], argc == 3 ? ", direct Rust signature" : "");
    }
    return 0;
}
