// crc8_stdin_demo.c
// Read hex bytes from STDIN, compute CRC-8 (poly=0x07), and optionally trace.
// Examples:
//   echo "A4 C9 9B" | ./crc8_stdin_demo
//   echo "0xA4 0xc9 9b" | ./crc8_stdin_demo -v
//   echo "A4 C9 9B" | ./crc8_stdin_demo -vv

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define CRC8_POLY   0x07u   // x^8 + x^2 + x + 1 (top bit implicit)
#define CRC8_INIT   0x00u
#define CRC8_XOROUT 0x00u

static void print_bits8(const char *label, uint8_t x) {
    if (label && *label) fputs(label, stdout);
    fputs("0b", stdout);
    for (int i = 7; i >= 0; --i) putchar((x & (1u << i)) ? '1' : '0');
    printf(" (0x%02X)\n", x);
}

static uint8_t crc8_update_verbose(uint8_t crc, uint8_t data, int verbosity, size_t idx) {
    // verbosity: 0 = silent, 1 = per-byte header, 2 = bit-by-bit trace
    if (verbosity >= 1) {
        printf("\n-- Byte %zu -------------------------------------------------\n", idx);
        print_bits8("Data:          ", data);
        print_bits8("CRC(before):   ", crc);
        puts("Mix in next byte: CRC ^= data");
    }

    crc ^= data;

    if (verbosity >= 1) {
        print_bits8("CRC after XOR: ", crc);
        printf("POLY: 0x%02X (MSB-first; XOR when outgoing MSB was 1)\n", CRC8_POLY);
        if (verbosity >= 2) puts("Bit-by-bit steps:");
    }

    for (int i = 0; i < 8; ++i) {
        uint8_t msb = (crc & 0x80u) ? 1u : 0u; // outgoing bit before shift
        crc <<= 1;                              // shift (multiply by x)
        if (msb) crc ^= CRC8_POLY;              // XOR "subtract" polynomial (GF(2))
        if (verbosity >= 2) {
            printf("  bit %d: msb=%u → ", i, msb);
            print_bits8("CRC: ", crc);
        }
    }

    // xorout == 0x00 here; kept for completeness
    return (uint8_t)(crc ^ CRC8_XOROUT);
}

static uint8_t crc8_stream(const uint8_t *buf, size_t len, int verbosity) {
    uint8_t crc = CRC8_INIT;
    for (size_t i = 0; i < len; ++i) {
        int v = 0;
        if (verbosity >= 2) v = 2;            // -vv : trace every bit for every byte
        else if (verbosity == 1) v = (i == 0) ? 2 : 1; // -v : full trace for first byte, per-byte headers for rest
        crc = crc8_update_verbose(crc, buf[i], v, i);
    }
    return (uint8_t)(crc ^ CRC8_XOROUT);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-q|-v|-vv]\n"
        "Reads hex bytes from STDIN (e.g., \"A4 C9 9B\" or \"0xA4 0xC9 9B\").\n"
        "Options:\n"
        "  -q    Quiet (just final CRC and verification)\n"
        "  -v    Verbose (trace first byte bit-by-bit, headers for others)\n"
        "  -vv   Very verbose (bit-by-bit for all bytes)\n", prog);
}

int main(int argc, char **argv) {
    int verbosity = 0;  // 0 quietish, 1 verbose, 2 very-verbose
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-q"))  verbosity = -1;
        else if (!strcmp(argv[i], "-v"))  verbosity = 1;
        else if (!strcmp(argv[i], "-vv")) verbosity = 2;
        else { usage(argv[0]); return 1; }
    }

    // Read tokens from STDIN and parse as hex bytes.
    // Accepts forms like "A4", "a4", "0xA4".
    size_t cap = 32, n = 0;
    uint8_t *bytes = (uint8_t*)malloc(cap);
    if (!bytes) { perror("malloc"); return 1; }

    char tok[256];
    while (fscanf(stdin, "%255s", tok) == 1) {
        char *p = tok;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        char *end = NULL;
        unsigned long val = strtoul(p, &end, 16);
        if (end == p || val > 0xFFUL) {
            fprintf(stderr, "Skipping invalid token: '%s'\n", tok);
            continue;
        }
        if (n == cap) {
            cap = cap * 2;
            uint8_t *tmp = (uint8_t*)realloc(bytes, cap);
            if (!tmp) { perror("realloc"); free(bytes); return 1; }
            bytes = tmp;
        }
        bytes[n++] = (uint8_t)val;
    }

    if (n == 0) {
        usage(argv[0]);
        free(bytes);
        return 1;
    }

    if (verbosity >= 0) {
        printf("CRC-8 Demo  |  width=8, poly=0x%02X, init=0x%02X, xorout=0x%02X, refin=false, refout=false\n",
               CRC8_POLY, CRC8_INIT, CRC8_XOROUT);
        printf("Streaming: yes (byte-by-byte)\n");
        printf("Input bytes (%zu): ", n);
        for (size_t i = 0; i < n; ++i) printf("%02X%s", bytes[i], (i+1<n)?" ":"");
        puts("");
    }

    // 1) Sender computes CRC over input
    uint8_t crc = crc8_stream(bytes, n, verbosity > 0 ? verbosity : 0);

    if (verbosity >= 0) {
        printf("\nCRC-8(message) = 0x%02X\n", crc);
        puts("\nVerification: run CRC over data || CRC → expect remainder 0x00 (for these parameters).");
    }

    // 2) Receiver verification: CRC over (data + CRC) should be 0
    uint8_t *verify = (uint8_t*)malloc(n + 1);
    if (!verify) { perror("malloc"); free(bytes); return 1; }
    memcpy(verify, bytes, n);
    verify[n] = crc;

    uint8_t ok = crc8_stream(verify, n + 1, (verbosity >= 2) ? 1 : 0); // keep verification trace minimal
    printf("CRC-8(data || crc) = 0x%02X%s\n", ok, (ok == 0x00 ? "  (no detected error)" : "  (non-zero → error detected)"));

    // 3) Optional quick demo: flip one bit (if at least 2 bytes present)
    if (n >= 2 && verbosity >= 0) {
        verify[1] ^= 0x01;
        uint8_t bad = crc8_stream(verify, n + 1, 0);
        printf("After bit flip:  CRC-8(data' || crc) = 0x%02X (non-zero → error detected)\n", bad);
    }

    free(verify);
    free(bytes);
    return 0;
}

