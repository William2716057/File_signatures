//gcc -std=c99 -O2 fileSignatures.c -o fileSig -lm

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
 
#define MAX_FILE_SIZE (512UL * 1024UL * 1024UL)
#define MAP_COLUMNS   64
 
typedef struct {
    const char          *name;
    const unsigned char *magic;
    size_t               len;
} Signature;
 
#define SIG(name, bytes) { name, (const unsigned char *)(bytes), sizeof(bytes) - 1 }
 
//file signatures
static const Signature SIGS[] = {
    SIG("PNG image",        "\x89" "PNG\r\n\x1a\n"),
    SIG("JPEG image",       "\xff\xd8\xff"),
    SIG("GIF image",        "GIF8"),
    SIG("PDF document",     "%PDF-"),
    SIG("ZIP archive",      "PK\x03\x04"),
    SIG("ELF executable",   "\x7f" "ELF"),
    SIG("PE/DOS executable","MZ"),
    SIG("gzip archive",     "\x1f\x8b\x08"),
    SIG("RAR archive",      "Rar!\x1a\x07"),
    SIG("7-Zip archive",    "7z\xbc\xaf\x27\x1c"),
    SIG("BMP image",        "BM"),
    SIG("SQLite database",  "SQLite format 3"),
    SIG("RIFF container",   "RIFF"),
    SIG("Ogg container",    "OggS"),
    SIG("FLAC audio",       "fLaC"),
    SIG("MP3 (ID3 tag)",    "ID3"),
    SIG("TIFF (little-endian)", "II*\x00"),
    SIG("TIFF (big-endian)",    "MM\x00*"),
};
#define NSIGS (sizeof SIGS / sizeof SIGS[0])
 

//loading features
static unsigned char *load_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
 
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { perror("ftell"); fclose(f); return NULL; }
    rewind(f);
 
    if ((unsigned long)size > MAX_FILE_SIZE) {
        fprintf(stderr, "%s: file too large (limit %lu MB)\n", path, MAX_FILE_SIZE >> 20);
        fclose(f);
        return NULL;
    }
 
    unsigned char *buf = malloc(size ? (size_t)size : 1);
    if (!buf) { fprintf(stderr, "out of memory\n"); fclose(f); return NULL; }
 
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) { fprintf(stderr, "%s: short read\n", path); free(buf); return NULL; }
 
    *out_len = got;
    return buf;
}
 

//analyse entropy
static double entropy(const unsigned char *data, size_t len)
{
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
 
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        double p = (double)counts[i] / (double)len;
        h -= p * log2(p);
    }
    return h; /* 0..8 bits per byte */
}
 
static const char *classify_entropy(double h)
{
    if (h > 7.5) return "very high (compressed or encrypted)";
    if (h > 6.5) return "high (packed / dense binary)";
    if (h > 4.5) return "medium (typical code or mixed data)";
    if (h > 2.0) return "low (text or structured data)";
    return "very low (repetitive or padding)";
}
 
//commands
static const Signature *identify(const unsigned char *data, size_t len)
{
    const Signature *best = NULL;
    for (size_t i = 0; i < NSIGS; i++) {
        const Signature *s = &SIGS[i];
        if (len >= s->len && memcmp(data, s->magic, s->len) == 0)
            if (!best || s->len > best->len) best = s;   /* prefer longest match */
    }
    return best;
}
 
static int cmd_info(const char *path)
{
    size_t len;
    unsigned char *data = load_file(path, &len);
    if (!data) return 1;
 
    const Signature *sig = identify(data, len);
    double h = entropy(data, len);
 
    printf("File     : %s\n", path);
    printf("Size     : %zu bytes\n", len);
    printf("Type     : %s\n", sig ? sig->name : "unknown");
    printf("Entropy  : %.3f bits/byte - %s\n", h, classify_entropy(h));
 
    if (len > 0) {
        static const char ramp[] = " .:-=+*#%@";   /* low -> high entropy */
        char row[MAP_COLUMNS + 1];
        size_t cols = len < MAP_COLUMNS ? len : MAP_COLUMNS;
        for (size_t c = 0; c < cols; c++) {
            size_t start = c * len / cols;
            size_t end   = (c + 1) * len / cols;
            double bh = entropy(data + start, end - start);
            int idx = (int)(bh / 8.0 * 9.0 + 0.5);
            if (idx > 9) idx = 9;
            row[c] = ramp[idx];
        }
        row[cols] = '\0';
        printf("Map      : [%s]\n", row);
        printf("           (each column = 1/%zu of file; ' ' low ... '@' high entropy)\n", cols);
    }
 
    free(data);
    return 0;
}
 
static int cmd_hex(const char *path, size_t offset, size_t count, int has_count)
{
    size_t len;
    unsigned char *data = load_file(path, &len);
    if (!data) return 1;
 
    if (offset > len) offset = len;
    size_t end = has_count && offset + count < len ? offset + count : len;
 
    for (size_t pos = offset; pos < end; pos += 16) {
        printf("%08zx  ", pos);
        for (size_t i = 0; i < 16; i++) {
            if (pos + i < end) printf("%02x ", data[pos + i]);
            else               printf("   ");
            if (i == 7) putchar(' ');
        }
        printf(" |");
        for (size_t i = 0; i < 16 && pos + i < end; i++) {
            unsigned char c = data[pos + i];
            putchar(c >= 32 && c < 127 ? c : '.');
        }
        printf("|\n");
    }
 
    free(data);
    return 0;
}
 
static int cmd_scan(const char *path)
{
    size_t len;
    unsigned char *data = load_file(path, &len);
    if (!data) return 1;
 
    size_t hits = 0;
    for (size_t pos = 0; pos < len; pos++) {
        for (size_t i = 0; i < NSIGS; i++) {
            const Signature *s = &SIGS[i];
            if (s->len < 4) continue;               /* too short: noisy in a scan */
            if (pos + s->len > len) continue;
            if (data[pos] != s->magic[0]) continue; /* cheap first-byte filter */
            if (memcmp(data + pos, s->magic, s->len) == 0) {
                printf("0x%08zx  %s\n", pos, s->name);
                hits++;
            }
        }
    }
    printf("%zu signature%s found\n", hits, hits == 1 ? "" : "s");
 
    free(data);
    return 0;
}
 
//entry point
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s info FILE                  identify type, show entropy and entropy map\n"
        "  %s hex  FILE [OFFSET [LEN]]   hex dump (numbers may be decimal or 0x hex)\n"
        "  %s scan FILE                  find embedded file signatures\n",
        prog, prog, prog);
}
 

//main functions
int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 2; }
 
    const char *cmd = argv[1], *path = argv[2];
 
    if (strcmp(cmd, "info") == 0 && argc == 3) return cmd_info(path);
    if (strcmp(cmd, "scan") == 0 && argc == 3) return cmd_scan(path);
    if (strcmp(cmd, "hex") == 0 && argc <= 5) {
        size_t off = argc > 3 ? (size_t)strtoull(argv[3], NULL, 0) : 0;
        size_t cnt = argc > 4 ? (size_t)strtoull(argv[4], NULL, 0) : 0;
        return cmd_hex(path, off, cnt, argc > 4);
    }
 
    usage(argv[0]);
    return 2;
}