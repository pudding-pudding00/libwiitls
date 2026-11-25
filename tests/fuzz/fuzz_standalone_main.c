/* Standalone deterministic regression runner for libFuzzer targets.
 * Feeds every seed file in WTLS_FUZZ_CORPUS_DIR and runs deterministic
 * single-byte/truncate mutations so regular CTest & ASan/UBSan verify all
 * fuzz harnesses even without Clang/libFuzzer. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint32_t s_rng = 0x9e3779b9u;
static uint32_t rnd(void) {
    uint32_t x = s_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return s_rng = x;
}

static void run_with_mutations(const uint8_t *seed, size_t len) {
    LLVMFuzzerTestOneInput(seed, len);
    if (len > 4096) return;
    uint8_t buf[4096];
    for (int m = 0; m < 64; m++) {
        size_t n = len;
        if (n) memcpy(buf, seed, n);
        uint32_t op = rnd() % 4;
        if (op == 0 && n > 0) {
            buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
        } else if (op == 1 && n > 1) {
            n = 1 + (rnd() % n);
        } else if (op == 2 && n < sizeof buf) {
            size_t at = n ? rnd() % n : 0;
            memmove(buf + at + 1, buf + at, n - at);
            buf[at] = (uint8_t)rnd();
            n++;
        } else if (op == 3 && n > 0) {
            size_t at = rnd() % n;
            memmove(buf + at, buf + at + 1, n - at - 1);
            n--;
        }
        LLVMFuzzerTestOneInput(buf, n);
    }
}

static int run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    uint8_t *buf = malloc(sz ? (size_t)sz : 1u);
    if (!buf) {
        fclose(f);
        return 1;
    }
    size_t n = sz ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    run_with_mutations(buf, n);
    free(buf);
    return 0;
}

static int run_dir(const char *dir) {
    int count = 0;
#if defined(_WIN32)
    char pat[1024];
    snprintf(pat, sizeof pat, "%s/*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", dir, fd.cFileName);
        if (run_file(full) == 0) count++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", dir, ent->d_name);
        if (run_file(full) == 0) count++;
    }
    closedir(d);
#endif
    return count;
}

int main(int argc, char **argv) {
    LLVMFuzzerTestOneInput((const uint8_t *)"", 0);
    const char *dir = argc > 1 ? argv[1] : NULL;
#ifdef WTLS_FUZZ_CORPUS_DIR
    if (!dir) dir = WTLS_FUZZ_CORPUS_DIR;
#endif
    if (!dir) {
        fprintf(stderr, "missing corpus directory\n");
        return 1;
    }
    int count = run_dir(dir);
    if (count <= 0) {
        fprintf(stderr, "no corpus files in %s\n", dir);
        return 1;
    }
    printf("WTLS-FUZZ DONE files=%d fail=0\n", count);
    return 0;
}
