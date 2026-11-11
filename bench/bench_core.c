/* libwiitls benchmarks (Task 11). Shared by the Wii DOL (bench/main.c) and the
 * host smoke run (bench/host_main.c). Every value is printed as
 *   BENCH <name> <value> <unit>
 * and every measurement is one RUN(), so a failing operation shows as fail=N.
 * The plan's target values are evaluated at the end as GATE lines; they are
 * informational and never fail the run (the host is not the target).
 *
 * Needs tests/host/tls_test_server.py (--certs) on g_env.server_host. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "bench.h"
#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "rsa_vector.h"

#define RUNS 20
#define BLOCK 16384
#define PLAIN_PORT 4430
#define TLS_PORT 4431
#define STREAM_BYTES (4u * 1024u * 1024u)

/* Results for the gate evaluation (0 = not measured). */
static double s_chacha_mbs, s_x25519_ms, s_hs_full_cpu_ms, s_hs_res_cpu_ms, s_read_ratio;

static uint8_t s_in[BLOCK], s_out[BLOCK + 16];

/* ---- helpers ------------------------------------------------------------ */

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static uint64_t median(uint64_t *v, size_t n) {
    qsort(v, n, sizeof *v, cmp_u64);
    return v[n / 2];
}

static void report(const char *name, double value, const char *unit) {
    /* %.3f via integer parts: newlib-nano builds may lack float printf. */
    long long milli = (long long)(value * 1000.0 + 0.5);
    TLOG("BENCH %s %lld.%03lld %s\n", name, milli / 1000, milli % 1000, unit);
}

static double mbs(uint64_t bytes, uint64_t us) { return us ? (double)bytes / (double)us : 0.0; }

/* ---- symmetric crypto --------------------------------------------------- */

static void bench_sha256(void) {
    uint64_t t[RUNS];
    uint8_t h[32];
    size_t hl;
    for (int i = 0; i < RUNS; i++) {
        uint64_t t0 = wtls_plat_now_us();
        psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, s_in, BLOCK, h, sizeof h, &hl);
        t[i] = wtls_plat_now_us() - t0;
        CHECK_EQ_INT(st, PSA_SUCCESS);
    }
    report("sha256_16k", mbs(BLOCK, median(t, RUNS)), "MB/s");
}

static double bench_aead(psa_key_type_t type, size_t bits, psa_algorithm_t alg) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, type);
    psa_set_key_bits(&a, bits);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&a, alg);
    uint8_t key[32] = {1, 2, 3, 4, 5, 6, 7, 8};
    psa_key_id_t id = 0;
    psa_status_t st = psa_import_key(&a, key, bits / 8, &id);
    CHECK_EQ_INT(st, PSA_SUCCESS);
    if (st != PSA_SUCCESS) return 0.0;
    uint8_t nonce[12] = {0};
    uint64_t t[RUNS];
    for (int i = 0; i < RUNS; i++) {
        size_t ol;
        nonce[0] = (uint8_t)i;
        uint64_t t0 = wtls_plat_now_us();
        st = psa_aead_encrypt(id, alg, nonce, sizeof nonce, NULL, 0, s_in, BLOCK, s_out,
                              sizeof s_out, &ol);
        t[i] = wtls_plat_now_us() - t0;
        CHECK_EQ_INT(st, PSA_SUCCESS);
    }
    psa_destroy_key(id);
    return mbs(BLOCK, median(t, RUNS));
}

static void bench_chacha20_poly1305(void) {
    s_chacha_mbs = bench_aead(PSA_KEY_TYPE_CHACHA20, 256, PSA_ALG_CHACHA20_POLY1305);
    report("chacha20_poly1305_enc_16k", s_chacha_mbs, "MB/s");
}

static void bench_aes128_gcm(void) {
    report("aes128_gcm_enc_16k", bench_aead(PSA_KEY_TYPE_AES, 128, PSA_ALG_GCM), "MB/s");
}

/* ---- public-key crypto -------------------------------------------------- */

static void bench_x25519(void) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&a, 255);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    psa_key_id_t peer = 0;
    uint8_t peer_pub[32];
    size_t pl = 0;
    CHECK_EQ_INT(psa_generate_key(&a, &peer), PSA_SUCCESS);
    CHECK_EQ_INT(psa_export_public_key(peer, peer_pub, sizeof peer_pub, &pl), PSA_SUCCESS);
    psa_destroy_key(peer);
    uint64_t t[RUNS];
    for (int i = 0; i < RUNS; i++) {
        psa_key_id_t id = 0;
        uint8_t shared[32];
        size_t sl;
        /* One TLS 1.3 key exchange: ephemeral keygen + agreement. */
        uint64_t t0 = wtls_plat_now_us();
        psa_status_t st = psa_generate_key(&a, &id);
        if (st == PSA_SUCCESS)
            st = psa_raw_key_agreement(PSA_ALG_ECDH, id, peer_pub, pl, shared, sizeof shared, &sl);
        t[i] = wtls_plat_now_us() - t0;
        CHECK_EQ_INT(st, PSA_SUCCESS);
        psa_destroy_key(id);
    }
    s_x25519_ms = (double)median(t, RUNS) / 1000.0;
    report("x25519_keygen_agree", s_x25519_ms, "ms");
}

static void bench_ecdsa_p256_verify(void) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&a, alg);
    psa_key_id_t id = 0;
    psa_status_t st = psa_generate_key(&a, &id);
    CHECK_EQ_INT(st, PSA_SUCCESS);
    if (st != PSA_SUCCESS) return;
    uint8_t hash[32] = {0x42}, sig[64];
    size_t sl = 0;
    CHECK_EQ_INT(psa_sign_hash(id, alg, hash, sizeof hash, sig, sizeof sig, &sl), PSA_SUCCESS);
    uint64_t t[RUNS];
    for (int i = 0; i < RUNS; i++) {
        uint64_t t0 = wtls_plat_now_us();
        st = psa_verify_hash(id, alg, hash, sizeof hash, sig, sl);
        t[i] = wtls_plat_now_us() - t0;
        CHECK_EQ_INT(st, PSA_SUCCESS);
    }
    psa_destroy_key(id);
    report("ecdsa_p256_verify", (double)median(t, RUNS) / 1000.0, "ms");
}

static void bench_rsa2048_verify(void) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    psa_set_key_type(&a, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&a, alg);
    psa_key_id_t id = 0;
    psa_status_t st = psa_import_key(&a, k_rsa_pub, sizeof k_rsa_pub, &id);
    CHECK_EQ_INT(st, PSA_SUCCESS);
    if (st != PSA_SUCCESS) return;
    uint64_t t[RUNS];
    for (int i = 0; i < RUNS; i++) {
        uint64_t t0 = wtls_plat_now_us();
        st = psa_verify_hash(id, alg, k_rsa_hash, sizeof k_rsa_hash, k_rsa_sig, sizeof k_rsa_sig);
        t[i] = wtls_plat_now_us() - t0;
        CHECK_EQ_INT(st, PSA_SUCCESS);
    }
    psa_destroy_key(id);
    report("rsa2048_verify", (double)median(t, RUNS) / 1000.0, "ms");
}

/* ---- network ------------------------------------------------------------ */

static bool plain_recv_exact(int fd, uint8_t *buf, size_t n, uint64_t deadline_ms) {
    size_t off = 0;
    while (off < n) {
        uint64_t now = wtls_plat_now_ms();
        if (now >= deadline_ms) return false;
        int r = wtls_plat_recv(fd, buf + off, n - off);
        if (r > 0) off += (size_t)r;
        else if (r == WTLS_WANT_READ) wtls_plat_poll(fd, true, false, (uint32_t)(deadline_ms - now));
        else return false;
    }
    return true;
}

static bool plain_send_all(int fd, const char *s) {
    size_t len = strlen(s), off = 0;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    while (off < len && wtls_plat_now_ms() < deadline) {
        int r = wtls_plat_send(fd, (const uint8_t *)s + off, len - off);
        if (r > 0) off += (size_t)r;
        else if (r == WTLS_WANT_WRITE) wtls_plat_poll(fd, false, true, 100);
        else return false;
    }
    return off == len;
}

static int plain_connect(void) {
    uint32_t ip;
    int fd = -1;
    if (wtls_plat_resolve(g_env.server_host, &ip) != WTLS_OK) return -1;
    if (wtls_plat_connect(ip, PLAIN_PORT, 3000, &fd) != WTLS_OK) return -1;
    return fd;
}

/* Fetches test-ca.der over the plain port (command CA) and trusts it. */
static bool trust_test_ca(void) {
    int fd = plain_connect();
    if (fd < 0) return false;
    bool ok = false;
    uint8_t *der = NULL;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    if (plain_send_all(fd, "CA\n")) {
        char line[16] = {0};
        size_t i = 0;
        while (i < sizeof line - 1 && plain_recv_exact(fd, (uint8_t *)&line[i], 1, deadline) &&
               line[i] != '\n')
            i++;
        long len = strtol(line, NULL, 10);
        if (len > 0 && len < 8192 && (der = malloc((size_t)len)) &&
            plain_recv_exact(fd, der, (size_t)len, deadline))
            ok = wtls_add_trusted_ca(der, (size_t)len) == WTLS_OK;
    }
    free(der);
    wtls_plat_close(fd);
    return ok;
}

/* Reads exactly n bytes from a TLS connection. */
static bool tls_read_exact(wtls_conn *c, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = wtls_read(c, buf + off, n - off);
        if (r <= 0) return false;
        off += (size_t)r;
    }
    return true;
}

/* PING round trip; reading also stores the session ticket for resumption. */
static bool ping(wtls_conn *c) {
    uint8_t buf[5];
    return wtls_write(c, "PING\n", 5) == 5 && tls_read_exact(c, buf, 5) && memcmp(buf, "PING\n", 5) == 0;
}

/* Times wtls_connect: wall and CPU (= wall - time blocked in wtls_plat_poll). */
static int timed_connect(wtls_conn **c, const wtls_options *opt, uint64_t *wall_us, uint64_t *cpu_us) {
    uint64_t w0 = wtls_plat_poll_wait_us, t0 = wtls_plat_now_us();
    int r = wtls_connect(c, g_env.server_host, TLS_PORT, opt);
    *wall_us = wtls_plat_now_us() - t0;
    uint64_t waited = wtls_plat_poll_wait_us - w0;
    *cpu_us = *wall_us > waited ? *wall_us - waited : 0;
    return r;
}

static void bench_handshake_full(void) {
    wtls_options opt = {0};
    opt.no_resumption = true;
    uint64_t wall[RUNS], cpu[RUNS];
    for (int i = 0; i < RUNS; i++) {
        wtls_conn *c = NULL;
        int r = timed_connect(&c, &opt, &wall[i], &cpu[i]);
        CHECK_EQ_INT(r, WTLS_OK);
        if (r != WTLS_OK) return;
        wtls_close(c);
    }
    report("handshake_full_wall", (double)median(wall, RUNS) / 1000.0, "ms");
    s_hs_full_cpu_ms = (double)median(cpu, RUNS) / 1000.0;
    report("handshake_full_cpu", s_hs_full_cpu_ms, "ms");
}

static void bench_handshake_resumed(void) {
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, TLS_PORT, NULL), WTLS_OK);
    if (!c) return;
    CHECK(ping(c)); /* primes the ticket cache */
    wtls_close(c);
    uint64_t wall[RUNS], cpu[RUNS];
    for (int i = 0; i < RUNS; i++) {
        c = NULL;
        int r = timed_connect(&c, NULL, &wall[i], &cpu[i]);
        CHECK_EQ_INT(r, WTLS_OK);
        if (r != WTLS_OK) return;
        wtls_conn_info info;
        CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
        CHECK(info.resumed);
        CHECK(ping(c)); /* next ticket for the next round */
        wtls_close(c);
    }
    report("handshake_resumed_wall", (double)median(wall, RUNS) / 1000.0, "ms");
    s_hs_res_cpu_ms = (double)median(cpu, RUNS) / 1000.0;
    report("handshake_resumed_cpu", s_hs_res_cpu_ms, "ms");
}

static uint8_t s_stream[16384];

/* Raw TCP: BIG n on the plain port. Timed from the first byte to the last. */
static uint64_t stream_raw_us(void) {
    int fd = plain_connect();
    CHECK(fd >= 0);
    if (fd < 0) return 0;
    char cmd[32];
    snprintf(cmd, sizeof cmd, "BIG %u\n", STREAM_BYTES);
    CHECK(plain_send_all(fd, cmd));
    uint64_t deadline = wtls_plat_now_ms() + 60000, t0 = 0;
    size_t got = 0;
    while (got < STREAM_BYTES && wtls_plat_now_ms() < deadline) {
        size_t want = STREAM_BYTES - got < sizeof s_stream ? STREAM_BYTES - got : sizeof s_stream;
        int r = wtls_plat_recv(fd, s_stream, want);
        if (r > 0) {
            if (!got) t0 = wtls_plat_now_us();
            got += (size_t)r;
        } else if (r == WTLS_WANT_READ) {
            wtls_plat_poll(fd, true, false, 1000);
        } else {
            break;
        }
    }
    uint64_t dt = wtls_plat_now_us() - t0;
    wtls_plat_close(fd);
    CHECK_EQ_INT(got, STREAM_BYTES);
    return got == STREAM_BYTES ? dt : 0;
}

/* TLS: BIG n on the TLS port through wtls_read. Timed from the first byte. */
static uint64_t stream_tls_us(void) {
    wtls_conn *c = NULL;
    int r = wtls_connect(&c, g_env.server_host, TLS_PORT, NULL);
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return 0;
    char cmd[32];
    int n = snprintf(cmd, sizeof cmd, "BIG %u\n", STREAM_BYTES);
    CHECK_EQ_INT(wtls_write(c, cmd, (size_t)n), n);
    uint64_t t0 = 0;
    size_t got = 0;
    while (got < STREAM_BYTES) {
        r = wtls_read(c, s_stream, sizeof s_stream);
        if (r <= 0) break;
        if (!got) t0 = wtls_plat_now_us();
        got += (size_t)r;
    }
    uint64_t dt = wtls_plat_now_us() - t0;
    wtls_close(c);
    CHECK_EQ_INT(got, STREAM_BYTES);
    return got == STREAM_BYTES ? dt : 0;
}

static void bench_stream_4m(void) {
    /* 3 rounds each, median: the link, not the crypto, dominates the variance. */
    uint64_t raw[3], tls[3];
    for (int i = 0; i < 3; i++) {
        raw[i] = stream_raw_us();
        tls[i] = stream_tls_us();
    }
    double raw_mbs = mbs(STREAM_BYTES, median(raw, 3)), tls_mbs = mbs(STREAM_BYTES, median(tls, 3));
    report("net_recv_4m", raw_mbs, "MB/s");
    report("wtls_read_4m", tls_mbs, "MB/s");
    s_read_ratio = raw_mbs > 0 ? 100.0 * tls_mbs / raw_mbs : 0.0;
    report("wtls_read_vs_raw", s_read_ratio, "%");
}

/* ---- gate --------------------------------------------------------------- */

static void gate(const char *what, double value, bool met) {
    long long milli = (long long)(value * 1000.0 + 0.5);
    TLOG("GATE %-34s %lld.%03lld %s\n", what, milli / 1000, milli % 1000, met ? "met" : "MISSED");
}

static void print_gates(void) {
    /* Targets from the plan (Task 11); Task 12 is due if any is missed on the Wii. */
    gate("handshake_full_cpu <= 30 ms", s_hs_full_cpu_ms, s_hs_full_cpu_ms <= 30.0);
    gate("handshake_resumed_cpu <= 10 ms", s_hs_res_cpu_ms, s_hs_res_cpu_ms <= 10.0);
    gate("chacha20_poly1305 >= 20 MB/s", s_chacha_mbs, s_chacha_mbs >= 20.0);
    gate("x25519 <= 5 ms", s_x25519_ms, s_x25519_ms <= 5.0);
    gate("wtls_read >= 90 % of net_recv", s_read_ratio, s_read_ratio >= 90.0);
}

void wtls_bench_run(void) {
    for (size_t i = 0; i < sizeof s_in; i++) s_in[i] = (uint8_t)i;
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    RUN(bench_sha256);
    RUN(bench_chacha20_poly1305);
    RUN(bench_aes128_gcm);
    RUN(bench_x25519);
    RUN(bench_ecdsa_p256_verify);
    RUN(bench_rsa2048_verify);
    if (trust_test_ca()) {
        RUN(bench_handshake_full);
        RUN(bench_handshake_resumed);
        RUN(bench_stream_4m);
    } else {
        TLOG("cannot fetch the test CA from %s:%d - network benchmarks not run\n",
             g_env.server_host ? g_env.server_host : "-", PLAIN_PORT);
        wtls_t_fail++;
    }
    print_gates();
    wtls_shutdown();
}
