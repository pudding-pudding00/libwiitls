#include <stdint.h>
#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_time.h"

WTLS_CHECK_DEFINE_COUNTERS;

#define YEAR_S (365LL * 86400)

static void test_time_check_bounds(void) {
    int64_t b = wtls_time_build();
    CHECK(b > 1700000000); /* sanity: configured at build time */
    CHECK_EQ_INT(wtls_time_check(b - 86400), WTLS_OK);
    CHECK_EQ_INT(wtls_time_check(b - 86401), WTLS_ERR_CLOCK);
    CHECK_EQ_INT(wtls_time_check(946684800), WTLS_ERR_CLOCK);
    CHECK_EQ_INT(wtls_time_check(b + 20 * YEAR_S), WTLS_ERR_CLOCK);
    CHECK_EQ_INT(wtls_time_check(b + 20 * YEAR_S - 1), WTLS_OK);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static const uint64_t NONCE = 0x0123456789ABCDEFull;

static void test_sntp_request_layout(void) {
    uint8_t req[48];
    memset(req, 0xEE, sizeof req);
    CHECK_EQ_INT(wtls_sntp_build_request(req, NONCE), 48);
    CHECK_EQ_INT(req[0], 0x23);
    CHECK_MEM(req + 40, "\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8);
    uint8_t zero[39] = {0};
    CHECK_MEM(req + 1, zero, 39);
}

/* Server reply: LI 0, VN 4, mode 4, stratum 2, originate = nonce, transmit = secs. */
static void make_reply(uint8_t pkt[48], uint32_t secs) {
    memset(pkt, 0, 48);
    pkt[0] = 0x24;
    pkt[1] = 2;
    put_be32(pkt + 24, (uint32_t)(NONCE >> 32));
    put_be32(pkt + 28, (uint32_t)NONCE);
    put_be32(pkt + 40, secs);
    put_be32(pkt + 44, 0x80000000u);
}

static void test_sntp_parse_valid(void) {
    uint8_t pkt[48];
    make_reply(pkt, 3912345600u);
    int64_t t = 0;
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_OK);
    CHECK_EQ_INT(t, 1703356800);
}

/* NTP era 1 (after 2036-02-07): seconds wrap below 2^31. */
static void test_sntp_parse_era1(void) {
    uint8_t pkt[48];
    make_reply(pkt, 1000u);
    int64_t t = 0;
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_OK);
    CHECK_EQ_INT(t, 4294967296LL + 1000 - 2208988800LL);
}

static void test_sntp_parse_rejects(void) {
    uint8_t pkt[48];
    int64_t t;
    make_reply(pkt, 3912345600u);
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE ^ 1, &t), WTLS_ERR_IO);
    make_reply(pkt, 3912345600u);
    pkt[0] = 0x23; /* mode 3 */
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_ERR_IO);
    make_reply(pkt, 3912345600u);
    pkt[1] = 0; /* stratum 0 (kiss-o'-death) */
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_ERR_IO);
    make_reply(pkt, 3912345600u);
    pkt[1] = 16;
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_ERR_IO);
    make_reply(pkt, 3912345600u);
    pkt[0] = 0xE4; /* LI 3: unsynchronized */
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_ERR_IO);
    make_reply(pkt, 3912345600u);
    CHECK_EQ_INT(wtls_sntp_parse(pkt, 47, NONCE, &t), WTLS_ERR_IO);
    make_reply(pkt, 0);
    pkt[44] = 0; /* transmit timestamp == 0 */
    CHECK_EQ_INT(wtls_sntp_parse(pkt, sizeof pkt, NONCE, &t), WTLS_ERR_IO);
}

static void test_unix_time_offset(void) {
    int64_t a = wtls_plat_unix_time();
    wtls_plat_set_unix_time_offset(3600);
    int64_t b = wtls_plat_unix_time();
    wtls_plat_set_unix_time_offset(0);
    CHECK(b - a >= 3599 && b - a <= 3601);
    mbedtls_time_t m = 0;
    CHECK(wtls_mbedtls_time(&m) == m);
    CHECK(m - wtls_plat_unix_time() <= 1 && wtls_plat_unix_time() - m <= 1);
}

/* Scripted UDP exchange: plays back one result per call (WTLS_ERR_TIMEOUT,
 * 1 = a stray packet with a wrong nonce, 2 = the valid reply). */
typedef struct {
    int script[4];
    int calls;
    uint32_t timeouts[4];
} fake_udp;

static int fake_exchange(void *ctx, uint32_t ip, uint16_t port, const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t cap, uint32_t timeout_ms) {
    fake_udp *f = ctx;
    (void)ip;
    (void)req;
    (void)req_len;
    CHECK_EQ_INT(port, 123);
    CHECK(cap >= 48);
    f->timeouts[f->calls] = timeout_ms;
    int s = f->script[f->calls++];
    if (s < 0) return s;
    make_reply(resp, 3912345600u);
    if (s == 1) resp[24] ^= 0xFF; /* originate != nonce */
    return 48;
}

/* One lost UDP packet must not fail the sync: up to 3 attempts share the timeout. */
static void test_sntp_query_retries_lost_packet(void) {
    fake_udp f = {{WTLS_ERR_TIMEOUT, 1, 2, 2}, 0, {0}};
    int64_t t = 0;
    CHECK_EQ_INT(wtls_sntp_query(fake_exchange, &f, 0x01020304u, NONCE, 3000, &t), WTLS_OK);
    CHECK_EQ_INT(t, 1703356800);
    CHECK_EQ_INT(f.calls, 3);
    CHECK_EQ_INT(f.timeouts[0], 1000);
    CHECK_EQ_INT(f.timeouts[2], 1000);
}

static void test_sntp_query_gives_up_after_3(void) {
    fake_udp f = {{WTLS_ERR_TIMEOUT, WTLS_ERR_TIMEOUT, WTLS_ERR_TIMEOUT, 2}, 0, {0}};
    int64_t t = 0;
    CHECK_EQ_INT(wtls_sntp_query(fake_exchange, &f, 1, NONCE, 300, &t), WTLS_ERR_TIMEOUT);
    CHECK_EQ_INT(f.calls, 3);
    fake_udp g = {{1, 1, 1, 2}, 0, {0}};
    CHECK_EQ_INT(wtls_sntp_query(fake_exchange, &g, 1, NONCE, 300, &t), WTLS_ERR_IO);
    fake_udp h = {{WTLS_ERR_IO, 2, 2, 2}, 0, {0}}; /* hard socket error: no retry */
    CHECK_EQ_INT(wtls_sntp_query(fake_exchange, &h, 1, NONCE, 300, &t), WTLS_ERR_IO);
    CHECK_EQ_INT(h.calls, 1);
    fake_udp k = {{WTLS_ERR_TIMEOUT, 2, 2, 2}, 0, {0}}; /* tiny timeout: >= 1 ms each */
    CHECK_EQ_INT(wtls_sntp_query(fake_exchange, &k, 1, NONCE, 2, &t), WTLS_OK);
    CHECK_EQ_INT(k.timeouts[0], 1);
}

/* SNTP needs PSA (nonce); without wtls_init nobody would free that state. */
static void test_sntp_needs_init(void) {
    CHECK_EQ_INT(wtls_time_sync_sntp("127.0.0.1", 100), WTLS_ERR_STATE);
}

int main(void) {
    RUN(test_sntp_needs_init);
    RUN(test_time_check_bounds);
    RUN(test_sntp_request_layout);
    RUN(test_sntp_parse_valid);
    RUN(test_sntp_parse_era1);
    RUN(test_sntp_parse_rejects);
    RUN(test_unix_time_offset);
    RUN(test_sntp_query_retries_lost_packet);
    RUN(test_sntp_query_gives_up_after_3);
    return CHECK_DONE();
}
