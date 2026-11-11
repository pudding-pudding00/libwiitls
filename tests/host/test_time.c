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

int main(void) {
    RUN(test_time_check_bounds);
    RUN(test_sntp_request_layout);
    RUN(test_sntp_parse_valid);
    RUN(test_sntp_parse_era1);
    RUN(test_sntp_parse_rejects);
    RUN(test_unix_time_offset);
    return CHECK_DONE();
}
