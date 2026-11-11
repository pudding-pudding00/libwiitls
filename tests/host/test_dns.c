#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_dns.h"

WTLS_CHECK_DEFINE_COUNTERS;

static int calls;
static int fake_resolver(const char *host, uint32_t *ip) {
    calls++;
    if (strcmp(host, "fail.test") == 0) return WTLS_ERR_DNS;
    *ip = 0x01020304u + (uint32_t)calls;
    return WTLS_OK;
}

static void setup(void) {
    wtls_dns_clear();
    wtls_dns_set_resolver(fake_resolver);
    calls = 0;
}

static void test_cache_hit_skips_resolver(void) {
    setup();
    uint32_t a = 0, b = 0;
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, 0), WTLS_OK);
    CHECK_EQ_INT(wtls_dns_lookup("X.TEST", &b, 10), WTLS_OK);
    CHECK_EQ_INT(calls, 1);
    CHECK_EQ_INT(a, b);
}

static void test_ttl_expiry_requeries(void) {
    setup();
    uint32_t a;
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, 0), WTLS_OK);
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, WTLS_DNS_TTL_MS - 1), WTLS_OK);
    CHECK_EQ_INT(calls, 1);
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, WTLS_DNS_TTL_MS + 1), WTLS_OK);
    CHECK_EQ_INT(calls, 2);
}

static void test_invalidate_requeries(void) {
    setup();
    uint32_t a;
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, 0), WTLS_OK);
    wtls_dns_invalidate("X.test");
    CHECK_EQ_INT(wtls_dns_lookup("x.test", &a, 1), WTLS_OK);
    CHECK_EQ_INT(calls, 2);
}

static void test_ip_literal_bypasses_resolver(void) {
    setup();
    uint32_t a = 0;
    CHECK_EQ_INT(wtls_dns_lookup("10.0.0.1", &a, 0), WTLS_OK);
    CHECK_EQ_INT(calls, 0);
    const uint8_t *p = (const uint8_t *)&a;
    CHECK(p[0] == 10 && p[1] == 0 && p[2] == 0 && p[3] == 1);
}

static void test_failure_not_cached(void) {
    setup();
    uint32_t a;
    CHECK_EQ_INT(wtls_dns_lookup("fail.test", &a, 0), WTLS_ERR_DNS);
    CHECK_EQ_INT(wtls_dns_lookup("fail.test", &a, 1), WTLS_ERR_DNS);
    CHECK_EQ_INT(calls, 2);
}

static void test_full_cache_evicts_lru(void) {
    setup();
    char h[32];
    uint32_t a;
    for (int i = 0; i < WTLS_DNS_SLOTS; i++) {
        snprintf(h, sizeof h, "h%d.test", i);
        CHECK_EQ_INT(wtls_dns_lookup(h, &a, (uint64_t)i), WTLS_OK);
    }
    CHECK_EQ_INT(wtls_dns_lookup("h0.test", &a, 100), WTLS_OK); /* h0 now most recent */
    CHECK_EQ_INT(wtls_dns_lookup("new.test", &a, 101), WTLS_OK); /* evicts h1 */
    int before = calls;
    CHECK_EQ_INT(wtls_dns_lookup("h0.test", &a, 102), WTLS_OK);
    CHECK_EQ_INT(calls, before);
    CHECK_EQ_INT(wtls_dns_lookup("h1.test", &a, 103), WTLS_OK);
    CHECK_EQ_INT(calls, before + 1);
}

int main(void) {
    RUN(test_cache_hit_skips_resolver);
    RUN(test_ttl_expiry_requeries);
    RUN(test_invalidate_requeries);
    RUN(test_ip_literal_bypasses_resolver);
    RUN(test_failure_not_cached);
    RUN(test_full_cache_evicts_lru);
    return CHECK_DONE();
}
