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

static int multi_calls;
static int fake_multi_resolver(const char *host, uint32_t *addrs, size_t cap, size_t *count) {
    (void)host;
    multi_calls++;
    static const uint32_t list[] = {0x01010101u, 0x02020202u, 0x03030303u, 0x04040404u, 0x05050505u};
    size_t n = sizeof list / sizeof list[0];
    if (n > cap) n = cap;
    memcpy(addrs, list, n * sizeof(uint32_t));
    *count = n;
    return WTLS_OK;
}

static void test_multi_ip_commit_keeps_working(void) {
    wtls_dns_clear();
    wtls_dns_set_resolver_all(fake_multi_resolver);
    multi_calls = 0;

    uint32_t addrs[WTLS_DNS_MAX_ADDRS];
    size_t count = 0;
    bool from_cache = true;
    CHECK_EQ_INT(wtls_dns_lookup_list("Multi.Test", addrs, &count, &from_cache, 10), WTLS_OK);
    CHECK(!from_cache);
    CHECK_EQ_INT(count, WTLS_DNS_MAX_ADDRS);
    CHECK_EQ_INT(multi_calls, 1);

    /* Not committed yet: a second lookup queries the resolver again. */
    CHECK_EQ_INT(wtls_dns_lookup_list("multi.test", addrs, &count, &from_cache, 11), WTLS_OK);
    CHECK(!from_cache);
    CHECK_EQ_INT(multi_calls, 2);

    /* Commit the 3rd IP (0x03030303): cached lookup now returns only that working IP. */
    wtls_dns_commit("multi.test", addrs[2], 12);
    CHECK_EQ_INT(wtls_dns_lookup_list("MULTI.TEST", addrs, &count, &from_cache, 13), WTLS_OK);
    CHECK(from_cache);
    CHECK_EQ_INT(count, 1);
    CHECK(addrs[0] == 0x03030303u);
    CHECK_EQ_INT(multi_calls, 2);

    wtls_dns_set_resolver_all(NULL);
}

int main(void) {
    RUN(test_cache_hit_skips_resolver);
    RUN(test_ttl_expiry_requeries);
    RUN(test_invalidate_requeries);
    RUN(test_ip_literal_bypasses_resolver);
    RUN(test_failure_not_cached);
    RUN(test_full_cache_evicts_lru);
    RUN(test_multi_ip_commit_keeps_working);
    return CHECK_DONE();
}
