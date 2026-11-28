#include <stdio.h>
#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "plat/plat.h"
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

/* ---- asynchronous lookups ------------------------------------------------- */

#include <time.h>

static volatile int slow_ms = 200;
static volatile int slow_calls;

static void nap(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static int slow_resolver_all(const char *host, uint32_t *addrs, size_t cap, size_t *count) {
    __sync_fetch_and_add(&slow_calls, 1);
    nap(slow_ms);
    if (strcmp(host, "fail.test") == 0) return WTLS_ERR_DNS;
    if (cap < 2) return WTLS_ERR_DNS;
    addrs[0] = 0x0a000001u;
    addrs[1] = 0x0a000002u;
    *count = 2;
    return WTLS_OK;
}

static void noop_job(void *p) { (void)p; }

/* true if this platform has helper threads (not the Wii, not Windows hosts: lookups run inline there). */
static bool have_threads(void) { return wtls_plat_async_run(noop_job, NULL) == WTLS_OK; }

static void async_setup(int ms) {
    wtls_dns_clear();
    wtls_dns_set_resolver_all(slow_resolver_all);
    slow_ms = ms;
    slow_calls = 0;
}

/* Polls until the job leaves WANT_READ or a second passed. */
static int wait_job(int job, uint32_t addrs[WTLS_DNS_MAX_ADDRS], size_t *count) {
    for (int i = 0; i < 1000; i++) {
        int r = wtls_dns_job_poll(job, addrs, count);
        if (r != WTLS_WANT_READ) return r;
        nap(1);
    }
    return WTLS_WANT_READ;
}

static void test_dns_async_begin_poll_ok(void) {
    if (!have_threads()) {
        SKIP("no helper threads on this platform");
        return;
    }
    async_setup(200);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n = 0;
    bool cached = true;
    int job = -5;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK_EQ_INT(wtls_dns_lookup_begin("slow.test", &job, a, &n, &cached, 0), WTLS_WANT_READ);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < 100); /* begin does not wait */
    CHECK(job >= 0 && !cached);
    CHECK_EQ_INT(wtls_dns_job_poll(job, a, &n), WTLS_WANT_READ);
    CHECK_EQ_INT(wait_job(job, a, &n), WTLS_OK);
    CHECK_EQ_INT((int)n, 2);
    CHECK_EQ_INT((long long)a[0], 0x0a000001);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= 150);
    CHECK_EQ_INT(wtls_dns_job_poll(job, a, &n), WTLS_ERR_ARG); /* the slot was released */
}

static void test_dns_async_cache_hit_and_literal_immediate(void) {
    if (!have_threads()) {
        SKIP("no helper threads on this platform");
        return;
    }
    async_setup(200);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n = 0;
    bool cached = false;
    int job = -5;
    wtls_dns_commit("hit.test", 0x01010101u, 100);
    CHECK_EQ_INT(wtls_dns_lookup_begin("HIT.test", &job, a, &n, &cached, 200), WTLS_OK);
    CHECK_EQ_INT(job, -1);
    CHECK(cached && n == 1 && a[0] == 0x01010101u);
    CHECK_EQ_INT(wtls_dns_lookup_begin("10.1.2.3", &job, a, &n, &cached, 200), WTLS_OK);
    CHECK_EQ_INT(job, -1);
    CHECK_EQ_INT(slow_calls, 0);
}

static void test_dns_async_failure_and_not_cached(void) {
    if (!have_threads()) {
        SKIP("no helper threads on this platform");
        return;
    }
    async_setup(20);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n = 0;
    bool cached;
    int job;
    CHECK_EQ_INT(wtls_dns_lookup_begin("fail.test", &job, a, &n, &cached, 0), WTLS_WANT_READ);
    CHECK_EQ_INT(wait_job(job, a, &n), WTLS_ERR_DNS);
    /* a successful asynchronous answer is not cached either (commit does that after a connect) */
    CHECK_EQ_INT(wtls_dns_lookup_begin("ok.test", &job, a, &n, &cached, 0), WTLS_WANT_READ);
    CHECK_EQ_INT(wait_job(job, a, &n), WTLS_OK);
    CHECK_EQ_INT(wtls_dns_lookup_begin("ok.test", &job, a, &n, &cached, 1), WTLS_WANT_READ);
    wtls_dns_job_cancel(job);
    nap(100);
}

static void test_dns_async_cancel_frees_the_slot(void) {
    if (!have_threads()) {
        SKIP("no helper threads on this platform");
        return;
    }
    async_setup(150);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n = 0;
    bool cached;
    int jobs[WTLS_DNS_JOBS];
    char name[32];
    for (int i = 0; i < WTLS_DNS_JOBS; i++) {
        snprintf(name, sizeof name, "h%d.test", i);
        CHECK_EQ_INT(wtls_dns_lookup_begin(name, &jobs[i], a, &n, &cached, 0), WTLS_WANT_READ);
    }
    int extra;
    CHECK_EQ_INT(wtls_dns_lookup_begin("extra.test", &extra, a, &n, &cached, 0), WTLS_ERR_DNS); /* table full */
    for (int i = 0; i < WTLS_DNS_JOBS; i++) wtls_dns_job_cancel(jobs[i]);
    CHECK_EQ_INT(wtls_dns_lookup_begin("extra.test", &extra, a, &n, &cached, 0), WTLS_ERR_DNS); /* still running in the background */
    nap(400);
    CHECK_EQ_INT(wtls_dns_lookup_begin("extra.test", &extra, a, &n, &cached, 0), WTLS_WANT_READ); /* slots came back */
    CHECK_EQ_INT(wait_job(extra, a, &n), WTLS_OK);
}

static void test_dns_async_result_dropped_after_net_reset(void) {
    if (!have_threads()) {
        SKIP("no helper threads on this platform");
        return;
    }
    async_setup(100);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n = 0;
    bool cached;
    int job;
    CHECK_EQ_INT(wtls_dns_lookup_begin("moved.test", &job, a, &n, &cached, 0), WTLS_WANT_READ);
    wtls_dns_clear(); /* the network changed while the lookup ran */
    CHECK_EQ_INT(wait_job(job, a, &n), WTLS_ERR_DNS); /* its answer belongs to the old network */
}

static void test_dns_async_bad_args(void) {
    async_setup(1);
    uint32_t a[WTLS_DNS_MAX_ADDRS];
    size_t n;
    bool cached;
    int job;
    CHECK_EQ_INT(wtls_dns_lookup_begin(NULL, &job, a, &n, &cached, 0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_dns_job_poll(-1, a, &n), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_dns_job_poll(WTLS_DNS_JOBS, a, &n), WTLS_ERR_ARG);
    wtls_dns_job_cancel(99); /* harmless */
}

int main(void) {
    RUN(test_cache_hit_skips_resolver);
    RUN(test_ttl_expiry_requeries);
    RUN(test_invalidate_requeries);
    RUN(test_ip_literal_bypasses_resolver);
    RUN(test_failure_not_cached);
    RUN(test_full_cache_evicts_lru);
    RUN(test_multi_ip_commit_keeps_working);
    RUN(test_dns_async_begin_poll_ok);
    RUN(test_dns_async_cache_hit_and_literal_immediate);
    RUN(test_dns_async_failure_and_not_cached);
    RUN(test_dns_async_cancel_frees_the_slot);
    RUN(test_dns_async_result_dropped_after_net_reset);
    RUN(test_dns_async_bad_args);
    return CHECK_DONE();
}
