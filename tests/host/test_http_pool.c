/* Keep-alive pool (src/http/wtls_http_pool.c) with fake handles and a counting closer. */
#include <string.h>

#include "check.h"
#include "http/wtls_http_pool.h"

WTLS_CHECK_DEFINE_COUNTERS;

static int s_closed;
static void *s_last_closed;

static void count_close(void *c) {
    s_closed++;
    s_last_closed = c;
}

static void *fake(int i) { return (void *)(uintptr_t)(0x1000 + i); }

static void reset(void) {
    wtls_http_pool_flush();
    s_closed = 0;
    s_last_closed = NULL;
}

static void pool_put_take(void) {
    reset();
    wtls_http_pool_put(fake(1), true, "a", 443, false, 0);
    CHECK(wtls_http_pool_take(true, "a", 443, false, 10) == fake(1));
    CHECK(wtls_http_pool_take(true, "a", 443, false, 10) == NULL);
    CHECK_EQ_INT(s_closed, 0);
}

static void pool_key_mismatch(void) {
    reset();
    wtls_http_pool_put(fake(1), true, "a", 443, false, 0);
    CHECK(wtls_http_pool_take(true, "a", 444, false, 1) == NULL);
    CHECK(wtls_http_pool_take(true, "b", 443, false, 1) == NULL);
    CHECK(wtls_http_pool_take(true, "a", 443, true, 1) == NULL);
    CHECK(wtls_http_pool_take(false, "a", 443, false, 1) == NULL);
    CHECK(wtls_http_pool_take(true, "a", 443, false, 1) == fake(1));
}

static void pool_lifo(void) {
    reset();
    wtls_http_pool_put(fake(1), true, "a", 443, false, 0);
    wtls_http_pool_put(fake(2), true, "a", 443, false, 1);
    CHECK(wtls_http_pool_take(true, "a", 443, false, 2) == fake(2));
    CHECK(wtls_http_pool_take(true, "a", 443, false, 2) == fake(1));
}

static void pool_lru_evicts_oldest(void) {
    reset();
    for (int i = 1; i <= 5; i++) wtls_http_pool_put(fake(i), true, "a", 443, false, (uint64_t)i);
    CHECK_EQ_INT(s_closed, 1);
    CHECK(s_last_closed == fake(1));
    for (int i = 5; i >= 2; i--) CHECK(wtls_http_pool_take(true, "a", 443, false, 10) == fake(i));
    CHECK(wtls_http_pool_take(true, "a", 443, false, 10) == NULL);
}

static void pool_expired_closed(void) {
    reset();
    wtls_http_pool_put(fake(1), true, "a", 443, false, 0);
    CHECK(wtls_http_pool_take(true, "a", 443, false, WTLS_HTTP_POOL_IDLE_MS) == fake(1));
    wtls_http_pool_put(fake(1), true, "a", 443, false, 0);
    CHECK(wtls_http_pool_take(true, "a", 443, false, WTLS_HTTP_POOL_IDLE_MS + 1) == NULL);
    CHECK_EQ_INT(s_closed, 1);
    CHECK(s_last_closed == fake(1));
}

static void pool_flush_closes_all(void) {
    reset();
    for (int i = 1; i <= WTLS_HTTP_POOL_SLOTS; i++) wtls_http_pool_put(fake(i), true, "a", 443, false, 0);
    wtls_http_pool_flush();
    CHECK_EQ_INT(s_closed, WTLS_HTTP_POOL_SLOTS);
    CHECK(wtls_http_pool_take(true, "a", 443, false, 0) == NULL);
}

int main(void) {
    wtls_http_pool_set_closer(count_close);
    RUN(pool_put_take);
    RUN(pool_key_mismatch);
    RUN(pool_lifo);
    RUN(pool_lru_evicts_oldest);
    RUN(pool_expired_closed);
    RUN(pool_flush_closes_all);
    return CHECK_DONE();
}
