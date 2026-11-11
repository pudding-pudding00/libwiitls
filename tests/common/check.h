/* Minimal test framework shared by host and Wii test runners. */
#ifndef WTLS_CHECK_H
#define WTLS_CHECK_H

#include <stdio.h>
#include <string.h>

#ifndef WTLS_TEST_PRINTF
#if defined(GEKKO)
int wtls_hw_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define WTLS_TEST_PRINTF wtls_hw_printf
#else
#define WTLS_TEST_PRINTF printf
#endif
#endif

/* Counters are shared by all suites of one runner: exactly one translation
 * unit per executable writes WTLS_CHECK_DEFINE_COUNTERS at file scope. */
extern int wtls_t_pass;
extern int wtls_t_fail;
extern int wtls_t_cur_failed;
extern int wtls_t_skip;
extern int wtls_t_cur_skipped;
#define WTLS_CHECK_DEFINE_COUNTERS \
    int wtls_t_pass, wtls_t_fail, wtls_t_cur_failed, wtls_t_skip, wtls_t_cur_skipped

/* Formatted log line through the runner's printf (console + TCP log on the Wii). */
#define TLOG(...) WTLS_TEST_PRINTF(__VA_ARGS__)

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            WTLS_TEST_PRINTF("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            wtls_t_cur_failed = 1;                                           \
        }                                                                    \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                   \
    do {                                                                     \
        long long wtls_t_a = (long long)(a), wtls_t_b = (long long)(b);      \
        if (wtls_t_a != wtls_t_b) {                                          \
            WTLS_TEST_PRINTF("  FAIL %s:%d: %s == %s (%lld != %lld)\n",      \
                             __FILE__, __LINE__, #a, #b, wtls_t_a, wtls_t_b); \
            wtls_t_cur_failed = 1;                                           \
        }                                                                    \
    } while (0)

#define CHECK_MEM(a, b, n)                                                   \
    do {                                                                     \
        if (memcmp((a), (b), (n)) != 0) {                                    \
            WTLS_TEST_PRINTF("  FAIL %s:%d: memcmp(%s, %s, %s)\n",           \
                             __FILE__, __LINE__, #a, #b, #n);                \
            wtls_t_cur_failed = 1;                                           \
        }                                                                    \
    } while (0)

/* Marks the running test as skipped (counted neither as pass nor as fail).
 * A CHECK failure in the same test still wins. */
#define SKIP(reason)                                                         \
    do {                                                                     \
        WTLS_TEST_PRINTF("  SKIP: %s\n", (reason));                          \
        wtls_t_cur_skipped = 1;                                              \
    } while (0)

#define RUN(fn)                                                              \
    do {                                                                     \
        wtls_t_cur_failed = 0;                                               \
        wtls_t_cur_skipped = 0;                                              \
        WTLS_TEST_PRINTF("RUN  %s\n", #fn);                                  \
        fn();                                                                \
        if (wtls_t_cur_failed) {                                             \
            wtls_t_fail++;                                                   \
            WTLS_TEST_PRINTF("FAIL %s\n", #fn);                              \
        } else if (wtls_t_cur_skipped) {                                     \
            wtls_t_skip++;                                                   \
            WTLS_TEST_PRINTF("SKIP %s\n", #fn);                              \
        } else {                                                             \
            wtls_t_pass++;                                                   \
            WTLS_TEST_PRINTF("OK   %s\n", #fn);                              \
        }                                                                    \
    } while (0)

/* Prints the summary line parsed by CTest and tools/hwtest.py. */
#define CHECK_DONE()                                                         \
    (WTLS_TEST_PRINTF("WTLS-TEST DONE pass=%d fail=%d skip=%d\n", wtls_t_pass, \
                      wtls_t_fail, wtls_t_skip),                             \
     wtls_t_fail > 0 ? 1 : 0)

#endif
