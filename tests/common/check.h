/* Minimal test framework shared by host and Wii test runners. */
#ifndef WTLS_CHECK_H
#define WTLS_CHECK_H

#include <stdio.h>
#include <string.h>

#ifndef WTLS_TEST_PRINTF
#define WTLS_TEST_PRINTF printf
#endif

static int wtls_t_pass;
static int wtls_t_fail;
static int wtls_t_cur_failed;

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

#define RUN(fn)                                                              \
    do {                                                                     \
        wtls_t_cur_failed = 0;                                               \
        WTLS_TEST_PRINTF("RUN  %s\n", #fn);                                  \
        fn();                                                                \
        if (wtls_t_cur_failed) {                                             \
            wtls_t_fail++;                                                   \
            WTLS_TEST_PRINTF("FAIL %s\n", #fn);                              \
        } else {                                                             \
            wtls_t_pass++;                                                   \
            WTLS_TEST_PRINTF("OK   %s\n", #fn);                              \
        }                                                                    \
    } while (0)

/* Prints the summary line parsed by CTest and tools/hwtest.py. */
#define CHECK_DONE()                                                         \
    (WTLS_TEST_PRINTF("WTLS-TEST DONE pass=%d fail=%d\n", wtls_t_pass, wtls_t_fail), \
     wtls_t_fail > 0 ? 1 : 0)

#endif
