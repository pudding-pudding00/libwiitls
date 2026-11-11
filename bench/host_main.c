/* Host run of the benchmarks (ctest test_bench via run_with_server.py). The
 * numbers are the PC's, not the Wii's: this run only proves that every
 * benchmark works end to end. */
#include "bench.h"
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {"localhost", false, 0};

int main(void) {
    wtls_bench_run();
    return CHECK_DONE();
}
