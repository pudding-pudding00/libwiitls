/* Suite "time": SNTP sync on real hardware (Task 5). Needs Internet access. */
#include <stdlib.h>
#include <time.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "suites.h"
#include "wtls_time.h"

static void hw_sntp_sync(void) {
    TLOG("    RTC before sync: time(NULL)=%lld check=%d\n", (long long)time(NULL),
         wtls_time_check((int64_t)time(NULL)));
    CHECK_EQ_INT(wtls_init(), WTLS_OK); /* SNTP needs it (PSA nonce) */
    CHECK_EQ_INT(wtls_time_sync_sntp(NULL, 3000), WTLS_OK);
    int64_t diff = wtls_plat_unix_time() - g_env.pc_time;
    TLOG("    synced unix time - pctime = %lld s\n", (long long)diff);
    /* pctime is taken before the DOL upload and boot, so the Wii may be ahead
     * by the transfer time; it must never be behind by more than a few seconds. */
    CHECK(g_env.pc_time != 0);
    CHECK(diff > -5 && diff < 60);
    CHECK_EQ_INT(wtls_time_check(wtls_plat_unix_time()), WTLS_OK);
    wtls_shutdown();
}

void wtls_suite_time(void) { RUN(hw_sntp_sync); }
