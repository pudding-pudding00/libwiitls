/* Debug single-thread affinity guard tests.
 * Only compiled/registered when WTLS_THREAD_CHECK is active. */
#include <stdbool.h>
#include <stdint.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_internal.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

WTLS_CHECK_DEFINE_COUNTERS;

static int s_violations;
static int s_worker_rc;

static void on_violation(const char *api) {
    (void)api;
    s_violations++;
}

static void worker_violate(void) {
    wtls_conn *c = NULL;
    s_worker_rc = wtls_connect(&c, "127.0.0.1", 4431, NULL);
}

static void worker_reinit(void) {
    s_worker_rc = wtls_init();
    if (s_worker_rc == WTLS_OK) {
        wtls_net_reset();
        wtls_shutdown();
    }
}

#if defined(_WIN32)
static DWORD WINAPI win_trampoline(LPVOID arg) {
    void (*fn)(void) = (void (*)(void))(uintptr_t)arg;
    fn();
    return 0;
}
#else
static void *posix_trampoline(void *arg) {
    void (*fn)(void) = (void (*)(void))(uintptr_t)arg;
    fn();
    return NULL;
}
#endif

static void run_on_other_thread(void (*fn)(void)) {
#if defined(_WIN32)
    HANDLE th = CreateThread(NULL, 0, win_trampoline, (LPVOID)(uintptr_t)fn, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
#else
    pthread_t th;
    CHECK_EQ_INT(pthread_create(&th, NULL, posix_trampoline, (void *)(uintptr_t)fn), 0);
    pthread_join(th, NULL);
#endif
}

static void test_thread_guard_catches_other_thread(void) {
    s_violations = 0;
    wtls_set_thread_violation_handler(on_violation);
    CHECK_EQ_INT(wtls_init(), WTLS_OK);

    /* Same thread succeeds (no violation). */
    wtls_net_reset();
    CHECK_EQ_INT(s_violations, 0);

    /* Another thread calling wtls_* triggers the guard. */
    s_worker_rc = WTLS_OK;
    run_on_other_thread(worker_violate);
    CHECK_EQ_INT(s_violations, 1);
    CHECK_EQ_INT(s_worker_rc, WTLS_ERR_STATE);

    /* Shutdown on owner thread unbinds; another thread may then wtls_init(). */
    wtls_shutdown();
    s_worker_rc = -1;
    run_on_other_thread(worker_reinit);
    CHECK_EQ_INT(s_worker_rc, WTLS_OK);
    CHECK_EQ_INT(s_violations, 1);

    wtls_set_thread_violation_handler(NULL);
}

int main(void) {
    RUN(test_thread_guard_catches_other_thread);
    return CHECK_DONE();
}
