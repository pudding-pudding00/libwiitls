/* Host integration tests for the optional curl-lite compatibility shim. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {.server_host = "127.0.0.1"};

typedef struct {
    char data[4096];
    size_t len;
} buf_sink;

static size_t sink_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    buf_sink *s = userdata;
    size_t n = size * nmemb;
    if (s->len + n >= sizeof s->data) return 0;
    memcpy(s->data + s->len, ptr, n);
    s->len += n;
    s->data[s->len] = '\0';
    return n;
}

static void test_curl_get_post_and_headers(void) {
    CURL *c = curl_easy_init();
    CHECK(c != NULL);
    if (!c) return;

    char url_buf[256];
    snprintf(url_buf, sizeof url_buf, "http://%s:4440/hello", g_env.server_host);
    buf_sink body = {0};
    buf_sink hdrs = {0};
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_URL, url_buf), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink_cb), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_WRITEDATA, &body), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, sink_cb), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_HEADERDATA, &hdrs), CURLE_OK);
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);

    long code = 0;
    CHECK_EQ_INT(curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code), CURLE_OK);
    CHECK_EQ_INT(code, 200);
    CHECK(strcmp(body.data, "hello") == 0);
    CHECK(strstr(hdrs.data, "content-type: text/plain") != NULL);

    /* HTTPS POST via insecure test option + custom header. */
    snprintf(url_buf, sizeof url_buf, "https://%s:4438/echo", g_env.server_host);
    body.len = 0;
    struct curl_slist *sl = curl_slist_append(NULL, "X-Curl-Shim: 1");
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_URL, url_buf), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_POSTFIELDS, "payload"), CURLE_OK);
    CHECK_EQ_INT(curl_easy_setopt(c, CURLOPT_HTTPHEADER, sl), CURLE_OK);
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(strcmp(body.data, "payload") == 0);

    curl_slist_free_all(sl);
    curl_easy_cleanup(c);
}

typedef struct {
    const char *data;
    size_t len, off;
} src_t;

static size_t read_cb(char *buf, size_t size, size_t nitems, void *ud) {
    src_t *s = ud;
    size_t n = size * nitems;
    if (n > s->len - s->off) n = s->len - s->off;
    if (n > 7) n = 7; /* many small reads */
    memcpy(buf, s->data + s->off, n);
    s->off += n;
    return n;
}

static void https_url(char *out, size_t cap, const char *path) {
    snprintf(out, cap, "https://%s:4438%s", g_env.server_host, path);
}

static void test_curl_upload_read_callback(void) {
    CURL *c = curl_easy_init();
    if (!c) { CHECK(c != NULL); return; }
    char url[256];
    https_url(url, sizeof url, "/echo");
    buf_sink body = {0};
    src_t src = {"streamed upload body", 20, 0};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt(c, CURLOPT_READDATA, &src);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)20);
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(strcmp(body.data, "streamed upload body") == 0);
    /* unknown size: chunked */
    src.off = 0;
    body.len = 0;
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)-1);
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(strcmp(body.data, "streamed upload body") == 0);
    /* UPLOAD=1 without POST is a PUT */
    https_url(url, sizeof url, "/method");
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 0L);
    curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t)20);
    src.off = 0;
    body.len = 0;
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(strcmp(body.data, "PUT 20") == 0);
    curl_easy_cleanup(c);
}

static int s_progress_calls;
static curl_off_t s_last_dl;

static int xfer_cb(void *ud, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    (void)dltotal; (void)ultotal; (void)ulnow;
    s_progress_calls++;
    s_last_dl = dlnow;
    return ud && s_progress_calls >= *(int *)ud; /* abort at the given call */
}

static void test_curl_progress_and_abort(void) {
    CURL *c = curl_easy_init();
    if (!c) { CHECK(c != NULL); return; }
    char url[256];
    https_url(url, sizeof url, "/len?n=50000");
    buf_sink body = {0};
    size_t sink_all(char *p, size_t sz, size_t nm, void *ud);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink_all);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, xfer_cb);
    s_progress_calls = 0;
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(s_progress_calls > 0);
    CHECK_EQ_INT((long)s_last_dl, 50000);
    curl_off_t sz = 0;
    CHECK_EQ_INT(curl_easy_getinfo(c, CURLINFO_SIZE_DOWNLOAD_T, &sz), CURLE_OK);
    CHECK_EQ_INT((long)sz, 50000);
    int stop_at = 2;
    curl_easy_setopt(c, CURLOPT_XFERINFODATA, &stop_at);
    s_progress_calls = 0;
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_ABORTED_BY_CALLBACK);
    CHECK_EQ_INT(s_progress_calls, 2);
    curl_easy_cleanup(c);
}

size_t sink_all(char *p, size_t sz, size_t nm, void *ud) {
    (void)p; (void)ud;
    return sz * nm; /* discard */
}

static void test_curl_userpwd_and_info(void) {
    CURL *c = curl_easy_init();
    if (!c) { CHECK(c != NULL); return; }
    char url[256];
    https_url(url, sizeof url, "/headers");
    buf_sink body = {0};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_USERPWD, "Aladdin:open sesame");
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    CHECK(strstr(body.data, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==") != NULL);
    const char *ct = NULL, *eff = NULL;
    CHECK_EQ_INT(curl_easy_getinfo(c, CURLINFO_EFFECTIVE_URL, &eff), CURLE_OK);
    CHECK(eff && strcmp(eff, url) == 0);
    CHECK_EQ_INT(curl_easy_getinfo(c, CURLINFO_CONTENT_TYPE, &ct), CURLE_OK);
    /* a followed redirect shows up in the info */
    https_url(url, sizeof url, "/redirect-chain?n=2");
    body.len = 0;
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_USERPWD, NULL);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    CHECK_EQ_INT(curl_easy_perform(c), CURLE_OK);
    long redirects = 0;
    CHECK_EQ_INT(curl_easy_getinfo(c, CURLINFO_REDIRECT_COUNT, &redirects), CURLE_OK);
    CHECK_EQ_INT(redirects, 2);
    CHECK(strcmp(body.data, "done") == 0);
    curl_easy_cleanup(c);
}

static void test_curl_multi_sequential(void) {
    CURLM *m = curl_multi_init();
    CURL *a = curl_easy_init(), *b = curl_easy_init();
    CHECK(m && a && b);
    if (!m || !a || !b) return;
    char url[256];
    buf_sink ba = {0}, bb = {0};
    https_url(url, sizeof url, "/hello");
    curl_easy_setopt(a, CURLOPT_URL, url);
    curl_easy_setopt(a, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(a, CURLOPT_WRITEFUNCTION, sink_cb);
    curl_easy_setopt(a, CURLOPT_WRITEDATA, &ba);
    https_url(url, sizeof url, "/nonexistent-host-test");
    snprintf(url, sizeof url, "http://127.0.0.1:1/");
    curl_easy_setopt(b, CURLOPT_URL, url);
    curl_easy_setopt(b, CURLOPT_WRITEFUNCTION, sink_cb);
    curl_easy_setopt(b, CURLOPT_WRITEDATA, &bb);
    CHECK_EQ_INT(curl_multi_add_handle(m, a), CURLM_OK);
    CHECK_EQ_INT(curl_multi_add_handle(m, b), CURLM_OK);
    CHECK_EQ_INT(curl_multi_add_handle(m, a), CURLM_BAD_EASY_HANDLE); /* twice */
    int running = -1;
    CHECK_EQ_INT(curl_multi_perform(m, &running), CURLM_OK);
    CHECK_EQ_INT(running, 0);
    int numfds = -1;
    CHECK_EQ_INT(curl_multi_wait(m, NULL, 0, 100, &numfds), CURLM_OK);
    int left = 0, seen_ok = 0, seen_fail = 0;
    CURLMsg *msg;
    while ((msg = curl_multi_info_read(m, &left))) {
        CHECK_EQ_INT(msg->msg, CURLMSG_DONE);
        if (msg->easy_handle == a) { CHECK_EQ_INT(msg->data.result, CURLE_OK); seen_ok++; }
        if (msg->easy_handle == b) { CHECK(msg->data.result != CURLE_OK); seen_fail++; }
    }
    CHECK_EQ_INT(seen_ok, 1);
    CHECK_EQ_INT(seen_fail, 1);
    CHECK(strcmp(ba.data, "hello") == 0);
    CHECK_EQ_INT(curl_multi_remove_handle(m, a), CURLM_OK);
    CHECK_EQ_INT(curl_multi_remove_handle(m, a), CURLM_BAD_EASY_HANDLE);
    CHECK_EQ_INT(curl_multi_remove_handle(m, b), CURLM_OK);
    CHECK_EQ_INT(curl_multi_cleanup(m), CURLM_OK);
    curl_easy_cleanup(a);
    curl_easy_cleanup(b);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    CHECK_EQ_INT(curl_global_init(CURL_GLOBAL_DEFAULT), CURLE_OK);
    RUN(test_curl_get_post_and_headers);
    RUN(test_curl_upload_read_callback);
    RUN(test_curl_progress_and_abort);
    RUN(test_curl_userpwd_and_info);
    RUN(test_curl_multi_sequential);
    curl_global_cleanup();
    return CHECK_DONE();
}
