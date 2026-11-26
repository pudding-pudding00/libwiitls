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

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    CHECK_EQ_INT(curl_global_init(CURL_GLOBAL_DEFAULT), CURLE_OK);
    RUN(test_curl_get_post_and_headers);
    curl_global_cleanup();
    return CHECK_DONE();
}
