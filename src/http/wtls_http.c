/* HTTP/1.1 client: request, response head, body streaming (RFC 9112).
 *
 * The response keeps the connection and one buffer: the head (parsed in
 * place, so field names and values point into it) followed by the body bytes
 * that arrived together with the head; wtls_http_read() serves those first. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/http.h>

#include "http/wtls_http_chunked.h"
#include "http/wtls_http_parse.h"
#include "http/wtls_http_req.h"
#include "http/wtls_url.h"
#include "plat/plat.h"
#include "wtls_internal.h"

#define HEAD_BUF_START 2048u
#define DEFAULT_HEADER_TIMEOUT_MS 15000u
#define SINGLE_WRITE_MAX 16384u

/* wtls_conn_info.alpn points into this list, so it must outlive every connection. */
static const char *const k_alpn[] = {"http/1.1", NULL};

struct wtls_http_response {
    wtls_conn *conn;
    char *buf;           /* head, then extra body bytes */
    size_t extra_off;    /* first unread extra byte */
    size_t extra_end;    /* end of the extra bytes */
    wtls_http_head head; /* points into buf */
    wtls_http_framing fr;
    uint64_t remaining;  /* WTLS_BODY_LENGTH */
    wtls_chunked chunked;
    int err;             /* sticky read error */
    bool eof;            /* body read to its end */
    bool head_request;
    char *url;
    uint8_t redirects;
    bool reused;
    bool secure;
    wtls_conn_info info;
};

/* ---- transport ------------------------------------------------------------ */

static int tr_read(wtls_http_response *r, void *buf, size_t len) { return wtls_read(r->conn, buf, len); }

static int tr_write_all(wtls_conn *c, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len) {
        int k = wtls_write(c, p, len);
        if (k <= 0) return k < 0 ? k : WTLS_ERR_IO;
        p += k;
        len -= (size_t)k;
    }
    return WTLS_OK;
}

static void tr_close(wtls_conn *c) { wtls_close(c); }

/* ---- open ------------------------------------------------------------------- */

static void response_free(wtls_http_response *r) {
    if (!r) return;
    if (r->conn) tr_close(r->conn);
    free(r->buf);
    free(r->url);
    free(r);
}

static int send_request(wtls_conn *c, char *head, size_t head_len, const wtls_http_request *req) {
    size_t body_len = req->body ? req->body_len : 0;
    if (head_len + body_len <= SINGLE_WRITE_MAX && body_len) {
        char *all = malloc(head_len + body_len);
        if (!all) return WTLS_ERR_NOMEM;
        memcpy(all, head, head_len);
        memcpy(all + head_len, req->body, body_len);
        int st = tr_write_all(c, all, head_len + body_len);
        free(all);
        return st;
    }
    int st = tr_write_all(c, head, head_len);
    if (st == WTLS_OK && body_len) st = tr_write_all(c, req->body, body_len);
    return st;
}

/* Reads until a final (non-1xx) response head is parsed. On success r->buf
 * holds it and r->extra_* the body bytes behind it. */
static int read_head(wtls_http_response *r, uint32_t timeout_ms) {
    size_t cap = HEAD_BUF_START, fill = 0;
    char *buf = malloc(cap);
    if (!buf) return WTLS_ERR_NOMEM;
    r->buf = buf;
    uint64_t deadline = wtls_plat_now_ms() + timeout_ms;
    for (;;) {
        size_t end = wtls_http_head_end(buf, fill);
        if (end) {
            int st = wtls_http_parse_head(buf, end, &r->head);
            if (st != WTLS_OK) return st;
            if (r->head.status >= 200) {
                r->extra_off = end;
                r->extra_end = fill;
                return WTLS_OK;
            }
            if (r->head.status == 101) return WTLS_ERR_HTTP; /* no upgrade was asked for */
            memmove(buf, buf + end, fill - end);           /* interim 1xx: skip it */
            fill -= end;
            continue;
        }
        if (fill == WTLS_HTTP_MAX_HEAD) return WTLS_ERR_HTTP_LIMIT;
        if (fill == cap) {
            size_t ncap = cap * 2 > WTLS_HTTP_MAX_HEAD ? WTLS_HTTP_MAX_HEAD : cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) return WTLS_ERR_NOMEM;
            r->buf = buf = nb;
            cap = ncap;
        }
        uint64_t now = wtls_plat_now_ms();
        if (now >= deadline) return WTLS_ERR_TIMEOUT;
        r->conn->io_timeout_ms = (uint32_t)(deadline - now);
        int k = tr_read(r, buf + fill, cap - fill);
        if (k > 0) fill += (size_t)k;
        else if (k == WTLS_ERR_CLOSED) return WTLS_ERR_IO; /* closed before a complete head */
        else return k;
    }
}

wtls_status wtls_http_open(wtls_http_response **out, const wtls_http_request *req) {
    if (!out) return WTLS_ERR_ARG;
    *out = NULL;
    if (!req || !req->url) return WTLS_ERR_ARG;
    if (req->body_len && !req->body) return WTLS_ERR_ARG;

    wtls_http_response *r = calloc(1, sizeof *r);
    if (!r) return WTLS_ERR_NOMEM;
    size_t url_len = strnlen(req->url, WTLS_HTTP_MAX_URL + 1);
    if (url_len > WTLS_HTTP_MAX_URL) {
        free(r);
        return WTLS_ERR_ARG;
    }
    r->url = malloc(url_len + 1);
    if (!r->url) {
        free(r);
        return WTLS_ERR_NOMEM;
    }
    memcpy(r->url, req->url, url_len + 1);

    wtls_url u;
    int st = wtls_url_parse(r->url, &u);
    if (st == WTLS_OK && !u.secure) st = WTLS_ERR_ARG; /* plain http:// comes with the plain transport */
    char *head = NULL;
    size_t head_len = 0;
    const char *method = req->method ? req->method : "GET";
    if (st == WTLS_OK)
        st = wtls_http_build_head(method, &u, req->headers, req->n_headers, req->body != NULL, req->body_len,
                                  req->no_keepalive, false, &head, &head_len);
    if (st != WTLS_OK) {
        response_free(r);
        return st;
    }

    wtls_options opt = {0};
    if (req->tls) opt = *req->tls;
    opt.alpn = k_alpn;
    st = wtls_connect(&r->conn, u.host, u.port, &opt);
    if (st == WTLS_OK) {
        r->secure = true;
        wtls_get_info(r->conn, &r->info);
        st = send_request(r->conn, head, head_len, req);
    }
    free(head);
    if (st == WTLS_OK) {
        uint32_t io_timeout = r->conn->io_timeout_ms;
        r->head_request = strcmp(method, "HEAD") == 0;
        st = read_head(r, req->header_timeout_ms ? req->header_timeout_ms : DEFAULT_HEADER_TIMEOUT_MS);
        r->conn->io_timeout_ms = io_timeout;
    }
    if (st == WTLS_OK) st = wtls_http_frame(&r->head, r->head_request, !req->no_keepalive, &r->fr);
    if (st != WTLS_OK) {
        response_free(r);
        return st;
    }
    r->remaining = r->fr.length;
    r->eof = r->fr.kind == WTLS_BODY_NONE || (r->fr.kind == WTLS_BODY_LENGTH && r->fr.length == 0);
    wtls_chunked_init(&r->chunked);
    *out = r;
    return WTLS_OK;
}

/* ---- accessors ---------------------------------------------------------------- */

int wtls_http_status(const wtls_http_response *r) { return r ? r->head.status : 0; }

const char *wtls_http_get_header(const wtls_http_response *r, const char *name) {
    if (!r || !name) return NULL;
    return wtls_http_head_get(&r->head, name);
}

bool wtls_http_header_at(const wtls_http_response *r, size_t i, const char **name, const char **value) {
    if (!r || i >= r->head.n_fields) return false;
    if (name) *name = r->head.fields[i].name;
    if (value) *value = r->head.fields[i].value;
    return true;
}

/* Content-Length of a HEAD response: plain digits only, else -1. */
static int64_t head_content_length(const wtls_http_response *r) {
    const char *v = wtls_http_head_get(&r->head, "content-length");
    if (!v || !*v) return -1;
    int64_t n = 0;
    for (; *v; v++) {
        if (*v < '0' || *v > '9' || n > (INT64_MAX - 9) / 10) return -1;
        n = n * 10 + (*v - '0');
    }
    return n;
}

int64_t wtls_http_content_length(const wtls_http_response *r) {
    if (!r) return -1;
    switch (r->fr.kind) {
    case WTLS_BODY_LENGTH:
        return r->fr.length > (uint64_t)INT64_MAX ? -1 : (int64_t)r->fr.length;
    case WTLS_BODY_NONE:
        return r->head_request ? head_content_length(r) : 0;
    default:
        return -1;
    }
}

wtls_status wtls_http_get_info(const wtls_http_response *r, wtls_http_info *out) {
    if (!r || !out) return WTLS_ERR_ARG;
    memset(out, 0, sizeof *out);
    out->url = r->url;
    out->redirects = r->redirects;
    out->reused_connection = r->reused;
    out->secure = r->secure;
    out->tls = r->info;
    return WTLS_OK;
}

/* ---- body ------------------------------------------------------------------------ */

/* Raw bytes: first the ones that came with the head, then the connection. */
static int pull(wtls_http_response *r, void *buf, size_t len) {
    if (r->extra_off < r->extra_end) {
        size_t n = r->extra_end - r->extra_off;
        if (n > len) n = len;
        memcpy(buf, r->buf + r->extra_off, n);
        r->extra_off += n;
        return (int)n;
    }
    return tr_read(r, buf, len);
}

static int fail(wtls_http_response *r, int err) {
    r->err = err;
    return err;
}

int wtls_http_read(wtls_http_response *r, void *buf, size_t len) {
    if (!r || (!buf && len)) return WTLS_ERR_ARG;
    if (r->err) return r->err;
    if (r->eof || !len) return 0;
    if (len > INT_MAX) len = INT_MAX;
    switch (r->fr.kind) {
    case WTLS_BODY_LENGTH: {
        if ((uint64_t)len > r->remaining) len = (size_t)r->remaining;
        int k = pull(r, buf, len);
        if (k < 0) return fail(r, k == WTLS_ERR_CLOSED ? WTLS_ERR_IO : k); /* truncated */
        r->remaining -= (uint64_t)k;
        if (!r->remaining) r->eof = true;
        return k;
    }
    case WTLS_BODY_CLOSE: {
        int k = pull(r, buf, len);
        if (k == WTLS_ERR_CLOSED) {
            r->eof = true;
            return 0;
        }
        return k < 0 ? fail(r, k) : k;
    }
    case WTLS_BODY_CHUNKED:
        for (;;) {
            int k = pull(r, buf, len);
            if (k < 0) return fail(r, k == WTLS_ERR_CLOSED ? WTLS_ERR_IO : k);
            size_t out = 0, rest = 0;
            int st = wtls_chunked_decode(&r->chunked, buf, (size_t)k, &out, &rest);
            if (st != WTLS_OK && st != WTLS_WANT_READ) return fail(r, st);
            if (st == WTLS_OK) {
                r->eof = true;
                if (rest) r->fr.reusable = false; /* bytes after the message: not ours to keep */
            }
            if (out) return (int)out;
            if (r->eof) return 0;
        }
    default:
        r->eof = true;
        return 0;
    }
}

void wtls_http_close(wtls_http_response *r) { response_free(r); }

void wtls_http_pool_flush(void) {}
