/* Unit tests for HPACK (RFC 7541): integers, Huffman strings, tables, encoder/decoder. */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_hpack.h"

WTLS_CHECK_DEFINE_COUNTERS;

static void test_hpack_integers(void) {
    uint8_t buf[16];
    size_t off = 0;
    /* RFC 7541 Appendix C.1.1: 10 on 5-bit prefix -> 0x0a */
    CHECK_EQ_INT(wtls_hpack_encode_int(buf, sizeof buf, &off, 0x00, 5, 10), WTLS_OK);
    CHECK_EQ_INT((int)off, 1);
    CHECK_EQ_INT(buf[0], 10);
    const uint8_t *p = buf;
    uint64_t v = 0;
    CHECK_EQ_INT(wtls_hpack_decode_int(&p, buf + off, 5, &v), WTLS_OK);
    CHECK_EQ_INT((long long)v, 10);
    CHECK(p == buf + off);

    /* RFC 7541 Appendix C.1.2: 1337 on 5-bit prefix -> 1f 9a 0a */
    off = 0;
    CHECK_EQ_INT(wtls_hpack_encode_int(buf, sizeof buf, &off, 0x00, 5, 1337), WTLS_OK);
    CHECK_EQ_INT((int)off, 3);
    CHECK(buf[0] == 0x1f && buf[1] == 0x9a && buf[2] == 0x0a);
    p = buf;
    CHECK_EQ_INT(wtls_hpack_decode_int(&p, buf + off, 5, &v), WTLS_OK);
    CHECK_EQ_INT((long long)v, 1337);

    /* Truncated varint rejected */
    p = buf;
    CHECK_EQ_INT(wtls_hpack_decode_int(&p, buf + 2, 5, &v), WTLS_ERR_HTTP);
}

static void test_hpack_huffman_vectors(void) {
    /* RFC 7541 Appendix C.4.1: "www.example.com" */
    static const uint8_t h_www[] = {0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    const uint8_t *p = h_www;
    char *s = NULL;
    size_t len = 0;
    CHECK_EQ_INT(wtls_hpack_decode_str(&p, h_www + sizeof h_www, 256, &s, &len), WTLS_OK);
    CHECK_EQ_INT((int)len, 15);
    CHECK(strcmp(s, "www.example.com") == 0);
    free(s);

    /* RFC 7541 Appendix C.4.2: "no-cache" */
    static const uint8_t h_nc[] = {0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    p = h_nc;
    CHECK_EQ_INT(wtls_hpack_decode_str(&p, h_nc + sizeof h_nc, 256, &s, &len), WTLS_OK);
    CHECK(strcmp(s, "no-cache") == 0);
    free(s);

    /* Invalid padding (>7 bits or 0 bit in padding) must fail */
    static const uint8_t bad_pad_zero[] = {0x81, 0xf0}; /* 'a' = 00011 (5 bits) + 000 invalid pad */
    p = bad_pad_zero;
    CHECK_EQ_INT(wtls_hpack_decode_str(&p, bad_pad_zero + sizeof bad_pad_zero, 256, &s, &len), WTLS_ERR_HTTP);

    static const uint8_t bad_pad_long[] = {0x82, 0x1f, 0xff}; /* >=8 bits EOS prefix padding */
    p = bad_pad_long;
    CHECK_EQ_INT(wtls_hpack_decode_str(&p, bad_pad_long + sizeof bad_pad_long, 256, &s, &len), WTLS_ERR_HTTP);
}

static void test_hpack_dynamic_table(void) {
    wtls_hpack_ctx ctx;
    wtls_hpack_init(&ctx, WTLS_HPACK_DEFAULT_TABLE);

    /* Response 1: :status 200 (0x88) + literal incremental custom-key: custom-header */
    static const uint8_t blk1[] = {
        0x88,
        0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y',
        0x0d, 'c', 'u', 's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r'
    };
    wtls_http_head head;
    char *arena = NULL;
    CHECK_EQ_INT(wtls_hpack_decode_head(&ctx, blk1, sizeof blk1, &head, &arena), WTLS_OK);
    CHECK_EQ_INT(head.status, 200);
    CHECK_EQ_INT((int)head.n_fields, 1);
    CHECK(strcmp(head.fields[0].name, "custom-key") == 0);
    CHECK(strcmp(head.fields[0].value, "custom-header") == 0);
    free(arena);

    /* Response 2: :status 404 (0x8d) + indexed dynamic entry 62 (0xbe) */
    static const uint8_t blk2[] = {0x8d, 0xbe};
    CHECK_EQ_INT(wtls_hpack_decode_head(&ctx, blk2, sizeof blk2, &head, &arena), WTLS_OK);
    CHECK_EQ_INT(head.status, 404);
    CHECK_EQ_INT((int)head.n_fields, 1);
    CHECK(strcmp(head.fields[0].value, "custom-header") == 0);
    free(arena);

    /* Size update to 0 evicts entry 62 -> referencing 62 fails */
    static const uint8_t blk3[] = {0x20, 0x88, 0xbe};
    CHECK_EQ_INT(wtls_hpack_decode_head(&ctx, blk3, sizeof blk3, &head, &arena), WTLS_ERR_HTTP);

    /* Uppercase header name rejected */
    static const uint8_t bad_upper[] = {0x88, 0x00, 0x03, 'F', 'o', 'o', 0x01, '1'};
    CHECK_EQ_INT(wtls_hpack_decode_head(&ctx, bad_upper, sizeof bad_upper, &head, &arena), WTLS_ERR_HTTP);

    /* Pseudo-header after regular header rejected */
    static const uint8_t bad_pseudo_order[] = {0x88, 0x00, 0x01, 'x', 0x01, '1', 0x88};
    CHECK_EQ_INT(wtls_hpack_decode_head(&ctx, bad_pseudo_order, sizeof bad_pseudo_order, &head, &arena), WTLS_ERR_HTTP);

    wtls_hpack_free(&ctx);
}

static void test_hpack_encode_request(void) {
    wtls_url u;
    char raw[] = "https://example.com:8443/api/v1?x=1";
    CHECK_EQ_INT(wtls_url_parse(raw, &u), WTLS_OK);
    wtls_http_header hdrs[] = {
        {"X-Test", "hello"},
        {"Authorization", "Bearer secret"}
    };
    uint8_t *blk = NULL;
    size_t blen = 0;
    CHECK_EQ_INT(wtls_hpack_encode_request("POST", &u, hdrs, 2, true, 5, true, true, &blk, &blen), WTLS_OK);
    CHECK(blk != NULL && blen > 10);
    /* First two bytes: :method POST (0x83), :scheme https (0x87) */
    CHECK_EQ_INT(blk[0], 0x83);
    CHECK_EQ_INT(blk[1], 0x87);
    free(blk);

    /* Forbidden connection header rejected */
    wtls_http_header bad[] = {{"Connection", "close"}};
    CHECK_EQ_INT(wtls_hpack_encode_request("GET", &u, bad, 1, false, 0, false, false, &blk, &blen), WTLS_ERR_ARG);
}

int main(void) {
    RUN(test_hpack_integers);
    RUN(test_hpack_huffman_vectors);
    RUN(test_hpack_dynamic_table);
    RUN(test_hpack_encode_request);
    return CHECK_DONE();
}
