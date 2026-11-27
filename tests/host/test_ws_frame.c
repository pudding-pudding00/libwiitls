/* Unit tests for the WebSocket frame layer (RFC 6455 section 5.7 examples). */
#include <string.h>

#include "check.h"
#include "ws/wtls_ws_frame.h"
#include <wiitls/wiitls.h>

WTLS_CHECK_DEFINE_COUNTERS;

static void test_ws_unmasked_hello(void) {
    static const uint8_t f[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
    wtls_ws_hdr h;
    CHECK_EQ_INT(wtls_ws_parse_header(f, sizeof f, &h), WTLS_OK);
    CHECK(h.fin && h.opcode == WTLS_WS_OP_TEXT && !h.masked && h.len == 5 && h.hdr_len == 2);
    uint8_t out[14];
    CHECK_EQ_INT((int)wtls_ws_build_header(out, true, WTLS_WS_OP_TEXT, 5, NULL), 2);
    CHECK(out[0] == 0x81 && out[1] == 0x05);
}

static void test_ws_masked_hello(void) {
    static const uint8_t f[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
    wtls_ws_hdr h;
    CHECK_EQ_INT(wtls_ws_parse_header(f, sizeof f, &h), WTLS_OK);
    CHECK(h.masked && h.len == 5 && h.hdr_len == 6);
    uint8_t p[5];
    memcpy(p, f + h.hdr_len, 5);
    wtls_ws_mask(p, 5, h.mask, 0);
    CHECK_MEM(p, "Hello", 5);
    /* masking in two pieces gives the same result */
    memcpy(p, f + h.hdr_len, 5);
    wtls_ws_mask(p, 2, h.mask, 0);
    wtls_ws_mask(p + 2, 3, h.mask, 2);
    CHECK_MEM(p, "Hello", 5);
    uint8_t out[14];
    CHECK_EQ_INT((int)wtls_ws_build_header(out, true, WTLS_WS_OP_TEXT, 5, h.mask), 6);
    CHECK_MEM(out, f, 6);
}

static void test_ws_length_forms(void) {
    uint8_t out[14];
    CHECK_EQ_INT((int)wtls_ws_build_header(out, true, WTLS_WS_OP_BINARY, 256, NULL), 4);
    CHECK(out[0] == 0x82 && out[1] == 0x7E && out[2] == 0x01 && out[3] == 0x00);
    wtls_ws_hdr h;
    CHECK_EQ_INT(wtls_ws_parse_header(out, 4, &h), WTLS_OK);
    CHECK_EQ_INT((int)h.len, 256);
    CHECK_EQ_INT((int)wtls_ws_build_header(out, true, WTLS_WS_OP_BINARY, 65536, NULL), 10);
    CHECK(out[1] == 0x7F && out[7] == 0x01 && out[8] == 0x00 && out[9] == 0x00);
    CHECK_EQ_INT(wtls_ws_parse_header(out, 10, &h), WTLS_OK);
    CHECK_EQ_INT((int)h.len, 65536);
    static const uint8_t mask[4] = {1, 2, 3, 4};
    CHECK_EQ_INT((int)wtls_ws_build_header(out, false, WTLS_WS_OP_CONT, 70000, mask), 14);
}

static void test_ws_needs_more_bytes(void) {
    static const uint8_t f[] = {0x82, 0xFE, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    wtls_ws_hdr h;
    CHECK_EQ_INT(wtls_ws_parse_header(f, 0, &h), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_ws_parse_header(f, 1, &h), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_ws_parse_header(f, 3, &h), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_ws_parse_header(f, 5, &h), WTLS_WANT_READ); /* masked: mask not complete */
    CHECK_EQ_INT(wtls_ws_parse_header(f, 8, &h), WTLS_OK);
}

static void test_ws_protocol_errors(void) {
    wtls_ws_hdr h;
    static const uint8_t rsv[] = {0xC1, 0x00};
    static const uint8_t reserved_op[] = {0x83, 0x00};
    static const uint8_t reserved_ctl[] = {0x8B, 0x00};
    static const uint8_t frag_ping[] = {0x09, 0x00};
    static const uint8_t long_ping[] = {0x89, 0x7E, 0x00, 0x7E};
    static const uint8_t nonmin16[] = {0x82, 0x7E, 0x00, 0x05};
    static const uint8_t nonmin64[] = {0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    static const uint8_t msb64[] = {0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0};
    CHECK_EQ_INT(wtls_ws_parse_header(rsv, sizeof rsv, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(reserved_op, sizeof reserved_op, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(reserved_ctl, sizeof reserved_ctl, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(frag_ping, sizeof frag_ping, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(long_ping, sizeof long_ping, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(nonmin16, sizeof nonmin16, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(nonmin64, sizeof nonmin64, &h), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_parse_header(msb64, sizeof msb64, &h), WTLS_ERR_WS);
}

static void test_ws_utf8(void) {
    CHECK(wtls_ws_valid_utf8((const uint8_t *)"", 0));
    CHECK(wtls_ws_valid_utf8((const uint8_t *)"plain ASCII", 11));
    CHECK(wtls_ws_valid_utf8((const uint8_t *)"\xC3\xA4\xE2\x82\xAC\xF0\x9F\x98\x80", 9)); /* a-umlaut, euro, emoji */
    CHECK(wtls_ws_valid_utf8((const uint8_t *)"\xF4\x8F\xBF\xBF", 4));                    /* U+10FFFF */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xC0\xAF", 2));                            /* overlong '/' */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xE0\x80\xAF", 3));                        /* overlong */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xED\xA0\x80", 3));                        /* surrogate */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xF4\x90\x80\x80", 4));                    /* above U+10FFFF */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xC3", 1));                                /* truncated */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\x80", 1));                                /* stray continuation */
    CHECK(!wtls_ws_valid_utf8((const uint8_t *)"\xFF", 1));
}

static void test_ws_close_codes(void) {
    CHECK(wtls_ws_close_code_valid(1000) && wtls_ws_close_code_valid(1011) && wtls_ws_close_code_valid(4999));
    CHECK(!wtls_ws_close_code_valid(999) && !wtls_ws_close_code_valid(1004) && !wtls_ws_close_code_valid(1005));
    CHECK(!wtls_ws_close_code_valid(1006) && !wtls_ws_close_code_valid(1015) && !wtls_ws_close_code_valid(2999));
}

int main(void) {
    RUN(test_ws_unmasked_hello);
    RUN(test_ws_masked_hello);
    RUN(test_ws_length_forms);
    RUN(test_ws_needs_more_bytes);
    RUN(test_ws_protocol_errors);
    RUN(test_ws_utf8);
    RUN(test_ws_close_codes);
    return CHECK_DONE();
}
