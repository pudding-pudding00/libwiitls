/* IOS socket / timebase behaviour spike (suite "spike"). Measures, never fails. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fcntl.h>
#include <malloc.h>
#include <sys/ioctl.h>

#include <wiitls/wiitls.h>

#include <gccore.h>
#include <network.h>
#include <ogc/lwp_watchdog.h>

#include "check.h"
#include "env.h"
#include "suites.h"

#define SPIKE_PORT 4430
/* IOS poll event bits (/dev/net/ip/top) */
#define IOS_POLLIN  0x0003
#define IOS_POLLOUT 0x0008
#define IOS_O_NONBLOCK 0x04

static inline u32 tb_read(void) {
    u32 t;
    __asm__ volatile("mftb %0" : "=r"(t));
    return t;
}

static u32 us_since(u64 t0) { return (u32)ticks_to_microsecs(gettime() - t0); }

static int cmp_u32(const void *a, const void *b) {
    u32 x = *(const u32 *)a, y = *(const u32 *)b;
    return x < y ? -1 : x > y;
}

static struct sockaddr_in server_addr(void) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SPIKE_PORT);
    sa.sin_addr.s_addr = inet_addr(g_env.server_host ? g_env.server_host : "0.0.0.0");
    return sa;
}

static s32 blocking_connect(void) {
    s32 fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd < 0) return fd;
    struct sockaddr_in sa = server_addr();
    s32 r = net_connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r < 0) {
        net_close(fd);
        return r;
    }
    return fd;
}

static void send_all(s32 fd, const char *s) {
    size_t len = strlen(s), off = 0;
    while (off < len) {
        s32 r = net_send(fd, s + off, (s32)(len - off), 0);
        if (r <= 0) return;
        off += (size_t)r;
    }
}

static void spike_nonblocking_connect(void) {
    TLOG("[1] non-blocking connect\n");
    s32 fd = net_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
    TLOG("    net_socket(SOCK_NONBLOCK) = %d\n", (int)fd);
    if (fd < 0) {
        fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        s32 fr = net_fcntl(fd, F_SETFL, IOS_O_NONBLOCK);
        TLOG("    fallback net_fcntl(F_SETFL, IOS_O_NONBLOCK) = %d\n", (int)fr);
    }
    struct sockaddr_in sa = server_addr();
    u64 t0 = gettime();
    s32 r = net_connect(fd, (struct sockaddr *)&sa, sizeof sa);
    TLOG("    net_connect = %d after %u us\n", (int)r, (unsigned)us_since(t0));
    struct pollsd p = {fd, IOS_POLLOUT, 0};
    s32 pr = net_poll(&p, 1, 2000);
    TLOG("    net_poll(POLLOUT, 2000) = %d revents=0x%x after %u us\n", (int)pr,
         (unsigned)p.revents, (unsigned)us_since(t0));
    s32 r2 = net_connect(fd, (struct sockaddr *)&sa, sizeof sa);
    TLOG("    second net_connect = %d\n", (int)r2);
    send_all(fd, "hello\n");
    char buf[16] = {0};
    p.events = IOS_POLLIN;
    pr = net_poll(&p, 1, 1000);
    s32 n = net_recv(fd, buf, sizeof buf - 1, 0);
    TLOG("    echo poll=%d recv=%d '%s'\n", (int)pr, (int)n, n > 0 ? "ok" : "-");
    net_close(fd);
}

static void spike_nodelay(void) {
    TLOG("[2] TCP_NODELAY\n");
    s32 fd = blocking_connect();
    int one = 1;
    s32 r = net_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    TLOG("    connect fd=%d setsockopt(TCP_NODELAY) = %d\n", (int)fd, (int)r);
    if (fd >= 0) net_close(fd);
}

static void spike_poll_accuracy(void) {
    TLOG("[3] net_poll 100 ms on idle socket\n");
    s32 fd = blocking_connect();
    if (fd < 0) return;
    send_all(fd, "SILENT\n");
    u32 d[10];
    for (int i = 0; i < 10; i++) {
        struct pollsd p = {fd, IOS_POLLIN, 0};
        u64 t0 = gettime();
        net_poll(&p, 1, 100);
        d[i] = us_since(t0);
    }
    qsort(d, 10, sizeof d[0], cmp_u32);
    TLOG("    min=%u median=%u max=%u us\n", (unsigned)d[0], (unsigned)d[5], (unsigned)d[9]);
    net_close(fd);
}

static void spike_ipc_roundtrip(void) {
    TLOG("[4] IPC roundtrip (net_poll timeout 0) x1000\n");
    s32 fd = blocking_connect();
    if (fd < 0) return;
    u64 t0 = gettime();
    for (int i = 0; i < 1000; i++) {
        struct pollsd p = {fd, IOS_POLLIN, 0};
        net_poll(&p, 1, 0);
    }
    TLOG("    mean=%u us\n", (unsigned)(us_since(t0) / 1000));
    net_close(fd);
}

static void spike_max_recv(void) {
    TLOG("[5] net_recv(65536) on a 64 KiB stream\n");
    s32 fd = blocking_connect();
    if (fd < 0) return;
    send_all(fd, "BIG 65536\n");
    uint8_t *buf = memalign(32, 65536);
    size_t total = 0;
    s32 max = 0;
    int calls = 0;
    u64 t0 = gettime();
    while (total < 65536) {
        s32 n = net_recv(fd, buf, 65536, 0);
        calls++;
        if (n <= 0) {
            TLOG("    recv returned %d at total=%u\n", (int)n, (unsigned)total);
            break;
        }
        if (n > max) max = n;
        total += (size_t)n;
    }
    u32 us = us_since(t0);
    TLOG("    total=%u calls=%d max_per_call=%d time=%u us (%u KiB/s)\n", (unsigned)total, calls,
         (int)max, (unsigned)us, us ? (unsigned)((u64)total * 1000000 / us / 1024) : 0);
    free(buf);
    net_close(fd);
}

static void spike_clock(void) {
    TLOG("[6] clock\n");
    time_t now = time(NULL);
    TLOG("    time(NULL)=%lld pctime=%lld diff=%lld s\n", (long long)now, (long long)g_env.pc_time,
         (long long)(now - g_env.pc_time));
}

/* SP 800-90B 6.3.1 Most Common Value estimate over the low byte of samples. */
static double mcv_min_entropy(const uint32_t *hist, size_t n) {
    uint32_t mx = 0;
    for (int i = 0; i < 256; i++)
        if (hist[i] > mx) mx = hist[i];
    double p = (double)mx / (double)n;
    double pu = p + 2.576 * sqrt(p * (1.0 - p) / (double)(n - 1));
    if (pu > 1.0) pu = 1.0;
    return -log2(pu);
}

#define JIT_SAMPLES 100000
#define WALK_BYTES (256 * 1024)

static void spike_jitter_variant(char variant, volatile uint8_t *walk, s32 fd) {
    static uint32_t hist[256];
    memset(hist, 0, sizeof hist);
    size_t pos = 0;
    u32 prev = tb_read();
    for (int i = 0; i < JIT_SAMPLES; i++) {
        if (variant != 'a') {
            walk[pos] ^= (uint8_t)i;
            pos = (pos + 4096 + 32) % WALK_BYTES;
        }
        if (variant == 'c' && (i & 15) == 0 && fd >= 0) {
            struct pollsd p = {fd, IOS_POLLIN, 0};
            net_poll(&p, 1, 0);
        }
        u32 now = tb_read();
        hist[(now - prev) & 0xFF]++;
        prev = now;
    }
    int distinct = 0;
    for (int i = 0; i < 256; i++) distinct += hist[i] != 0;
    TLOG("    variant %c: H_mcv=%.3f bits/sample, distinct low bytes=%d\n", variant,
         mcv_min_entropy(hist, JIT_SAMPLES), distinct);
}

static void spike_jitter(void) {
    TLOG("[7] timebase jitter, %d samples per variant\n", JIT_SAMPLES);
    volatile uint8_t *walk = memalign(32, WALK_BYTES);
    s32 fd = blocking_connect();
    spike_jitter_variant('a', walk, fd);
    spike_jitter_variant('b', walk, fd);
    spike_jitter_variant('c', walk, fd);
    if (fd >= 0) net_close(fd);
    free((void *)walk);
}

/* net_send truthfulness: sustained full-speed sends at a given call size.
 * The server (SENDFUZZ) checks every byte and the count; a mismatch with
 * the Wii-side sum of return values means net_send reported more than it
 * actually transmitted. */
static void spike_send_truth(void) {
    static const struct {
        int chunk;
        long total;
    } rounds[] = {
        {4096, 64L * 1024},
        {16384, 256L * 1024},
    };
    for (size_t k = 0; k < sizeof rounds / sizeof rounds[0]; k++) {
        int chunk = rounds[k].chunk;
        long total = rounds[k].total;
        TLOG("[%d] net_send truthfulness: %d-byte calls, %ld bytes\n", (int)k + 8, chunk, total);
        s32 fd = blocking_connect();
        if (fd < 0) {
            TLOG("    connect failed: %d\n", (int)fd);
            return;
        }
        char cmd[48];
        snprintf(cmd, sizeof cmd, "SENDFUZZ %ld\n", total);
        send_all(fd, cmd);
        uint8_t *buf = malloc((size_t)chunk);
        if (!buf) {
            net_close(fd);
            return;
        }
        long sent = 0; /* sum of net_send return values, Wii-side view */
        s32 r = 0;
        int calls = 0, short_sends = 0;
        while (sent < total) {
            size_t want = (size_t)(total - sent) < (size_t)chunk ? (size_t)(total - sent) : (size_t)chunk;
            for (size_t i = 0; i < want; i++) buf[i] = (uint8_t)((sent + (long)i) % 251);
            r = net_send(fd, buf, (s32)want, 0);
            calls++;
            if (r <= 0) break;
            if ((size_t)r < want) short_sends++;
            sent += r;
        }
        TLOG("    net_send: %d calls, %d short, last r=%d, sum(wii view)=%ld\n", calls,
             short_sends, (int)r, sent);
        /* verdict line from the server */
        char line[96] = {0};
        size_t got = 0;
        while (got < sizeof line - 1) {
            s32 g = net_recv(fd, (uint8_t *)line + got, 1, 0);
            if (g <= 0) break;
            if (line[got] == '\n') break;
            got += (size_t)g;
        }
        line[got] = 0;
        TLOG("    server: %s\n", line);
        free(buf);
        net_close(fd);
    }
}

/* Same sustained-send pressure as spike_send_truth, but through the TLS
 * layer against /echo (the path http_upload_256k takes): wtls_write in
 * steps of various sizes, to find the threshold where records corrupt. */
static void spike_send_truth_tls(void) {
    static const int steps[] = {2048, 4096, 8192, 16384};
    if (wtls_init() != WTLS_OK) {
        TLOG("    wtls_init failed\n");
        return;
    }
    for (size_t k = 0; k < sizeof steps / sizeof steps[0]; k++) {
        int step = steps[k];
        long total = 256L * 1024;
        TLOG("[10.%d] TLS sustained write: 256 KiB to /echo in %d-byte steps\n", (int)k, step);
        wtls_options opt = {0};
        opt.io_timeout_ms = 20000;
        opt.insecure_skip_verify = true; /* the spike suite trusts no CA */
        wtls_conn *c = (wtls_conn *)1;
        s32 st = wtls_connect(&c, g_env.server_host, 4438, &opt);
        if (st != WTLS_OK) {
            TLOG("    connect: %d\n", (int)st);
            return;
        }
        wtls_conn_info info;
        if (wtls_get_info(c, &info) == WTLS_OK)
            TLOG("    %s %s\n", info.tls_version, info.ciphersuite);
        char head[128];
        int hn = snprintf(head, sizeof head,
                          "PUT /echo HTTP/1.1\r\nHost: x\r\nContent-Length: %ld\r\n\r\n", total);
        int r = wtls_write(c, head, (size_t)hn);
        if (r != hn) {
            TLOG("    head write: %d of %d\n", r, hn);
            wtls_close(c);
            continue;
        }
        long off = 0;
        uint8_t buf[16384];
        while (off < total) {
            size_t want = (size_t)(total - off) < (size_t)step ? (size_t)(total - off) : (size_t)step;
            for (size_t i = 0; i < want; i++) buf[i] = (uint8_t)((off + (long)i) % 251);
            r = wtls_write(c, buf, want);
            if (r <= 0) {
                TLOG("    write failed at off=%ld (record %ld): %d\n", off, off / step, r);
                break;
            }
            off += r;
        }
        if (r > 0) TLOG("    write done: %ld bytes\n", off);
        wtls_close(c);
    }
}

/* Bidirectional-pressure probe on PLAIN TCP: like spike_send_truth, but the
 * server pushes junk back while we upload, the way a TLS 1.3 server's
 * NewSessionTicket arrives during a big upload. The client never reads
 * (mbedtls does not read while writing either). */
static void spike_send_truth_duplex(void) {
    static const int steps[] = {2048, 16384};
    for (size_t k = 0; k < sizeof steps / sizeof steps[0]; k++) {
        int chunk = steps[k];
        long total = 256L * 1024;
        TLOG("[11.%d] plain duplex pressure: %d-byte calls, %ld bytes, junk inbound\n", (int)k,
             chunk, total);
        s32 fd = blocking_connect();
        if (fd < 0) return;
        char cmd[48];
        snprintf(cmd, sizeof cmd, "SENDFUZZDUP %ld\n", total);
        send_all(fd, cmd);
        long sent = 0;
        s32 r = 0;
        int calls = 0, short_sends = 0;
        uint8_t buf[16384];
        while (sent < total) {
            size_t want = (size_t)(total - sent) < (size_t)chunk ? (size_t)(total - sent) : (size_t)chunk;
            for (size_t i = 0; i < want; i++) buf[i] = (uint8_t)((sent + (long)i) % 251);
            r = net_send(fd, buf, (s32)want, 0);
            calls++;
            if (r <= 0) break;
            if ((size_t)r < want) short_sends++;
            sent += r;
        }
        TLOG("    net_send: %d calls, %d short, last r=%d, sum=%ld\n", calls, short_sends, (int)r,
             sent);
        char line[96] = {0};
        size_t got = 0, skipped = 0;
        uint8_t rx[4096];
        for (;;) {
            s32 g = net_recv(fd, rx, sizeof rx, 0);
            if (g <= 0) break;
            for (s32 i = 0; i < g; i++) {
                if (rx[i] == 'J' && got == 0) {
                    skipped++;
                    continue;
                }
                if (rx[i] == '\n') goto done_line;
                if (got < sizeof line - 1) line[got++] = (char)rx[i];
            }
        }
    done_line:
        line[got] = 0;
        TLOG("    server (skipped %u junk): %s\n", (unsigned)skipped, line);
        net_close(fd);
    }
}

/* Stalled-peer send probe (safe: clears O_NONBLOCK around net_send; also
 * checks once whether IOS implements FIONSPACE / FIONWRITE via net_ioctl). */
static void spike_stalled_peer_send(void) {
    static const int chunks[] = {2048, 4080, 16384};
    static uint8_t buf[16384];
    memset(buf, 0xA5, sizeof buf);
    for (size_t k = 0; k < sizeof chunks / sizeof chunks[0]; k++) {
        int chunk = chunks[k];
        TLOG("[12.%d] stalled-peer send probe (%d B chunks)\n", (int)k, chunk);
        s32 fd = blocking_connect();
        if (fd < 0) return;
        if (k == 0) {
            int sp = -1, wr = -1;
            s32 r1 = net_ioctl(fd, FIONSPACE, &sp);
            s32 r2 = net_ioctl(fd, FIONWRITE, &wr);
            TLOG("    net_ioctl: FIONSPACE=%d (val=%d) FIONWRITE=%d (val=%d)\n",
                 (int)r1, sp, (int)r2, wr);
        }
        send_all(fd, "STALL\n");
        net_fcntl(fd, 4, IOS_O_NONBLOCK);
        size_t sent = 0;
        int calls = 0;
        u32 max_call_us = 0;
        s32 last_r = 0;
        u64 t0 = gettime();
        for (int iter = 0; iter < 64; iter++) {
            struct pollsd p = {fd, IOS_POLLOUT, 0};
            if (net_poll(&p, 1, 0) <= 0) {
                last_r = -11;
                break;
            }
            s32 fl = net_fcntl(fd, 3, 0);
            if (fl >= 0 && (fl & IOS_O_NONBLOCK)) net_fcntl(fd, 4, fl & ~IOS_O_NONBLOCK);
            u64 c0 = gettime();
            last_r = net_send(fd, buf, chunk, 0);
            u32 cus = us_since(c0);
            if (cus > max_call_us) max_call_us = cus;
            if (fl >= 0 && (fl & IOS_O_NONBLOCK)) net_fcntl(fd, 4, fl);
            calls++;
            if (last_r <= 0) break;
            sent += (size_t)last_r;
            if (us_since(t0) > 2000000u) break;
        }
        TLOG("    calls=%d sent=%u last=%d max_call=%u us total=%u us\n", calls, (unsigned)sent,
             (int)last_r, (unsigned)max_call_us, (unsigned)us_since(t0));
        net_close(fd);
    }
}

void wtls_suite_spike(void) {
    spike_nonblocking_connect();
    spike_nodelay();
    spike_poll_accuracy();
    spike_ipc_roundtrip();
    spike_max_recv();
    spike_clock();
    spike_jitter();
    spike_send_truth();
    spike_send_truth_tls();
    spike_send_truth_duplex();
    spike_stalled_peer_send();
}
