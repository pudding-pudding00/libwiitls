/* Network bring-up and the TCP log connection for the Wii runners
 * (tests/hw/main.c, bench/main.c). Header-only: both are single-file DOLs. */
#ifndef WTLS_HW_NET_H
#define WTLS_HW_NET_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gccore.h>
#include <network.h>

/* net_init() answers -EAGAIN (-11) for a few seconds after boot while IOS
 * brings the interface up; retry for up to 15 s instead of a handful of
 * immediate tries. Prints the result and the Wii's own address. */
static inline s32 hw_net_init(void) {
    s32 r = -1;
    for (int i = 0; i < 150; i++) {
        r = net_init();
        if (r >= 0) break;
        usleep(100 * 1000);
    }
    if (r < 0) {
        printf("net_init failed: %d\n", (int)r);
        return r;
    }
    u32 ip = net_gethostip();
    printf("network up, Wii IP %u.%u.%u.%u\n", (unsigned)(ip >> 24) & 255, (unsigned)(ip >> 16) & 255,
           (unsigned)(ip >> 8) & 255, (unsigned)ip & 255);
    return r;
}

/* TCP log connection to the PC; 3 attempts. Returns the fd or -1 (and prints why). */
static inline s32 hw_log_connect(const char *ip, int port) {
    s32 last = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        s32 fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (fd < 0) {
            last = fd;
            continue;
        }
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((u16)port);
        sa.sin_addr.s_addr = inet_addr(ip);
        last = net_connect(fd, (struct sockaddr *)&sa, sizeof sa);
        if (last >= 0) return fd;
        net_close(fd);
        usleep(500 * 1000);
    }
    printf("log connect to %s:%d failed: %d (PC firewall? same network?)\n", ip, port, (int)last);
    return -1;
}

/* Keeps the console readable before returning to the loader: 3 s normally,
 * 30 s when the PC never got the log (so the screen is the only record). */
static inline void hw_hold_screen(bool logged) {
    if (!logged) printf("\nNo TCP log: returning to the loader in 30 s.\n");
    for (int i = 0; i < 60 * (logged ? 3 : 30); i++) VIDEO_WaitVSync();
}

#endif
