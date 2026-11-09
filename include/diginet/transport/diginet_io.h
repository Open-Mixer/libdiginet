/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet-transport: the wire under a session. A session never touches a socket or a
 * clock directly; it calls the three functions of a struct diginet_io. The packet socket is
 * one implementation, a socketpair or an in-process desk emulator is another, so every
 * behaviour of the session can be tested without hardware or privileges.
 *
 * Two kinds of packet socket: one bound to an interface (diginet_packet_open), driven through
 * struct diginet_io; and one bound to none (diginet_packet_open_any), which hears every
 * interface and sends out of the one a desk is on, driven by the desk mux (diginet_mux.h).
 * The second can be opened by a small privileged helper and handed to an unprivileged process
 * over a Unix socket.
 */
#ifndef DIGINET_IO_H
#define DIGINET_IO_H

#include <stddef.h>
#include <stdint.h>

#include <diginet/diginet.h>

#ifdef __cplusplus
extern "C" {
#endif

struct diginet_io {
	void *ctx;
	/* Send one whole Ethernet frame. 0, or a negative errno. */
	int (*send)(void *ctx, const uint8_t *frame, size_t len);
	/* Receive one frame, waiting at most timeout_ms (0: do not wait). Returns its length,
	 * 0 when nothing came, or a negative errno. */
	int (*recv)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
	/* A monotonic clock in microseconds. */
	uint64_t (*now_us)(void *ctx);
};

/* CLOCK_MONOTONIC in microseconds. */
uint64_t diginet_clock_us(void);

/* An io over a descriptor that carries whole frames: an AF_PACKET socket from
 * diginet_packet_open(), one handed over by a privileged launcher, or one end of a
 * SOCK_SEQPACKET socketpair. Frames an AF_PACKET socket reports as outgoing are skipped.
 * `store` holds the state and must outlive `io`. */
struct diginet_fd_io {
	int fd;
};
void diginet_io_fd(struct diginet_io *io, struct diginet_fd_io *store, int fd);

/* An AF_PACKET socket bound to EtherType 0x885F on the interface `ifname`. The protocol is
 * given to bind(), never to socket(), so the socket hears nothing from any other interface.
 * Needs CAP_NET_RAW. On success returns the descriptor and fills the interface's MAC; on
 * failure returns a negative errno (-EPERM without the capability, -ENODEV for a name that
 * does not exist). */
int diginet_packet_open(const char *ifname, uint8_t mac[DIGINET_MAC_LEN]);

/* ---- one socket for every interface ---- */

/* An AF_PACKET socket bound to EtherType 0x885F and to no interface: it hears the desks on every
 * interface, those that come up after it too. Frames are taken with diginet_packet_recvfrom(),
 * which names the interface each came in on, and sent with diginet_packet_sendto() out of the
 * one a desk is on. Needs CAP_NET_RAW at this call only: the descriptor works without it, so a
 * process that holds the capability can open it and hand it over (diginet_packet_send_fd()).
 * Returns the descriptor, or a negative errno (-EPERM without the capability). */
int diginet_packet_open_any(void);

/* Receive one frame, waiting at most timeout_ms (0: do not wait), and the index of the
 * interface it came in on (0 for a descriptor that is not a packet socket). Frames the socket
 * reports as outgoing, our own on every interface, are skipped. Returns the length, 0 when
 * nothing came, or a negative errno. */
int diginet_packet_recvfrom(int fd, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms);

/* Send one whole Ethernet frame out of interface `ifindex`, to the destination its first six
 * bytes name. 0, or a negative errno (-EINVAL for an ifindex <= 0 or a frame shorter than its
 * Ethernet header). */
int diginet_packet_sendto(int fd, int ifindex, const uint8_t *frame, size_t len);

/* The MAC address of interface `ifindex`: the host MAC a desk on that interface talks to. Needs
 * no privilege. 0, or a negative errno (-ENODEV when there is no such interface). */
int diginet_if_mac(int ifindex, uint8_t mac[DIGINET_MAC_LEN]);

/* The MACs of this host's interfaces that have one (loopback and an all-zero MAC left out), at
 * most cap of them: their count, or a negative errno. */
int diginet_host_macs(uint8_t (*macs)[DIGINET_MAC_LEN], unsigned cap);

/* ---- a packet socket handed over a Unix socket (SCM_RIGHTS) ---- */

/* Pass descriptor `fd` over the connected AF_UNIX socket `unix_sock`, with one byte of data.
 * 0, or a negative errno. */
int diginet_packet_send_fd(int unix_sock, int fd);

/* Take one descriptor from the connected AF_UNIX socket `unix_sock`, as diginet_packet_send_fd()
 * passes it; waits for it. Only an AF_PACKET socket is taken: any other descriptor is closed and
 * refused with -EPROTO, as is a message carrying more than one (all of them closed). Returns the
 * descriptor (close-on-exec), -EPIPE when the peer closed with none, or a negative errno. */
int diginet_packet_receive_fd(int unix_sock);

/* Open the any-interface socket through `helper` (NULL: "diginet-packet-helper", looked up in
 * PATH), a program that holds cap_net_raw (docs/diginet-packet-helper.1): it is started with a
 * connected AF_UNIX socket on its descriptor 3 and an empty environment, opens the socket, passes
 * it back and exits. Returns the descriptor; -ENOENT when there is no such program, -EPERM when
 * it ran without the capability (its exit status 1), -EACCES when the caller may not run it (the
 * packages let only root and the group diginet run it), -EPROTO when it ended any other way
 * without passing one, or a negative errno. Not for a hot path: it starts a process and waits for it. */
int diginet_packet_open_by_helper(const char *helper);

#ifdef __cplusplus
}
#endif

#endif
