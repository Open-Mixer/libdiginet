// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE DESK MUX (transport/src/diginet_mux.c), the table of desks of
 * include/diginet/transport/diginet_mux.h fed frames from any desk on any interface, in any
 * order, with desks attached and detached, commands submitted and time passing as the input
 * chooses. The sessions it runs are the library's (transport/src/diginet_session.c), which
 * fuzz_transport holds to their own model; this harness holds the mux to its own.
 *
 * The mux's io is the harness: send records each frame and the interface it goes out of,
 * recv hands diginet_mux_poll() a frame and an interface the input chose, if_mac gives
 * interfaces 1 and 2 a MAC of their own and interface 3 none, host_macs lists those two, and
 * the clock is a time the input moves. No socket, no clock, no thread.
 *
 * Input: [flags] [gone_ms 1 + u16] [offline_ms 1 + u16] [wake_timeout_ms 1 + u16], then up to
 * OPS_MAX operations, each [op] and its arguments. flags bit 0: the harness attaches each desk
 * in its APPEARED notice. A desk `who` % 10 is the Digidesign MAC 00:a0:7e:24:00:who for who
 * under 9, else a MAC that is no Digidesign's; an interface `ifx` is 1 + ifx % 3.
 *   op % 8:
 *     0 who ifx kind      an announce from `who` on `ifx`: kind bit 0 e1 else e0; (kind >> 1)
 *                         % 3 the name "CNTRL|24", "MAINUNIT" or "OTHER"; bit 3 the MAC of
 *                         `ifx` at body offset 0 (an e1 naming this host); bit 4 a body one byte
 *                         short of an announce
 *     1 who ifx sel s16 u16-len bytes
 *                         a frame from `who` on `ifx` (fuzz/spec.h, spec_build_frame): (sel & 7) % 7
 *                         the command (data, a0, e0, e1, e2, e3, an unknown 0x55); sel bit 3 to
 *                         broadcast, else to the MAC of `ifx`; sel bit 7 acks the last frame
 *                         sent to that desk, else s16; then the body (at most 1484)
 *     2 ifx u16-len bytes one raw frame
 *     3 scale u16         time passes by u16 times 1 us, 1 ms, 100 ms or 1 s; then tick
 *     4 slot              diginet_mux_attach(slot % 9), slot 8 out of range
 *     5 slot              diginet_mux_detach(slot % 9)
 *     6 slot              a fader command to the session of slot % 8, when there is one
 *     7 pf ifx u16-len bytes
 *                         diginet_mux_poll(), its recv handing over this frame on `ifx`; pf
 *                         bit 0: recv fails instead
 *
 * THE MODEL. The harness keeps the table on its own: which desk is in which slot, on which
 * interface, attached or not, when its last frame came, whether its session ended on silence
 * (seen in that session's own notice). Before each operation it works out what the operation
 * owes; every notice and every frame the library then gives is held to it as it happens, and
 * the table and the deadline after it. No expected value comes from the mux.
 *
 * Properties, each an abort() in a check_ function:
 *   - appear: DIGINET_MUX_N_APPEARED exactly for an announce (an e0 or e1 of the grammar, of
 *     at least 33 body bytes) from a Digidesign MAC no present desk holds while a slot is free,
 *     in the lowest free slot, with its MAC, its interface, the announce and the desk its name
 *     selects; never for anything else.
 *   - route: a frame of a present desk on that desk's interface goes to its session when it is
 *     attached, and to no other; on another interface, or from no present desk, to none;
 *     a session's notice comes under its own desk, and every frame behind one is its desk's.
 *   - send: every frame a session sends goes out of its desk's interface, to that desk, from
 *     that interface's MAC.
 *   - gone: DIGINET_MUX_N_GONE exactly for a present desk silent for gone_ms or whose session
 *     ended on silence, on a tick; then its slot is free and its MAC no desk's.
 *   - attach: diginet_mux_attach() and _detach() answer as the header says, and an attached
 *     session talks to its desk from its interface's MAC.
 *   - deadline: never before now, never more than a second away, never after a present desk's
 *     gone time nor an attached session's own deadline.
 */
#include <errno.h>

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_mux.h>

#include "fuzz.h"

#define OPS_MAX   1024
#define WHO       10
/* The table holds 8 desks. contract: diginet_mux.h:61 */
#define SLOTS     8
/* contract: diginet_mux.h:102-106 */
enum { N_APPEARED = 1, N_GONE, N_SESSION };

static const uint8_t NOTDD[SPEC_MAC] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

static struct diginet_mux g_m;
static uint64_t g_now;
static int g_auto;
static uint32_t g_gone_ms;

static uint64_t ms(uint32_t v)
{
	return (uint64_t)v * 1000u;
}

static void who_mac(unsigned who, uint8_t mac[SPEC_MAC])
{
	if (who >= WHO - 1) {
		memcpy(mac, NOTDD, SPEC_MAC);
		return;
	}
	static const uint8_t base[SPEC_MAC] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x00 };
	memcpy(mac, base, SPEC_MAC);
	mac[5] = (uint8_t)who;
}

/* the harness's interfaces: 1 and 2 have a MAC, 3 none */
static int host_mac(int ifx, uint8_t mac[SPEC_MAC])
{
	if (ifx != 1 && ifx != 2)
		return 0;
	static const uint8_t base[SPEC_MAC] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
	memcpy(mac, base, SPEC_MAC);
	mac[5] = (uint8_t)ifx;
	return 1;
}

/* ---------------------------------------------------------------- the model */

static struct {
	int present, attached, silent;
	uint8_t mac[SPEC_MAC];
	int ifx;
	uint64_t last_rx;
	uint64_t rx_before;     /* the session's frame count before the operation */
	uint32_t last_sent;     /* the counter of the last frame its session sent */
} D[SLOTS];

/* what one operation owes, and what it got */
static struct {
	int appeared, slot, ifx, routed_to, attach_in_notice;
	int ack_to;             /* the attached desk whose session owes this frame an a0, or -1 */
	uint32_t ack_counter;   /* the send counter of that frame */
	uint8_t mac[SPEC_MAC];
	const uint8_t *name, *body;
} OW;
static struct {
	int appeared, routed;
	int acks, ack_desk;
	uint32_t ack_counter;
} GOT;

static int m_find(const uint8_t *mac)
{
	for (int i = 0; i < SLOTS; i++)
		if (D[i].present && !memcmp(D[i].mac, mac, SPEC_MAC))
			return i;
	return -1;
}

static uint64_t session_rx_count(int i)
{
	struct diginet_session *s = diginet_mux_session(&g_m, (unsigned)i);
	return s ? s->stats.rx_frames + s->stats.rx_ignored : 0;
}

static void op_begin(void)
{
	memset(&OW, 0, sizeof OW);
	memset(&GOT, 0, sizeof GOT);
	OW.slot = OW.routed_to = OW.ack_to = -1;
	for (int i = 0; i < SLOTS; i++)
		D[i].rx_before = session_rx_count(i);
}

/* One frame on interface ifx, as the header reads it: a frame of the grammar from a present
 * desk, on its interface, is routed to it; else an announce of a Digidesign MAC no desk holds
 * makes a desk present in the lowest free slot (diginet_mux.h:9-19, :26-27) */
static void m_rx(const uint8_t *frame, size_t n, int ifx)
{
	struct spec_frame f;
	if (spec_read_frame(frame, n, &f) != SPEC_OK)
		return;
	int i = m_find(f.src);
	if (i >= 0) {
		if (D[i].ifx != ifx)
			return;
		D[i].last_rx = g_now;
		OW.routed_to = i;
		/* an attached desk's session reads a data frame for this interface's MAC, or a
		 * broadcast one, and ACKs it (diginet_session.h:15) */
		uint8_t mine[SPEC_MAC];
		if (D[i].attached && f.cmd == SPEC_CMD_DATA &&
		    (!memcmp(f.dst, SPEC_BCAST, SPEC_MAC) || (host_mac(ifx, mine) && !memcmp(f.dst, mine, SPEC_MAC)))) {
			OW.ack_to = i;
			OW.ack_counter = f.send;
		}
		return;
	}
	if (memcmp(f.src, SPEC_OUI, sizeof SPEC_OUI) || (f.cmd != SPEC_CMD_E0 && f.cmd != SPEC_CMD_E1) ||
	    f.body_len < SPEC_ANN_MIN)
		return;
	for (i = 0; i < SLOTS && D[i].present; i++)
		;
	if (i == SLOTS)
		return;
	OW.appeared = 1;
	OW.slot = i;
	OW.ifx = ifx;
	OW.name = f.body + SPEC_ANN_NAME;
	OW.body = f.body;
	memcpy(OW.mac, f.src, SPEC_MAC);
	memset(&D[i], 0, sizeof D[i]);
	D[i].present = 1;
	memcpy(D[i].mac, f.src, SPEC_MAC);
	D[i].ifx = ifx;
	D[i].last_rx = g_now;
}

/* the desk a name selects (docs/protocol.md:47) */
static const struct spec_desk *desk_named(const uint8_t *name)
{
	size_t n = spec_strz_len(name);
	if (n == strlen(SPEC_C24.name) && !memcmp(name, SPEC_C24.name, n))
		return &SPEC_C24;
	if (n == strlen(SPEC_PC.name) && !memcmp(name, SPEC_PC.name, n))
		return &SPEC_PC;
	return NULL;
}

/* ---------------------------------------------------------------- the properties */

FUZZ_CHECK check_appear_notice(const struct diginet_mux_notice *n)
{
	/* An APPEARED notice comes only for the announce of a new desk while a slot is free.
	 * contract: diginet_mux.h:9-12, :26-27
	 * mutant: transport/src/diginet_mux.c:155 `!diginet_mac_is_digidesign(f.src) || ` -> ``
	 * input: set-aside
	 * mutant: transport/src/diginet_mux.c:139 `if (i >= 0) {` -> `if (i >= 0 && 0) {`
	 * input: pinned */
	if (!OW.appeared || GOT.appeared > 1)
		abort();
	/* It names the lowest free slot, the desk's MAC and the interface it came in on.
	 * contract: diginet_mux.h:9-12, :107-109
	 * mutant: transport/src/diginet_mux.c:172 `d->ifindex = ifindex;` -> `d->ifindex = 1;`
	 * input: two-desks
	 * mutant: transport/src/diginet_mux.c:161 `!m->desks[k].present` -> `!m->desks[k].present && k > 0`
	 * input: two-desks */
	if ((int)n->desk != OW.slot || !n->mac || memcmp(n->mac, OW.mac, SPEC_MAC) || n->ifindex != OW.ifx)
		abort();
	const struct spec_desk *want = desk_named(OW.name);
	size_t nn = spec_strz_len(OW.name);
	/* It carries the announce, and the desk its name selects.
	 * contract: diginet_mux.h:104, :110-111; docs/protocol.md:47
	 * mutant: transport/src/diginet_mux.c:43 `n.personality = diginet_personality_from_name(a->name);` -> `(void)0;`
	 * input: two-desks */
	if (!n->announce || memcmp(n->announce->name, OW.name, nn) || n->announce->name[nn] ||
	    !n->personality != !want || (want && n->personality->device != want->device))
		abort();
	size_t vn = spec_strz_len(OW.body + SPEC_ANN_VERSION);
	/* Its version is the body bytes from 15, up to the first NUL and at most 9, terminated.
	 * contract: diginet_mux.h:104; protocol/diginet.ksy `announce` `version` (strz, size: 9)
	 * mutant: transport/src/diginet_mux.c:175 `m->stats.appeared++;` -> `m->stats.appeared++, a.version[0] = 0;`
	 * input: two-desks */
	if (memcmp(n->announce->version, OW.body + SPEC_ANN_VERSION, vn) || n->announce->version[vn])
		abort();
	/* Its unknown field is the first 15 body bytes, the same bytes.
	 * contract: diginet.h:130-131; protocol/diginet.ksy `announce`
	 * mutant: transport/src/diginet_mux.c:175 `m->stats.appeared++;` -> `m->stats.appeared++, a.unknown_len = 0;`
	 * input: two-desks */
	if (n->announce->unknown_len != SPEC_ANN_UNKNOWN || memcmp(n->announce->unknown, OW.body, SPEC_ANN_UNKNOWN))
		abort();
}

FUZZ_CHECK check_appear_settle(void)
{
	/* Every appearance owed came: a new desk's announce while a slot is free.
	 * contract: diginet_mux.h:9-12, :26-27
	 * mutant: transport/src/diginet_mux.c:176 `notify_desk(m, d, DIGINET_MUX_N_APPEARED, &a, NULL);` -> `(void)a;`
	 * input: two-desks
	 * mutant: transport/src/diginet_mux.c:160 `k < DIGINET_MUX_MAX_DESKS && !d` -> `k < DIGINET_MUX_MAX_DESKS - 1 && !d`
	 * input: table-full */
	if (OW.appeared != GOT.appeared)
		abort();
}

FUZZ_CHECK check_route_notice(const struct diginet_mux_notice *n)
{
	/* A session's notice comes under its own desk, an attached one, and a frame behind it is
	 * that desk's.
	 * contract: diginet_mux.h:20-23, :105
	 * mutant: transport/src/diginet_mux.c:65 `notify_desk(d->mux, d, DIGINET_MUX_N_SESSION, NULL, sn);` -> `notify_desk(d->mux, &d->mux->desks[0], DIGINET_MUX_N_SESSION, NULL, sn);`
	 * input: two-desks */
	if (n->desk >= SLOTS || !D[n->desk].present || !D[n->desk].attached || !n->session ||
	    (n->session->frame && memcmp(n->session->frame->src, D[n->desk].mac, SPEC_MAC)))
		abort();
}

FUZZ_CHECK check_route_settle(void)
{
	for (int i = 0; i < SLOTS; i++) {
		/* the session reads a frame it is given: it counts it as read or as set aside, at
		 * least once (diginet_session.h, struct diginet_session_stats) */
		int owed = (i == OW.routed_to && D[i].attached) || (i == OW.slot && OW.attach_in_notice);
		uint64_t got = session_rx_count(i);
		/* A frame of a present desk on its interface reaches its attached session, and no
		 * other session; on another interface, or from no desk, none.
		 * contract: diginet_mux.h:12-19, :21-23, :26-27
		 * mutant: transport/src/diginet_mux.c:141 `if (d->ifindex != ifindex) {` -> `if (0) {`
		 * input: pinned
		 * mutant: transport/src/diginet_mux.c:147 `if (d->attached)` -> `if (0)`
		 * input: two-desks
		 * mutant: transport/src/diginet_mux.c:178 `if (d->present && d->attached)` -> `if (0)`
		 * input: auto-attach
		 * mutant: transport/src/diginet_mux.c:179 `frame, len` -> `frame, 0`
		 * input: auto-attach */
		if (D[i].present && D[i].attached && (owed ? got <= D[i].rx_before : got != D[i].rx_before))
			abort();
	}
	/* The session got the frame itself: a data frame routed to an attached desk makes that
	 * desk's session send one a0 with the frame's send counter (check_send_frame holds where
	 * it goes), and no other frame makes one.
	 * contract: diginet_mux.h:12-19; diginet_session.h:15
	 * mutant: transport/src/diginet_mux.c:148 `frame, len` -> `frame, 0`
	 * input: two-desks */
	if (GOT.acks != (OW.ack_to >= 0) ||
	    (OW.ack_to >= 0 && (GOT.ack_desk != OW.ack_to || GOT.ack_counter != OW.ack_counter)))
		abort();
}

FUZZ_CHECK check_send_frame(int ifx, const uint8_t *frame, size_t len)
{
	struct spec_frame f;
	spec_read_frame(frame, len, &f);
	int i = f.code == SPEC_OK ? m_find(f.dst) : -1;
	uint8_t mine[SPEC_MAC];
	/* A frame a session sends goes to an attached desk, out of that desk's interface, from that
	 * interface's MAC.
	 * contract: diginet_mux.h:20-22, :82-83
	 * mutant: transport/src/diginet_mux.c:51 `d->ifindex, frame, len);` -> `1, frame, len);`
	 * input: two-desks */
	if (i < 0 || !D[i].attached || ifx != D[i].ifx || !host_mac(ifx, mine) || memcmp(f.src, mine, SPEC_MAC))
		abort();
	D[i].last_sent = f.send;
	if (f.cmd == SPEC_CMD_ACK) {
		GOT.acks++;
		GOT.ack_desk = i;
		GOT.ack_counter = f.ack;
	}
}

FUZZ_CHECK check_gone_notice(const struct diginet_mux_notice *n, int ticking)
{
	/* A desk is gone only on a tick, only when present and silent for gone_ms or its session
	 * ended on silence.
	 * contract: diginet_mux.h:24-27, :106
	 * mutant: transport/src/diginet_mux.c:200 `>= ms(m->cfg.gone_ms)` -> `>= ms(m->cfg.gone_ms) / 2`
	 * input: gone-exact
	 * mutant: transport/src/diginet_mux.c:200 `if (d->silent || ` -> `if (d->attached || `
	 * input: gone-silence */
	if (!ticking || n->desk >= SLOTS || !D[n->desk].present ||
	    !(D[n->desk].silent || g_now - D[n->desk].last_rx >= ms(g_gone_ms)) ||
	    memcmp(n->mac, D[n->desk].mac, SPEC_MAC) || n->ifindex != D[n->desk].ifx)
		abort();
}

FUZZ_CHECK check_gone_settle(int ticked)
{
	for (int i = 0; i < SLOTS; i++) {
		/* After a tick no desk is left that is silent for gone_ms or whose session ended on
		 * silence.
		 * contract: diginet_mux.h:24-27
		 * mutant: transport/src/diginet_mux.c:200 `>= ms(m->cfg.gone_ms)` -> `> ms(m->cfg.gone_ms)`
		 * input: gone-exact
		 * mutant: transport/src/diginet_mux.c:200 `if (d->silent || ` -> `if (`
		 * input: gone-silence
		 * mutant: transport/src/diginet_mux.c:64 `d->silent = 1;` -> `(void)0;`
		 * input: gone-silence */
		if (ticked && D[i].present && (D[i].silent || g_now - D[i].last_rx >= ms(g_gone_ms)))
			abort();
		/* A desk gone is forgotten: its slot free and its MAC no desk's.
		 * contract: diginet_mux.h:24-25, :106
		 * mutant: transport/src/diginet_mux.c:187 `memset(d, 0, sizeof *d);` -> `d->silent = 0;`
		 * input: gone-exact */
		if (!D[i].present && g_m.desks[i].present)
			abort();
	}
}

FUZZ_CHECK check_attach_code(int rc, int want)
{
	/* attach answers DIGINET_E_ARG for a slot out of range, with no desk or attached, the io's
	 * code when the interface has no MAC, and DIGINET_OK otherwise; detach DIGINET_E_ARG for
	 * a desk not attached.
	 * contract: diginet_mux.h:144-150, :152-156
	 * mutant: transport/src/diginet_mux.c:83 `if (!d->present || d->attached)` -> `if (!d->present)`
	 * input: attach-refusals
	 * mutant: transport/src/diginet_mux.c:87 `if (r < 0)` -> `if (r < -100)`
	 * input: attach-refusals
	 * mutant: transport/src/diginet_mux.c:111 `!m->desks[desk].attached)` -> `!m->desks[desk].present)`
	 * input: attach-refusals */
	if (rc != want)
		abort();
}

FUZZ_CHECK check_attach_other_macs(const struct diginet_session *s, int i)
{
	uint8_t other[SPEC_MAC];
	host_mac(D[i].ifx == 1 ? 2 : 1, other);
	/* An attached desk's session knows this host's other MACs: every MAC host_macs lists but
	 * its own interface's.
	 * contract: diginet_mux.h:14-19, :151-153
	 * mutant: transport/src/diginet_mux.c:91 `if (m->io.host_macs) {` -> `if (0) {`
	 * input: two-desks
	 * mutant: transport/src/diginet_mux.c:96 `if (memcmp(all[i], c.host_mac, DIGINET_MAC_LEN))` -> `if (1)`
	 * input: two-desks */
	if (s->cfg.n_other_host_macs != 1 || memcmp(s->cfg.other_host_macs[0], other, SPEC_MAC))
		abort();
}

FUZZ_CHECK check_attach_session(int i)
{
	struct diginet_session *s = diginet_mux_session(&g_m, (unsigned)i);
	uint8_t mine[SPEC_MAC];
	/* An attached desk's session talks to that desk only, from its interface's MAC.
	 * contract: diginet_mux.h:20-21, :144-147
	 * mutant: transport/src/diginet_mux.c:90 `c.desk_mac_set = 1;` -> `c.desk_mac_set = 0;`
	 * input: two-desks
	 * mutant: transport/src/diginet_mux.c:86 `d->ifindex, c.host_mac);` -> `1, c.host_mac);`
	 * input: two-desks */
	if (!s || !s->cfg.desk_mac_set || memcmp(s->cfg.desk_mac, D[i].mac, SPEC_MAC) || !host_mac(D[i].ifx, mine) ||
	    memcmp(s->cfg.host_mac, mine, SPEC_MAC))
		abort();
	check_attach_other_macs(s, i);
}

FUZZ_CHECK check_deadline(void)
{
	uint64_t d = diginet_mux_deadline(&g_m, g_now);
	/* The deadline is now or later, and never more than a second away.
	 * contract: diginet_mux.h:135-136
	 * mutant: transport/src/diginet_mux.c:210 `now_us + 1000000` -> `now_us + 1000001`
	 * input: set-aside */
	if (d < g_now || d > g_now + 1000000)
		abort();
	for (int i = 0; i < SLOTS; i++) {
		if (!D[i].present)
			continue;
		uint64_t gone = D[i].last_rx + ms(g_gone_ms);
		struct diginet_session *s = diginet_mux_session(&g_m, (unsigned)i);
		/* Nor later than a present desk's gone time, nor than an attached session's deadline.
		 * contract: diginet_mux.h:24-27, :135-136; diginet_session.h:182-183
		 * mutant: transport/src/diginet_mux.c:219 `k->last_rx_us + ms(m->cfg.gone_ms)` -> `k->last_rx_us + 2 * ms(m->cfg.gone_ms)`
		 * input: gone-exact
		 * mutant: transport/src/diginet_mux.c:220 `if (k->attached)` -> `if (0)`
		 * input: two-desks */
		if ((gone > g_now && d > gone) || (s && d > diginet_session_deadline(s, g_now)))
			abort();
	}
}

/* ---------------------------------------------------------------- the io and the notices */

static int g_ticking;

static int io_send(void *ctx, int ifindex, const uint8_t *frame, size_t len)
{
	(void)ctx;
	check_send_frame(ifindex, frame, len);
	return 0;
}

static const uint8_t *g_rx;
static size_t g_rx_len;
static int g_rx_ifx, g_rx_fail;

static int io_recv(void *ctx, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms)
{
	(void)ctx;
	(void)timeout_ms;
	if (g_rx_fail) {
		g_rx_fail = 0;
		return -EIO;
	}
	if (!g_rx)
		return 0;
	size_t n = g_rx_len < cap ? g_rx_len : cap;
	memcpy(buf, g_rx, n);
	*ifindex = g_rx_ifx;
	g_rx = NULL;
	return (int)n;
}

static int io_if_mac(void *ctx, int ifindex, uint8_t mac[DIGINET_MAC_LEN])
{
	(void)ctx;
	return host_mac(ifindex, mac) ? 0 : -ENODEV;
}

static uint64_t io_now(void *ctx)
{
	(void)ctx;
	return g_now;
}

static int io_host_macs(void *ctx, uint8_t (*macs)[DIGINET_MAC_LEN], unsigned cap)
{
	(void)ctx;
	unsigned n = 0;
	for (int ifx = 1; ifx <= 3 && n < cap; ifx++)
		if (host_mac(ifx, macs[n]))
			n++;
	return (int)n;
}

static void notice(void *ctx, const struct diginet_mux_notice *n)
{
	(void)ctx;
	switch (n->kind) {
	case N_APPEARED:
		GOT.appeared++;
		check_appear_notice(n);
		if (g_auto) {
			int want = host_mac(D[n->desk].ifx, (uint8_t[SPEC_MAC]){ 0 }) ? SPEC_OK : -ENODEV;
			check_attach_code(diginet_mux_attach(&g_m, n->desk, NULL), want);
			if (want == SPEC_OK) {
				D[n->desk].attached = 1;
				D[n->desk].rx_before = 0;
				OW.attach_in_notice = 1;
				check_attach_session((int)n->desk);
			}
		}
		break;
	case N_SESSION:
		check_route_notice(n);
		if (n->session->kind == DIGINET_N_STATE && n->session->state == DIGINET_S_IDLE &&
		    n->session->reason == DIGINET_R_SILENCE)
			D[n->desk].silent = 1;
		break;
	case N_GONE:
		check_gone_notice(n, g_ticking);
		memset(&D[n->desk], 0, sizeof D[n->desk]);
		break;
	default:
		break;
	}
}

/* ---------------------------------------------------------------- the operations */

static void settle(int ticked)
{
	check_appear_settle();
	check_route_settle();
	check_gone_settle(ticked);
	check_deadline();
}

static void receive(const uint8_t *p, size_t n, int ifx)
{
	uint8_t *frame = fuzz_dup(p, n);
	op_begin();
	m_rx(frame, n, ifx);
	diginet_mux_rx(&g_m, frame, n, ifx, g_now);
	settle(0);
	free(frame);
}

static void tick(void)
{
	op_begin();
	g_ticking = 1;
	diginet_mux_tick(&g_m, g_now);
	g_ticking = 0;
	settle(1);
}

static void op_announce(struct fuzz_in *in)
{
	static const char *const NAME[3] = { "CNTRL|24", "MAINUNIT", "OTHER" };
	uint8_t mac[SPEC_MAC], body[SPEC_ANN_MIN], frame[SPEC_MAX_FRAME];
	who_mac(fuzz_u8(in) % WHO, mac);
	int ifx = 1 + fuzz_u8(in) % 3;
	uint8_t kind = fuzz_u8(in);
	memset(body, 0, sizeof body);
	if (kind & 8)
		host_mac(ifx, body);
	memcpy(body + SPEC_ANN_VERSION, "1.08", 4);
	const char *name = NAME[(kind >> 1) % 3];
	memcpy(body + SPEC_ANN_NAME, name, strlen(name));
	size_t n = spec_build_frame(frame, SPEC_BCAST, mac, 0, 0, 0, kind & 1 ? SPEC_CMD_E1 : SPEC_CMD_E0, 0,
				    body, kind & 16 ? sizeof body - 1 : sizeof body, 0);
	receive(frame, n, ifx);
}

static void op_frame(struct fuzz_in *in)
{
	static const uint8_t CMD[7] = {
		SPEC_CMD_DATA, SPEC_CMD_ACK, SPEC_CMD_E0, SPEC_CMD_E1, SPEC_CMD_E2, SPEC_CMD_E3, 0x55,
	};
	uint8_t mac[SPEC_MAC], dst[SPEC_MAC], frame[SPEC_MAX_FRAME];
	const uint8_t *body;
	who_mac(fuzz_u8(in) % WHO, mac);
	int ifx = 1 + fuzz_u8(in) % 3;
	uint8_t sel = fuzz_u8(in);
	uint32_t send = fuzz_u16(in), ack = send;
	size_t len = fuzz_take(in, fuzz_u16(in) % (SPEC_MAX_BODY + 1), &body);
	if (sel & 8 || !host_mac(ifx, dst))
		memcpy(dst, SPEC_BCAST, SPEC_MAC);
	int i = m_find(mac);
	if (sel & 0x80 && i >= 0)
		ack = D[i].last_sent;
	size_t n = spec_build_frame(frame, dst, mac, send, ack, 0, CMD[(sel & 7) % 7], 1, body, len, 0);
	receive(frame, n, ifx);
}

static void op_attach(struct fuzz_in *in)
{
	unsigned slot = fuzz_u8(in) % (SLOTS + 1);
	int want = slot >= SLOTS || !D[slot].present || D[slot].attached ? SPEC_E_ARG
		   : host_mac(D[slot].ifx, (uint8_t[SPEC_MAC]){ 0 }) ? SPEC_OK : -ENODEV;
	op_begin();
	check_attach_code(diginet_mux_attach(&g_m, slot, NULL), want);
	if (want == SPEC_OK) {
		D[slot].attached = 1;
		D[slot].rx_before = session_rx_count((int)slot);
		check_attach_session((int)slot);
	}
	settle(0);
}

static void op_detach(struct fuzz_in *in)
{
	unsigned slot = fuzz_u8(in) % (SLOTS + 1);
	/* the session's close answers 0 here: the harness's send never fails */
	int want = slot < SLOTS && D[slot].attached ? SPEC_OK : SPEC_E_ARG;
	op_begin();
	check_attach_code(diginet_mux_detach(&g_m, slot, g_now), want);
	if (want == SPEC_OK) {
		D[slot].attached = 0;
		D[slot].silent = 0;
	}
	settle(0);
}

static void op_submit(struct fuzz_in *in)
{
	unsigned slot = fuzz_u8(in) % SLOTS;
	struct diginet_session *s = diginet_mux_session(&g_m, slot);
	if (!s)
		return;
	struct diginet_cmd c;
	memset(&c, 0, sizeof c);
	c.key = SPEC_KEY(1, slot);
	c.len = 5;
	c.bytes[0] = 0xb0;
	c.bytes[1] = (uint8_t)slot;
	c.bytes[2] = 0x40;
	c.bytes[3] = (uint8_t)(0x20 + slot);
	c.bytes[4] = 0x00;
	op_begin();
	diginet_session_submit(s, &c);
	settle(0);
}

static void op_poll(struct fuzz_in *in)
{
	const uint8_t *p;
	unsigned pf = fuzz_u8(in);
	int ifx = 1 + fuzz_u8(in) % 3;
	size_t n = fuzz_record(in, &p);
	size_t got = n > SPEC_MAX_FRAME ? SPEC_MAX_FRAME : n;   /* what recv hands over */
	uint8_t *frame = fuzz_dup(p, got);
	op_begin();
	int fails = pf & 1;
	if (!fails && got)
		m_rx(frame, got, ifx);
	g_rx = got ? frame : NULL;
	g_rx_len = got;
	g_rx_ifx = ifx;
	g_rx_fail = fails;
	g_ticking = !fails;
	diginet_mux_poll(&g_m, 0);
	g_ticking = 0;
	g_rx = NULL;
	g_rx_fail = 0;
	settle(!fails);
	free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint64_t SCALE[4] = { 1, 1000, 100000, 1000000 };
	struct diginet_mux_io io = { NULL, io_send, io_recv, io_if_mac, io_now, io_host_macs };
	struct diginet_mux_config cfg;

	if (size >= FUZZ_INPUT_MAX)
		return 0;
	struct fuzz_in in = fuzz_in(data, size);
	uint8_t flags = fuzz_u8(&in);
	diginet_mux_config_default(&cfg);
	g_auto = flags & 1;
	g_gone_ms = cfg.gone_ms = 1u + fuzz_u16(&in);
	cfg.session.offline_ms = 1u + fuzz_u16(&in);
	cfg.session.wake_timeout_ms = 1u + fuzz_u16(&in);
	g_now = 1000000;
	memset(D, 0, sizeof D);
	g_rx = NULL;
	g_ticking = 0;
	/* Every config made above is one the mux takes.
	 * contract: diginet_mux.h:125-126
	 * mutant: transport/src/diginet_mux.c:22 `!io->if_mac ||` -> `io->if_mac ||`
	 * input: two-desks */
	if (diginet_mux_init(&g_m, &cfg, &io, notice, NULL) != SPEC_OK)
		abort();

	for (int ops = 0; ops < OPS_MAX && in.n; ops++) {
		const uint8_t *p;
		size_t n;
		switch (fuzz_u8(&in) % 8) {
		case 0:
			op_announce(&in);
			break;
		case 1:
			op_frame(&in);
			break;
		case 2: {
			int ifx = 1 + fuzz_u8(&in) % 3;
			n = fuzz_record(&in, &p);
			receive(p, n, ifx);
			break;
		}
		case 3: {
			uint64_t scale = SCALE[fuzz_u8(&in) % 4];
			g_now += scale * fuzz_u16(&in);
			tick();
			break;
		}
		case 4:
			op_attach(&in);
			break;
		case 5:
			op_detach(&in);
			break;
		case 6:
			op_submit(&in);
			break;
		default:
			op_poll(&in);
			break;
		}
	}
	return 0;
}
