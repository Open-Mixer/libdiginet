// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
/* diginet-census: every control of a desk, checked one by one with an operator at the desk.
 *
 * The census wakes the desk like diginet-probe does, then walks the library's inventory
 * (diginet_census.h) in order: for an input control it tells the operator what to do and
 * waits for the desk to send it, and decodes what came; for an output control it writes the
 * frame that exercises it and asks whether the desk shows it, then clears it. Every verdict
 * goes to the report and every desk body to the record, in the golden format tests/test_census
 * reads back, so a row of the inventory the desk contradicts turns a test red:
 *
 *   PASS      the desk sent what the inventory says (input), or the operator saw it (output)
 *   MISMATCH  the desk sent something else: the bytes and the decoded event are recorded
 *   MISSING   the operator said nothing came (n), or the wait ran out
 *   FAIL      the operator saw nothing (n) after a write
 *   SKIP      the operator skipped it (s)
 *
 * Answers on stdin: Enter or y = seen, n = not seen, s = skip, q = stop the census here.
 * Exit 0 when every walked control passed or was skipped, 1 when one did not, 2 usage,
 * 3 the desk is in another host's session, 4 no desk, 5 the desk did not ACK our writes.
 */
#include <diginet/diginet_census.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_mux.h>
#include <diginet/transport/diginet_session.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { EXIT_OK = 0, EXIT_RED = 1, EXIT_USAGE = 2, EXIT_FOREIGN = 3, EXIT_NO_DESK = 4, EXIT_NO_ACK = 5 };

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static struct diginet_session S0, *S = &S0;
static uint64_t t0;
static const struct diginet_personality *P;
static FILE *report, *record, *frames;

static struct {
	int desk_seen, foreign, online, acked_wake;
	char name[10], version[10];
	unsigned acked, lost, desk_frames;
	/* the walk */
	unsigned pass, mismatch, missing, fail, skip;
	/* the input step in progress */
	const struct diginet_control *waiting;
	const struct diginet_control *last_in;   /* its later events (release, more motion) are not a mismatch */
	int got;                                 /* 1 matched, -1 mismatched */
	char got_text[200];
	uint8_t got_body[DIGINET_CMD_MAX_LEN];
	int got_len;
} R;

static double secs(void) { return (double)(diginet_clock_us() - t0) / 1e6; }

static void say(const char *fmt, ...)
{
	va_list ap;
	printf("[%7.3f] ", secs());
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static void hex_of(char *out, size_t n, const uint8_t *b, size_t len)
{
	size_t o = 0;
	for (size_t i = 0; i < len && o + 4 < n; i++)
		o += (size_t)snprintf(out + o, n - o, "%s%02x", i ? " " : "", b[i]);
	out[o] = '\0';
}

static const char *strip_button_name(unsigned b)
{
	static const char *n[] = { "REC", "PAN/SEND", "EQ", "DYN", "ACTIVE", "AUTO", "SELECT",
				   "SOLO", "MUTE", "TOUCH", "INSERTS", "PEAK", "SOURCE", "ROLL-OFF" };
	return b < sizeof n / sizeof n[0] ? n[b] : "?";
}

static void event_text(const struct diginet_event *ev, char *out, size_t n)
{
	switch (ev->kind) {
	case DIGINET_EV_FADER:
		snprintf(out, n, "fader %u at %u%s", ev->strip + 1, ev->value, ev->lsb_missing ? " (no LSB)" : "");
		break;
	case DIGINET_EV_TOUCH:
		snprintf(out, n, "fader %u %s", ev->strip + 1, ev->on ? "touched" : "released");
		break;
	case DIGINET_EV_STRIP_BUTTON:
		snprintf(out, n, "strip %u %s %s", ev->strip + 1, strip_button_name(ev->button),
			 ev->on ? "pressed" : "released");
		break;
	case DIGINET_EV_SECTION_BUTTON:
		snprintf(out, n, "zone 0x%02x button 0x%02x %s", ev->zone, ev->button, ev->on ? "pressed" : "released");
		break;
	case DIGINET_EV_VPOT:
		snprintf(out, n, "V-Pot %u %+d", ev->strip + 1, ev->delta);
		break;
	case DIGINET_EV_JOG:
		snprintf(out, n, "jog %+d", ev->delta);
		break;
	default:
		snprintf(out, n, "other (status %02x)", ev->msg.status);
		break;
	}
}

/* The bytes of one decoded command, for the record. */
static int event_bytes(const struct diginet_event *ev, uint8_t *out)
{
	if (ev->msg.status == 0xf0) {
		size_t n = ev->msg.sysex_len + 2;
		if (n > DIGINET_CMD_MAX_LEN)
			n = DIGINET_CMD_MAX_LEN;
		memcpy(out, ev->msg.sysex - 1, n);
		return (int)n;
	}
	out[0] = ev->msg.status;
	out[1] = ev->msg.d1;
	out[2] = ev->msg.d2;
	return 3;
}

/* A fader pair as the desk sends it: MSB then LSB; the decoder joins them into one event
 * whose msg is the LSB's, so the record carries both. */
static void record_body(const char *name, const uint8_t *b, int len)
{
	char hex[3 * DIGINET_CMD_MAX_LEN + 1];
	hex_of(hex, sizeof hex, b, (size_t)len);
	fprintf(record, "%s %s\n", name, hex);
	fflush(record);
}

static void log_event(const struct diginet_event *ev, unsigned counter)
{
	char text[160];
	event_text(ev, text, sizeof text);
	say("desk: %s", text);
	const struct diginet_control *c = R.waiting;
	if (!c)
		return;
	if (diginet_census_matches(c, ev)) {
		R.got = 1;
	} else if (R.last_in && diginet_census_matches(R.last_in, ev)) {
		return;   /* the previous control still moving: not this step's */
	} else if (!ev->on && (ev->kind == DIGINET_EV_TOUCH || ev->kind == DIGINET_EV_STRIP_BUTTON ||
			       ev->kind == DIGINET_EV_SECTION_BUTTON)) {
		return;   /* a release is never a mismatch */
	} else if (R.got == 0) {
		R.got = -1;
	}
	if (R.got != 0 && R.got_len == 0) {
		snprintf(R.got_text, sizeof R.got_text, "%s (desk frame %u)", text, counter);
		if (ev->kind == DIGINET_EV_FADER && !ev->lsb_missing) {
			/* MSB then LSB as sent: B0 ss msb, B0 (20|ss) lsb */
			R.got_body[0] = 0xb0;
			R.got_body[1] = ev->strip;
			R.got_body[2] = (uint8_t)(ev->value >> 3);
			R.got_body[3] = 0xb0;
			R.got_body[4] = (uint8_t)(0x20 | ev->strip);
			R.got_body[5] = (uint8_t)((ev->value & 7) << 4);
			R.got_len = 6;
		} else {
			R.got_len = event_bytes(ev, R.got_body);
		}
	}
}

static void on_notice(void *ctx, const struct diginet_notice *n)
{
	(void)ctx;
	switch (n->kind) {
	case DIGINET_N_DESK:
		if (!R.desk_seen) {
			R.desk_seen = 1;
			snprintf(R.name, sizeof R.name, "%s", n->announce->name);
			snprintf(R.version, sizeof R.version, "%s", n->announce->version);
			if (n->personality)
				P = n->personality;
			const uint8_t *m = n->frame->src;
			say("desk: %02x:%02x:%02x:%02x:%02x:%02x name \"%s\" version \"%s\" (%s)",
			    m[0], m[1], m[2], m[3], m[4], m[5], R.name, R.version,
			    !n->personality ? "unknown personality" :
			    n->personality->desk == DIGINET_DESK_CONTROL24 ? "Control|24" : "ProControl");
		}
		break;
	case DIGINET_N_FOREIGN:
		if (!R.foreign)
			say("desk is in a session with another host: not waking it");
		R.foreign = 1;
		break;
	case DIGINET_N_DESK_DEAF:
		say("desk announces but let %u wakes in a row time out; power-cycle it with the link quiet", n->counter);
		break;
	case DIGINET_N_STATE:
		say("session %s -> %s (%s)", diginet_state_name(n->old_state), diginet_state_name(n->state),
		    diginet_reason_name(n->reason));
		R.online = n->state == DIGINET_S_ONLINE;
		break;
	case DIGINET_N_ACKED:
		if (S->state == DIGINET_S_WAKING)
			R.acked_wake = 1;
		else
			R.acked++;
		break;
	case DIGINET_N_ACK_LOST:
		R.lost++;
		say("no ACK for our frame %u after %u retries", n->counter, n->retry);
		break;
	case DIGINET_N_DATA: {
		R.desk_frames++;
		char hex[3 * 320 + 1];
		hex_of(hex, sizeof hex, n->body, n->body_len > 320 ? 320 : n->body_len);
		fprintf(frames, "[%7.3f] %u %s\n", secs(), n->counter, hex);
		fflush(frames);
		struct diginet_decoder d;
		struct diginet_event ev;
		int r;
		diginet_decoder_init(&d, P, n->body, n->body_len);
		while ((r = diginet_decoder_next(&d, &ev)) != 0) {
			if (r < 0) {
				say("undecodable bytes in desk frame %u: %s", n->counter, diginet_strerror(r));
				continue;
			}
			log_event(&ev, n->counter);
		}
		break;
	}
	}
}

/* --any: one socket for every interface, and the desk mux over it. */
static struct diginet_mux MUX;
static int any_mode, our_desk = -1;
static struct diginet_session_config any_cfg;
static const uint8_t *desk_filter;

static void on_mux_notice(void *ctx, const struct diginet_mux_notice *n)
{
	(void)ctx;
	char name[IF_NAMESIZE];
	const uint8_t *m = n->mac;
	if (!if_indextoname((unsigned)n->ifindex, name))
		snprintf(name, sizeof name, "#%d", n->ifindex);
	switch (n->kind) {
	case DIGINET_MUX_N_APPEARED: {
		say("desk %02x:%02x:%02x:%02x:%02x:%02x appeared on %s (\"%s\")", m[0], m[1], m[2], m[3], m[4],
		    m[5], name, n->announce->name);
		if (our_desk >= 0 || (desk_filter && memcmp(desk_filter, m, 6)))
			break;
		struct diginet_session_config c = any_cfg;
		c.auto_wake = R.desk_seen;
		int r = diginet_mux_attach(&MUX, n->desk, &c);
		if (r != DIGINET_OK) {
			say("cannot attach the desk on %s: %s", name, r < 0 ? strerror(-r) : diginet_strerror(r));
			break;
		}
		our_desk = (int)n->desk;
		S = diginet_mux_session(&MUX, n->desk);
		break;
	}
	case DIGINET_MUX_N_GONE:
		say("desk %02x:%02x:%02x:%02x:%02x:%02x gone from %s", m[0], m[1], m[2], m[3], m[4], m[5], name);
		if ((int)n->desk == our_desk) {
			our_desk = -1;
			S = &S0;
		}
		break;
	case DIGINET_MUX_N_SESSION:
		if ((int)n->desk == our_desk)
			on_notice(NULL, n->session);
		break;
	}
}

static int send_nowhere(void *ctx, const uint8_t *frame, size_t len)
{
	(void)ctx;
	(void)frame;
	(void)len;
	return -ENOTCONN;
}

static int poll_wire(int ms)
{
	return any_mode ? diginet_mux_poll(&MUX, ms) : diginet_session_poll(S, ms);
}

static void run_for(unsigned ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	while (!stop && diginet_clock_us() < end) {
		int r = poll_wire(10);
		if (r < 0) {
			say("io error: %s", strerror(-r));
			stop = 1;
		}
	}
}

static int run_until(int (*cond)(void), unsigned ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	while (!stop && !cond() && diginet_clock_us() < end)
		run_for(5);
	return cond();
}

static int c_desk(void) { return R.desk_seen && (R.foreign || S->state != DIGINET_S_IDLE || !S->cfg.auto_wake); }
static int c_online(void) { return S->state == DIGINET_S_ONLINE || R.foreign; }
static int c_drained(void) { return !S->inflight && !S->queued; }

/* One keystroke line from the operator, if one is there: the first character, or 0. */
static int key_pending(void)
{
	struct pollfd p = { .fd = 0, .events = POLLIN };
	if (poll(&p, 1, 0) <= 0)
		return 0;
	char line[64];
	ssize_t k = read(0, line, sizeof line - 1);
	if (k <= 0)
		return 'q';   /* EOF: nobody to answer */
	line[k] = '\0';
	return line[0] == '\n' ? 'y' : line[0];
}

static int send_write(const struct diginet_cmd *c, char *hex, size_t hexn)
{
	hex_of(hex, hexn, c->bytes, (size_t)c->len);
	unsigned lost = R.lost;
	int r = diginet_session_submit(S, c);
	if (r) {
		say("write refused (%s)", diginet_strerror(r));
		return -1;
	}
	run_until(c_drained, 2000);
	return R.lost > lost ? -1 : 0;
}

static void verdict(const struct diginet_control *c, const char *v, const char *detail)
{
	say("VERDICT %s %s%s%s", c->slug, v, detail[0] ? ": " : "", detail);
	fprintf(report, "| %s | %s | %s | %s |\n", c->slug, c->what, v, detail);
	fflush(report);
	if (!strcmp(v, "PASS")) R.pass++;
	else if (!strcmp(v, "MISMATCH")) R.mismatch++;
	else if (!strcmp(v, "MISSING")) R.missing++;
	else if (!strcmp(v, "FAIL")) R.fail++;
	else R.skip++;
}

/* An input control: tell the operator, wait for the desk. Returns 'q' when the operator stops. */
static int step_in(const struct diginet_control *c, size_t i, size_t n, unsigned answer_ms, unsigned settle_ms)
{
	struct diginet_cmd e;
	char hex[3 * DIGINET_CMD_MAX_LEN + 1] = "";
	if (diginet_census_expect(P, c, &e) == DIGINET_OK)
		hex_of(hex, sizeof hex, e.bytes, (size_t)e.len);
	say("STEP %zu/%zu IN %s expect %s", i + 1, n, c->slug, hex);
	say("DO: %s (n = nothing happens, s = skip, q = stop)", c->what);
	R.waiting = c;
	R.got = 0;
	R.got_len = 0;
	R.got_text[0] = '\0';
	uint64_t end = diginet_clock_us() + (uint64_t)answer_ms * 1000u;
	int key = 0;
	while (!stop && R.got == 0 && diginet_clock_us() < end) {
		key = key_pending();
		if (key == 'n' || key == 's' || key == 'q')
			break;
		run_for(5);
	}
	R.waiting = NULL;
	char detail[256] = "";
	if (R.got == 1) {
		snprintf(detail, sizeof detail, "%s", R.got_text);
		verdict(c, "PASS", detail);
		record_body(c->slug, R.got_body, R.got_len);
		R.last_in = c;
	} else if (R.got == -1) {
		char got_hex[3 * DIGINET_CMD_MAX_LEN + 1];
		hex_of(got_hex, sizeof got_hex, R.got_body, (size_t)R.got_len);
		snprintf(detail, sizeof detail, "expected %s, got %s = %s", hex, got_hex, R.got_text);
		verdict(c, "MISMATCH", detail);
		char name[64];
		snprintf(name, sizeof name, "MISMATCH_%s", c->slug);
		record_body(name, R.got_body, R.got_len);
		R.last_in = NULL;
	} else if (key == 's' || key == 'q') {
		verdict(c, "SKIP", key == 'q' ? "stopped here" : "");
	} else {
		verdict(c, "MISSING", key == 'n' ? "nothing came, the operator says" : "nothing came before the wait ran out");
		R.last_in = NULL;
	}
	if (settle_ms)
		run_for(settle_ms);   /* the release, the rest of the motion */
	return key == 'q' ? 'q' : 0;
}

/* An output control: write it, ask, clear it. */
static int step_out(const struct diginet_control *c, size_t i, size_t n, unsigned answer_ms)
{
	struct diginet_cmd w;
	char hex[3 * DIGINET_CMD_MAX_LEN + 1] = "";
	if (diginet_census_write(P, c, 1, &w) != DIGINET_OK) {
		verdict(c, "SKIP", "the library cannot encode this write for this desk");
		return 0;
	}
	int sent = send_write(&w, hex, sizeof hex);
	say("STEP %zu/%zu OUT %s sent %s%s", i + 1, n, c->slug, hex, sent ? " NOT ACKED" : "");
	say("LOOK: %s? (Enter or y = yes, n = no, s = skip, q = stop)", c->what);
	uint64_t end = diginet_clock_us() + (uint64_t)answer_ms * 1000u;
	int key = 0;
	while (!stop && !key && diginet_clock_us() < end) {
		key = key_pending();
		if (!key)
			run_for(5);
	}
	char detail[128];
	snprintf(detail, sizeof detail, "wrote %s%s", hex, sent ? " (not ACKed)" : "");
	if (key == 'y')
		verdict(c, sent ? "FAIL" : "PASS", detail);
	else if (key == 'n')
		verdict(c, "FAIL", detail);
	else if (key == 's' || key == 'q')
		verdict(c, "SKIP", key == 'q' ? "stopped here" : "");
	else
		verdict(c, "SKIP", "no answer before the wait ran out");
	if (diginet_census_write(P, c, 0, &w) == DIGINET_OK)
		send_write(&w, hex, sizeof hex);
	return key == 'q' ? 'q' : 0;
}

static int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned v[6];
	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (v[i] > 0xff)
			return -1;
		mac[i] = (uint8_t)v[i];
	}
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f,
		"usage: diginet-census (-i IFACE | --fd N --mac MAC | --any [--helper PATH]) [options]\n"
		"  every control of the desk, one by one, with an operator at the desk; the report,\n"
		"  the record of the desk's bodies and the raw frames go to --out DIR (default .)\n"
		"  -i IFACE          the interface the desk is cabled to\n"
		"  --fd N --mac MAC  a descriptor that carries the frames, and the host MAC to use\n"
		"  --any             every interface (the packet socket, or --helper PATH)\n"
		"  --desk MAC        with --any: this desk only\n"
		"  --checksum zero|sum  the header checksum of our frames (default sum)\n"
		"  --keepalive S     keepalive period (default 2)\n"
		"  --wait S          wait for the announce (default 15)\n"
		"  --answer S        wait for the desk or the operator at each step (default 60)\n"
		"  --settle MS       pause after an input step for the release (default 300)\n"
		"  --only in|out|strips|sections   walk this part only\n"
		"  --strips N        walk the first N strips only\n"
		"  --from SLUG       start at this control\n"
		"  -o, --out DIR     where census.md, census-bodies.txt and census-frames.txt go\n");
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "fd", 1, 0, 'f' }, { "mac", 1, 0, 'm' }, { "any", 0, 0, 'A' }, { "helper", 1, 0, 'H' },
		{ "desk", 1, 0, 'd' }, { "checksum", 1, 0, 'c' }, { "keepalive", 1, 0, 'k' },
		{ "wait", 1, 0, 'w' }, { "answer", 1, 0, 'a' }, { "settle", 1, 0, 'S' },
		{ "only", 1, 0, 'O' }, { "strips", 1, 0, 'N' }, { "from", 1, 0, 'F' }, { "out", 1, 0, 'o' },
		{ "help", 0, 0, 'h' }, { 0, 0, 0, 0 },
	};
	const char *ifname = NULL, *helper = NULL, *only = NULL, *from = NULL, *outdir = ".";
	int fd = -1, have_mac = 0, opt;
	unsigned keepalive_s = 2, wait_s = 15, answer_s = 60, settle_ms = 300, strips = 0;
	struct diginet_session_config cfg;
	diginet_session_config_default(&cfg);
	while ((opt = getopt_long(argc, argv, "i:o:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'i': ifname = optarg; break;
		case 'f': fd = atoi(optarg); break;
		case 'm':
			if (parse_mac(optarg, cfg.host_mac)) goto bad;
			have_mac = 1;
			break;
		case 'A': any_mode = 1; break;
		case 'H': helper = optarg; break;
		case 'd':
			if (parse_mac(optarg, cfg.desk_mac)) goto bad;
			cfg.desk_mac_set = 1;
			break;
		case 'c':
			if (!strcmp(optarg, "zero")) cfg.sum_mode = DIGINET_SUM_ZERO;
			else if (!strcmp(optarg, "sum")) cfg.sum_mode = DIGINET_SUM_BODY;
			else goto bad;
			break;
		case 'k': keepalive_s = (unsigned)atoi(optarg); break;
		case 'w': wait_s = (unsigned)atoi(optarg); break;
		case 'a': answer_s = (unsigned)atoi(optarg); break;
		case 'S': settle_ms = (unsigned)atoi(optarg); break;
		case 'O':
			only = optarg;
			if (strcmp(only, "in") && strcmp(only, "out") && strcmp(only, "strips") && strcmp(only, "sections"))
				goto bad;
			break;
		case 'N': strips = (unsigned)atoi(optarg); break;
		case 'F': from = optarg; break;
		case 'o': outdir = optarg; break;
		case 'h': usage(stdout); return EXIT_OK;
		default: goto bad;
		}
	}
	if (optind != argc || (!!ifname + (fd >= 0) + any_mode) != 1 || (fd >= 0 && !have_mac) ||
	    (helper && !any_mode) || (any_mode && have_mac) || !keepalive_s)
		goto bad;
	cfg.keepalive_ms = keepalive_s * 1000u;
	if (cfg.offline_ms < 3 * cfg.keepalive_ms)
		cfg.offline_ms = 3 * cfg.keepalive_ms;

	if (any_mode) {
		fd = helper ? -EPERM : diginet_packet_open_any();
		if (fd == -EPERM || fd == -EACCES) {
			fd = diginet_packet_open_by_helper(helper);
			if (fd < 0) {
				fprintf(stderr, "diginet-census: no socket from %s: %s\n",
					helper ? helper : "diginet-packet-helper", strerror(-fd));
				return EXIT_USAGE;
			}
		} else if (fd < 0) {
			fprintf(stderr, "diginet-census: cannot open the any-interface socket: %s\n", strerror(-fd));
			return EXIT_USAGE;
		}
	} else if (ifname) {
		fd = diginet_packet_open(ifname, cfg.host_mac);
		if (fd < 0) {
			fprintf(stderr, "diginet-census: cannot open %s: %s\n", ifname, strerror(-fd));
			return EXIT_USAGE;
		}
	}

	char path[4096];
	mkdir(outdir, 0755);
	snprintf(path, sizeof path, "%s/census.md", outdir);
	report = fopen(path, "w");
	snprintf(path, sizeof path, "%s/census-bodies.txt", outdir);
	record = fopen(path, "w");
	snprintf(path, sizeof path, "%s/census-frames.txt", outdir);
	frames = fopen(path, "w");
	if (!report || !record || !frames) {
		fprintf(stderr, "diginet-census: cannot write in %s: %s\n", outdir, strerror(errno));
		return EXIT_USAGE;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	struct diginet_fd_io st;
	if (any_mode) {
		struct diginet_mux_io mio;
		diginet_mux_io_packet(&mio, &st, fd);
		any_cfg = cfg;
		desk_filter = cfg.desk_mac_set ? any_cfg.desk_mac : NULL;
		struct diginet_io none = { .ctx = NULL, .send = send_nowhere, .recv = NULL, .now_us = NULL };
		if (diginet_session_init(&S0, &cfg, &none, on_notice, NULL) != DIGINET_OK ||
		    diginet_mux_init(&MUX, NULL, &mio, on_mux_notice, NULL) != DIGINET_OK) {
			fprintf(stderr, "diginet-census: bad session settings\n");
			return EXIT_USAGE;
		}
		S0.desk_known = 0;
	} else {
		struct diginet_io io;
		diginet_io_fd(&io, &st, fd);
		if (diginet_session_init(S, &cfg, &io, on_notice, NULL) != DIGINET_OK) {
			fprintf(stderr, "diginet-census: bad session settings\n");
			return EXIT_USAGE;
		}
	}
	t0 = diginet_clock_us();
	P = diginet_personality_of(DIGINET_DESK_CONTROL24);
	say("diginet-census %s: waiting up to %u s for the desk's announce", DIGINET_VERSION_STRING, wait_s);
	run_until(c_desk, wait_s * 1000u);
	if (!R.desk_seen) {
		say("RESULT: no desk announced on the wire");
		return EXIT_NO_DESK;
	}
	if (R.foreign) {
		say("RESULT: the desk is in another host's session; nothing was sent");
		return EXIT_FOREIGN;
	}
	if (diginet_session_wake(S, diginet_clock_us()) != DIGINET_OK || !run_until(c_online, 5000) || R.foreign) {
		say("RESULT: the desk did not come online (a0 %s)", R.acked_wake ? "seen" : "missing");
		diginet_session_close(S, diginet_clock_us());
		return R.foreign ? EXIT_FOREIGN : EXIT_NO_DESK;
	}
	say("online: \"%s\" version \"%s\", %s", R.name, R.version,
	    P->desk == DIGINET_DESK_CONTROL24 ? "Control|24" : "ProControl");

	size_t n = diginet_census_count(P);
	fprintf(report, "# Census of \"%s\" version \"%s\" (%s), libdiginet %s\n\n", R.name, R.version,
		P->desk == DIGINET_DESK_CONTROL24 ? "Control|24" : "ProControl", DIGINET_VERSION_STRING);
	fprintf(report, "%zu controls in the inventory; the walk is below, one row per control. "
		"The desk's bodies are in census-bodies.txt (golden format: slug, then the bytes), "
		"every desk frame in census-frames.txt.\n\n| control | what | verdict | detail |\n|---|---|---|---|\n", n);
	int started = !from, walked = 0, quit = 0;
	struct diginet_control c;
	for (size_t i = 0; i < n && !stop && !quit; i++) {
		if (diginet_census_control(P, i, &c) != DIGINET_OK)
			break;
		if (!started) {
			if (strcmp(c.slug, from))
				continue;
			started = 1;
		}
		int section = c.kind == DIGINET_CTL_SECTION_BUTTON || c.kind == DIGINET_CTL_SECTION_LAMP;
		int global = c.kind == DIGINET_CTL_JOG || c.kind == DIGINET_CTL_COUNTER || c.kind == DIGINET_CTL_COUNTER_LEDS;
		if (only) {
			if (!strcmp(only, "in") && !c.input) continue;
			if (!strcmp(only, "out") && c.input) continue;
			if (!strcmp(only, "strips") && (section || global)) continue;
			if (!strcmp(only, "sections") && !section) continue;
		}
		if (strips && !section && !global && c.strip >= strips)
			continue;
		walked++;
		quit = c.input ? step_in(&c, i, n, answer_s * 1000u, settle_ms) == 'q'
			       : step_out(&c, i, n, answer_s * 1000u) == 'q';
	}
	if (!started)
		say("RESULT: no control named %s", from);
	diginet_session_close(S, diginet_clock_us());
	fprintf(report, "\n%d walked of %zu: PASS %u, MISMATCH %u, MISSING %u, FAIL %u, SKIP %u; "
		"our writes ACKed %u, lost %u; desk frames %u.\n", walked, n, R.pass, R.mismatch, R.missing,
		R.fail, R.skip, R.acked, R.lost, R.desk_frames);
	fclose(report);
	fclose(record);
	fclose(frames);
	say("SUMMARY %d walked of %zu: PASS %u, MISMATCH %u, MISSING %u, FAIL %u, SKIP %u (%s)", walked, n,
	    R.pass, R.mismatch, R.missing, R.fail, R.skip, quit ? "stopped by the operator" : stop ? "interrupted" : "complete");
	say("SUMMARY our writes ACKed %u, lost %u; desk frames %u; report in %s/census.md", R.acked, R.lost,
	    R.desk_frames, outdir);
	if (R.lost)
		return EXIT_NO_ACK;
	return (R.mismatch || R.missing || R.fail || !started) ? EXIT_RED : EXIT_OK;
bad:
	usage(stderr);
	return EXIT_USAGE;
}
