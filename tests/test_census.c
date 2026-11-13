// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
/* The census: the inventory itself, diginet-census against the desk emulator with the emulator
 * as the operator, and a desk's recorded bodies read back.
 *
 *   tests/test_census <path to diginet-census> [a census-bodies.txt recorded on a desk]
 *
 *  A. the inventory: 1168 controls on a Control|24 (556 the desk sends, 612 the host writes),
 *     every slug unique, every expected body decodes to its own control and to no other, every
 *     write encodes on and off, the section table has no duplicate zone/id;
 *  B. the whole walk with a perfect operator: every input answered with the expected body plus
 *     its release, every write seen by the desk and answered yes: 1168 PASS, exit 0, a record of
 *     556 bodies that reads back clean;
 *  C. a wrong operator on strip 1: MUTE of strip 2 for strip 1's MUTE (MISMATCH, recorded as
 *     MISMATCH_s01_mute and red on read-back), nothing for the V-Pot (MISSING), no for a lamp
 *     (FAIL), q at the ring: stopped after 31 of the 36 of a strip, exit 1;
 *  D. refusals: bad usage exit 2, no desk exit 4;
 *  E. the file named on the command line, when there is one: a desk's record reads back clean.
 */
#include "golden.h"
#include <diginet/diginet_census.h>
#include <diginet/testsupport/emu_pump.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static const uint8_t DESK_MAC[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
#define HOST "02:00:00:00:00:01"
static const char *census;
static const struct diginet_personality *P;
static struct desk_emu E;
static char out[1 << 20];
static size_t outlen, scanned;
static int in_fd = -1;
static char outdir[256];


static int parse_hex(const char *s, uint8_t *b, int cap)
{
	int n = 0;
	unsigned v;
	while (n < cap && sscanf(s, "%2x", &v) == 1) {
		b[n++] = (uint8_t)v;
		s += 2;
		while (*s == ' ')
			s++;
		if (*s == '\0' || *s == '\n')
			break;
	}
	return n;
}

/* The operator the emulator plays: how it answers each step. */
typedef void (*operator_fn)(const char *kind, const char *slug, const uint8_t *body, int len);

static void answer(const char *s)
{
	if (write(in_fd, s, strlen(s)) < 0)
		perror("answer");
}

static void press(const uint8_t *body, int len)
{
	/* the press as expected, then its release in the same frame: a release is never a mismatch */
	uint8_t b[16];
	memcpy(b, body, (size_t)len);
	int n = len, ncmds = 1;
	if (len == 3 && body[0] == 0x90) {
		b[3] = body[0];
		b[4] = body[1];
		b[5] = (uint8_t)(body[2] & ~0x40);
		n = 6;
		ncmds = 2;
	} else if (len == 6) {
		ncmds = 2;   /* a fader: MSB then LSB */
	}
	emu_send_data(&E, b, (size_t)n, (uint8_t)ncmds, 0, 0);
}

static void perfect(const char *kind, const char *slug, const uint8_t *body, int len)
{
	(void)slug;
	if (!strcmp(kind, "IN"))
		press(body, len);
	else
		answer("y\n");
}

static int wrong_seen;
static void wrong(const char *kind, const char *slug, const uint8_t *body, int len)
{
	if (!strcmp(slug, "s01_mute")) {
		static const uint8_t other[] = { 0x90, 0x08, 0x41 };
		press(other, 3);
		wrong_seen++;
	} else if (!strcmp(slug, "s01_vpot")) {
		answer("n\n");
	} else if (!strcmp(slug, "s01_rec_lamp")) {
		answer("n\n");
	} else if (!strcmp(slug, "s01_ring")) {
		answer("q\n");
	} else {
		perfect(kind, slug, body, len);
	}
}

/* Scan the new output for STEP lines and let the operator answer them; count the writes the
 * desk saw. */
static unsigned writes_seen, writes_missed, steps;
static void drive(operator_fn op)
{
	for (;;) {
		char *nl = memchr(out + scanned, '\n', outlen - scanned);
		if (!nl)
			return;
		*nl = '\0';
		char *s = strstr(out + scanned, "STEP ");
		if (s) {
			char kind[8], slug[48], hex[3 * DIGINET_CMD_MAX_LEN + 1] = "";
			if (sscanf(s, "STEP %*u/%*u %7s %47s %*s %[0-9a-f ]", kind, slug, hex) >= 2) {
				uint8_t body[DIGINET_CMD_MAX_LEN];
				int len = parse_hex(hex, body, (int)sizeof body);
				steps++;
				if (!strcmp(kind, "OUT")) {
					if (emu_count_cmd(&E, body, (size_t)len))
						writes_seen++;
					else
						writes_missed++;
				}
				if (op)
					op(kind, slug, body, len);
			}
		}
		*nl = '\n';
		scanned = (size_t)(nl - out) + 1;
	}
}

static int run_census(const char *const *args, operator_fn op, unsigned cap_s)
{
	int sv[2], in[2], po[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0 || pipe(in) < 0 || pipe(po) < 0) {
		perror("pipe");
		exit(2);
	}
	pid_t pid = fork();
	if (pid == 0) {
		dup2(in[0], 0);
		dup2(po[1], 1);
		dup2(po[1], 2);
		dup2(sv[1], 3);
		for (int fd = 4; fd < 64; fd++)
			close(fd);
		const char *argv[48] = { census };
		int n = 1;
		for (; args[n - 1] && n < 47; n++)
			argv[n] = args[n - 1];
		argv[n] = NULL;
		execv(census, (char *const *)argv);
		_exit(127);
	}
	close(in[0]);
	close(po[1]);
	close(sv[1]);
	in_fd = in[1];
	fcntl(po[0], F_SETFL, O_NONBLOCK);
	outlen = scanned = 0;
	steps = writes_seen = writes_missed = 0;
	uint64_t t0 = diginet_clock_us(), next_ann = t0;
	int status = -1;
	for (;;) {
		ssize_t k;
		while ((k = read(po[0], out + outlen, sizeof out - 1 - outlen)) > 0)
			outlen += (size_t)k;
		out[outlen] = '\0';
		emu_pump_fd(&E, sv[0], &next_ann, 500000);
		drive(op);
		emu_pump_fd(&E, sv[0], &next_ann, 500000);
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid)
			break;
		if (diginet_clock_us() - t0 > (uint64_t)cap_s * 1000000u) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			fprintf(stderr, "diginet-census did not finish in %u s\n", cap_s);
			status = -1;
			break;
		}
		usleep(300);
	}
	ssize_t k;
	while ((k = read(po[0], out + outlen, sizeof out - 1 - outlen)) > 0)
		outlen += (size_t)k;
	out[outlen] = '\0';
	drive(op);
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	while ((k = recv(sv[0], b, sizeof b, MSG_DONTWAIT)) > 0)
		emu_from_host(&E, b, (size_t)k, diginet_clock_us());
	close(in[1]);
	close(po[0]);
	close(sv[0]);
	in_fd = -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int has(const char *s)
{
	if (strstr(out, s))
		return 1;
	fprintf(stderr, "census output lacks: %s\n", s);
	return 0;
}

/* A record of desk bodies read back: every row names a control of the inventory and decodes
 * to it; a MISMATCH_ or MISSING_ row, or one that does not decode to its control, is bad.
 * Returns the number of bad rows, -1 when the file cannot be read; *rows is the row count. */
static int read_record(const char *path, int *rows)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char line[1024];
	int bad = 0;
	*rows = 0;
	while (fgets(line, sizeof line, f)) {
		char name[128];
		int off = 0;
		if (line[0] == '#' || line[0] == '\n' || sscanf(line, "%127s %n", name, &off) < 1)
			continue;
		(*rows)++;
		if (!strncmp(name, "MISMATCH_", 9) || !strncmp(name, "MISSING_", 8)) {
			fprintf(stderr, "  %s: the desk contradicted the inventory\n", name);
			bad++;
			continue;
		}
		struct diginet_control c;
		if (diginet_census_find(P, name, &c) != DIGINET_OK || !c.input) {
			fprintf(stderr, "  %s: not an input control of the inventory\n", name);
			bad++;
			continue;
		}
		uint8_t body[DIGINET_CMD_MAX_LEN];
		int len = parse_hex(line + off, body, (int)sizeof body);
		struct diginet_decoder d;
		struct diginet_event ev;
		int matched = 0, r;
		diginet_decoder_init(&d, P, body, (size_t)len);
		while ((r = diginet_decoder_next(&d, &ev)) != 0)
			if (r > 0 && diginet_census_matches(&c, &ev))
				matched = 1;
		if (!matched) {
			fprintf(stderr, "  %s: its bytes do not decode to it\n", name);
			bad++;
		}
	}
	fclose(f);
	return bad;
}

static void test_inventory(void)
{
	size_t n = diginet_census_count(P);
	CHK(n == 1168);
	unsigned in = 0, outs = 0;
	struct diginet_control c, d;
	for (size_t i = 0; i < n; i++) {
		CHK(diginet_census_control(P, i, &c) == DIGINET_OK);
		if (c.input) {
			in++;
			struct diginet_cmd e;
			CHK(diginet_census_expect(P, &c, &e) == DIGINET_OK && e.len > 0);
			struct diginet_decoder dec;
			struct diginet_event ev;
			int matched = 0, r;
			diginet_decoder_init(&dec, P, e.bytes, (size_t)e.len);
			while ((r = diginet_decoder_next(&dec, &ev)) != 0)
				if (r > 0 && diginet_census_matches(&c, &ev))
					matched = 1;
			CHK(matched);
			/* and no other input control claims the same body */
			for (size_t j = 0; j < n; j++) {
				if (j == i || diginet_census_control(P, j, &d) != DIGINET_OK || !d.input)
					continue;
				diginet_decoder_init(&dec, P, e.bytes, (size_t)e.len);
				while ((r = diginet_decoder_next(&dec, &ev)) != 0)
					if (r > 0 && diginet_census_matches(&d, &ev)) {
						fprintf(stderr, "%s and %s share a body\n", c.slug, d.slug);
						fails++;
					}
				if (!strcmp(c.slug, d.slug)) {
					fprintf(stderr, "slug %s twice\n", c.slug);
					fails++;
				}
			}
			CHK(diginet_census_write(P, &c, 1, &e) == DIGINET_E_ARG);
		} else {
			outs++;
			struct diginet_cmd on, off;
			CHK(diginet_census_write(P, &c, 1, &on) == DIGINET_OK && on.len > 0);
			CHK(diginet_census_write(P, &c, 0, &off) == DIGINET_OK && off.len > 0);
			CHK(on.len != off.len || memcmp(on.bytes, off.bytes, (size_t)on.len) != 0);
			CHK(diginet_census_expect(P, &c, &on) == DIGINET_E_ARG);
		}
		CHK(c.slug[0] && c.what[0]);
	}
	CHK(in == 556 && outs == 612);
	CHK(diginet_census_control(P, n, &c) == DIGINET_E_RANGE);
	CHK(diginet_census_find(P, "s24_rolloff", &c) == DIGINET_OK && c.strip == 23 && c.button == DIGINET_BTN_ROLL_OFF);
	CHK(diginet_census_find(P, "sec_1c_10_play", &c) == DIGINET_OK && c.zone == 0x1c && c.button == 0x10 && c.input);
	CHK(diginet_census_find(P, "sec_1c_10_play_lamp", &c) == DIGINET_OK && c.kind == DIGINET_CTL_SECTION_LAMP);
	CHK(diginet_census_find(P, "sec_1d_15_right", &c) == DIGINET_OK && !strcmp(c.name, ">"));
	CHK(diginet_census_find(P, "nothing", &c) == DIGINET_E_RANGE);
	/* the table */
	CHK(diginet_c24_section_button_count == 171);
	for (size_t i = 0; i < diginet_c24_section_button_count; i++) {
		const struct diginet_section_button *s = &diginet_c24_section_buttons[i];
		CHK(s->zone >= DIGINET_ZONE_FIRST && s->zone <= DIGINET_ZONE_LAST && s->id < 0x40 && s->name[0]);
		for (size_t j = i + 1; j < diginet_c24_section_button_count; j++)
			if (diginet_c24_section_buttons[j].zone == s->zone && diginet_c24_section_buttons[j].id == s->id) {
				fprintf(stderr, "section %02x/%02x twice: %s, %s\n", s->zone, s->id, s->name,
					diginet_c24_section_buttons[j].name);
				fails++;
			}
	}
	/* a ProControl has strips and no section table yet */
	CHK(diginet_census_count(diginet_personality_of(DIGINET_DESK_PROCONTROL)) == 8 * 36 + 3);
	if (fails)
		fprintf(stderr, "A. inventory: %d failure(s)\n", fails);
}

static void test_walk(void)
{
	int f0 = fails;
	const char *args[] = { "--fd", "3", "--mac", HOST, "--wait", "5", "--keepalive", "1", "--answer", "5",
			       "--settle", "0", "-o", outdir, NULL };
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");
	int rc = run_census(args, perfect, 100);
	CHK(rc == 0);
	CHK(has("desk: 00:a0:7e:24:00:01 name \"CNTRL|24\" version \"1.37\" (Control|24)"));
	CHK(has("STEP 1/1168 IN s01_fader expect b0 00 40 20 00"));
	CHK(has("VERDICT s01_fader PASS: fader 1 at 512"));
	CHK(has("STEP 3/1168 IN s01_rec expect 90 00 40"));
	CHK(has("VERDICT s01_mute PASS: strip 1 MUTE pressed"));
	CHK(has("STEP 17/1168 OUT s01_fader_out sent b0 00 60 20 00"));
	CHK(has("VERDICT s01_mute_lamp PASS: wrote 90 08 40"));
	CHK(has("OUT s01_scribble_00 sent f0 13 01 40 00 00 43 30 31 20 f7"));
	CHK(has("OUT s01_scribble_20 sent f0 13 01 40 20 00 44 30 31 20 f7"));
	CHK(has("IN jog expect b0 5c 41") && has("VERDICT jog PASS: jog +1"));
	CHK(has("OUT counter sent f0 13 01 30 19 00"));
	CHK(has("IN sec_1c_10_play expect 90 10 5c") && has("VERDICT sec_1c_10_play PASS: zone 0x1c button 0x10 pressed"));
	CHK(has("OUT sec_1c_10_play_lamp sent 90 10 5c"));
	CHK(has("SUMMARY 1168 walked of 1168: PASS 1168, MISMATCH 0, MISSING 0, FAIL 0, SKIP 0 (complete)"));
	CHK(has("lost 0"));
	CHK(steps == 1168);
	CHK(writes_seen == 612 && writes_missed == 0);
	/* every lamp was cleared again: as many offs as ons */
	static const uint8_t on[] = { 0x90, 0x08, 0x40 }, off[] = { 0x90, 0x08, 0x00 };
	CHK(emu_count_cmd(&E, on, 3) == 1 && emu_count_cmd(&E, off, 3) == 1);
	char path[300];
	snprintf(path, sizeof path, "%s/census-bodies.txt", outdir);
	int rows = 0, bad = read_record(path, &rows);
	CHK(bad == 0 && rows == 556);
	snprintf(path, sizeof path, "%s/census.md", outdir);
	FILE *f = fopen(path, "r");
	CHK(f != NULL);
	if (f) {
		char line[512];
		int tail = 0;
		while (fgets(line, sizeof line, f))
			if (strstr(line, "1168 walked of 1168: PASS 1168"))
				tail = 1;
		fclose(f);
		CHK(tail);
	}
	if (fails > f0)
		fprintf(stderr, "B. the walk: %d failure(s)\n", fails - f0);
}

static void test_wrong(void)
{
	int f0 = fails;
	char dir[300];
	snprintf(dir, sizeof dir, "%s/wrong", outdir);
	const char *args[] = { "--fd", "3", "--mac", HOST, "--wait", "5", "--keepalive", "1", "--answer", "5",
			       "--settle", "0", "--only", "strips", "--strips", "1", "-o", dir, NULL };
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");
	wrong_seen = 0;
	int rc = run_census(args, wrong, 60);
	CHK(rc == 1);
	CHK(wrong_seen == 1);
	CHK(has("VERDICT s01_mute MISMATCH: expected 90 08 40, got 90 08 41 = strip 2 MUTE pressed"));
	CHK(has("VERDICT s01_vpot MISSING: nothing came, the operator says"));
	CHK(has("VERDICT s01_rec_lamp FAIL: wrote 90 00 40"));
	CHK(has("VERDICT s01_ring SKIP: stopped here"));
	CHK(has("SUMMARY 31 walked of 1168: PASS 27, MISMATCH 1, MISSING 1, FAIL 1, SKIP 1 (stopped by the operator)"));
	char path[400];
	snprintf(path, sizeof path, "%s/census-bodies.txt", dir);
	int rows = 0, bad = read_record(path, &rows);
	CHK(bad == 1 && rows == 15);
	FILE *f = fopen(path, "r");
	int seen = 0;
	if (f) {
		char line[256];
		while (fgets(line, sizeof line, f))
			if (!strcmp(line, "MISMATCH_s01_mute 90 08 41\n"))
				seen = 1;
		fclose(f);
	}
	CHK(seen);
	if (fails > f0)
		fprintf(stderr, "C. a wrong operator: %d failure(s)\n", fails - f0);
}

static void test_refusals(void)
{
	int f0 = fails;
	const char *none[] = { NULL };
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");
	CHK(run_census(none, NULL, 10) == 2);
	const char *only[] = { "--fd", "3", "--mac", HOST, "--only", "lamps", NULL };
	CHK(run_census(only, NULL, 10) == 2);
	char dir[300];
	snprintf(dir, sizeof dir, "%s/nodesk", outdir);
	const char *nodesk[] = { "--fd", "3", "--mac", HOST, "--wait", "1", "-o", dir, NULL };
	E.mute = 1;
	CHK(run_census(nodesk, NULL, 10) == 4);
	CHK(has("RESULT: no desk announced on the wire"));
	if (fails > f0)
		fprintf(stderr, "D. refusals: %d failure(s)\n", fails - f0);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: test_census <diginet-census> [census-bodies.txt from a desk]\n");
		return 2;
	}
	census = argv[1];
	P = diginet_personality_of(DIGINET_DESK_CONTROL24);
	signal(SIGPIPE, SIG_IGN);
	snprintf(outdir, sizeof outdir, "/tmp/test_census.%ld", (long)getpid());
	mkdir(outdir, 0755);
	test_inventory();
	test_walk();
	test_wrong();
	test_refusals();
	if (argc > 2) {
		int rows = 0, bad = read_record(argv[2], &rows);
		if (bad < 0) {
			printf("E. no desk record at %s yet: the inventory is proven on the emulator only\n", argv[2]);
		} else {
			printf("E. desk record %s: %d row(s), %d bad\n", argv[2], rows, bad);
			CHK(bad == 0);
		}
	}
	if (fails) {
		fprintf(stderr, "test_census: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_census: ok (%s)\n", outdir);
	return 0;
}
