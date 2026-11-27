// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* Writes the seed corpus of every harness in fuzz/ (`make fuzz-corpus`).
 *
 * Every seed is built from what the repository already holds: the golden frames of
 * tests/golden/frames.txt and the commands the library's own encoders make. Beside the
 * well-formed frames it writes one input per refusal a reader makes (a short frame, a wrong
 * EtherType, a length past the buffer, a status byte where a data byte is due, a sysex with
 * no F7, an F0 13 xx 70 whole or cut short, a value past an encoder's range ...), and the
 * sessions that reach every state. Nothing is fetched and nothing is random, so the corpus
 * regenerates byte for byte on any machine.
 *
 * Each seed is shaped the way its harness reads its input; the harness's header comment is
 * the grammar. Usage: fuzz-gen-corpus <tests/golden/frames.txt> <corpus dir>. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <sys/stat.h>

#include "golden.h"

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>   /* DIGINET_QUEUE_MAX */

/* ---- a growable byte buffer, one seed at a time ---- */
struct seed {
	uint8_t *p;
	size_t n, cap;
};

static struct seed S;

static void put(const void *p, size_t n)
{
	if (S.n + n > S.cap) {
		S.cap = (S.n + n) * 2 + 64;
		S.p = realloc(S.p, S.cap);
		if (!S.p) {
			perror("realloc");
			exit(1);
		}
	}
	if (n)
		memcpy(S.p + S.n, p, n);
	S.n += n;
}

static void put8(unsigned v)
{
	uint8_t b = (uint8_t)v;
	put(&b, 1);
}

/* little-endian, as fuzz_u16() reads it */
static void put16(unsigned v)
{
	put8(v & 0xff);
	put8(v >> 8 & 0xff);
}

/* little-endian, as fuzz_u32() reads it */
static void put32(uint32_t v)
{
	put16(v & 0xffff);
	put16(v >> 16);
}

/* a size_t as fuzz_codec reads it: two u32s, the high one first */
static void putlen(uint64_t v)
{
	put32((uint32_t)(v >> 32));
	put32((uint32_t)v);
}

/* a length-prefixed record, as fuzz_record() reads it */
static void put_rec(const uint8_t *p, size_t n)
{
	put16((unsigned)n);
	put(p, n);
}

static const char *g_root;

static void mkdir_p(const char *path)
{
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		perror(path);
		exit(1);
	}
}

static void emit(const char *harness, const char *name)
{
	char dir[512], path[640];
	snprintf(dir, sizeof dir, "%s/%s", g_root, harness);
	mkdir_p(dir);
	snprintf(path, sizeof path, "%s/%s", dir, name);
	FILE *f = fopen(path, "wb");
	if (!f || fwrite(S.p, 1, S.n, f) != S.n || fclose(f) != 0) {
		perror(path);
		exit(1);
	}
	S.n = 0;
}

static const uint8_t HOST[DIGINET_MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t DESK[DIGINET_MAC_LEN] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };

static void set16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* ---- fuzz_frame: one frame ---- */

static void frame_seeds(void)
{
	uint8_t f[DIGINET_MAX_FRAME_LEN + 64];
	const struct golden *g;

	for (int i = 0; i < golden_count; i++) {
		put(golden_set[i].bytes, golden_set[i].len);
		emit("frame", golden_set[i].name);
	}

	g = golden("keepalive");
	put(g->bytes, 29);
	emit("frame", "short");
	memcpy(f, g->bytes, g->len);
	set16(f + 12, 0x0800);
	put(f, g->len);
	emit("frame", "wrong-ethertype");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, 15);
	put(f, g->len);
	emit("frame", "numbytes-under-16");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, 47);   /* 14 + 47 = 61 > 60 */
	put(f, g->len);
	emit("frame", "numbytes-past-buffer");
	put(g->bytes, DIGINET_BODY_OFFSET + 1);
	emit("frame", "unpadded");

	g = golden("fader_move");
	memcpy(f, g->bytes, g->len);
	f[DIGINET_ETH_HDR_LEN + 3] ^= 1;
	put(f, g->len);
	emit("frame", "sum-mismatch");

	/* announces cut short, at the edge, and with fields that fill their 9 bytes */
	g = golden("announce_cntrl24");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + 32);
	put(f, g->len);
	emit("frame", "announce-body-32");
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + 33);
	put(f, g->len);
	emit("frame", "announce-body-33");
	memcpy(f, g->bytes, g->len);
	memset(f + DIGINET_BODY_OFFSET + 15, 'v', 9);
	memset(f + DIGINET_BODY_OFFSET + 24, 'n', 9);
	put(f, g->len);
	emit("frame", "announce-unterminated");

	/* a data frame holding the system family, which the builder refuses */
	g = golden("meter");
	memcpy(f, g->bytes, g->len);
	f[DIGINET_BODY_OFFSET + 3] = DIGINET_FN_SYSTEM;
	put(f, g->len);
	emit("frame", "system-body");

	/* a body longer than any Ethernet frame carries */
	memset(f, 0, sizeof f);
	memcpy(f, golden("keepalive")->bytes, DIGINET_BODY_OFFSET);
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + DIGINET_MAX_BODY_LEN + 1);
	put(f, DIGINET_BODY_OFFSET + DIGINET_MAX_BODY_LEN + 1);
	emit("frame", "body-past-max");
}

/* ---- fuzz_decode: [sel] then a body or a frame ---- */

static void body_seed(unsigned sel, const uint8_t *b, size_t n, const char *name)
{
	put8(sel);
	put(b, n);
	emit("decode", name);
}

#define BODY(name, ...) do { \
	static const uint8_t b_[] = { __VA_ARGS__ }; \
	body_seed(1, b_, sizeof b_, name); \
} while (0)

static void decode_seeds(void)
{
	static const char *const DATA[] = {
		"keepalive", "fader_move", "button_mute", "scribble_write", "meter", "clock_init",
		"running_status", "desk_retry", "counter_write",
	};
	char name[96];
	struct diginet_cmd c;
	const struct diginet_personality *c24 = diginet_personality_of(DIGINET_DESK_CONTROL24);
	const struct diginet_personality *pc = diginet_personality_of(DIGINET_DESK_PROCONTROL);

	for (size_t i = 0; i < sizeof DATA / sizeof DATA[0]; i++) {
		const struct golden *g = golden(DATA[i]);
		struct diginet_frame f;
		if (diginet_frame_parse(g->bytes, g->len, &f) != DIGINET_OK) {
			fprintf(stderr, "golden frame %s does not parse\n", DATA[i]);
			exit(1);
		}
		body_seed(1, f.body, f.body_len, DATA[i]);
		snprintf(name, sizeof name, "%s-procontrol", DATA[i]);
		body_seed(2, f.body, f.body_len, name);
		snprintf(name, sizeof name, "%s-frame", DATA[i]);
		body_seed(0x80, g->bytes, g->len, name);
	}
	body_seed(0x80, golden("keepalive")->bytes, 20, "frame-refused");

	/* the cursor's refusals */
	BODY("status-for-data", 0x90, 0x90, 0x40);
	BODY("status-for-second-data", 0x90, 0x08, 0xc0, 0x05);
	BODY("no-status", 0x07, 0x41, 0x90, 0x08, 0x40);
	BODY("status-f1", 0xf1, 0x90, 0x08, 0x40, 0xff);
	BODY("channel-cut-short", 0x90, 0x08);
	/* a message that runs past the body, its one byte left a status byte */
	BODY("status-at-end", 0x90, 0xc0);
	BODY("sysex-no-f7", 0xf0, 0x13, 0x01, 0x40, 0x00);
	BODY("one-data-byte", 0xc0, 0x05, 0xd0, 0x7f, 0x10);
	BODY("aftertouch", 0xa0, 0x10, 0x20);
	/* a system exclusive between a message and data bytes that running status would take */
	BODY("status-cancelled", 0x90, 0x08, 0x40, 0xf0, 0x13, 0x01, 0x20, 0x01, 0x40, 0xf7, 0x08, 0x40);

	/* the decoder's kinds */
	BODY("fader-msb-only", 0xb0, 0x03, 0x40, 0x90, 0x08, 0x40);
	BODY("fader-lsb-explicit", 0xb0, 0x03, 0x40, 0xb0, 0x23, 0x70);
	BODY("fader-lsb-other-strip", 0xb0, 0x03, 0x40, 0x24, 0x70);
	BODY("fader-last", 0xb0, 0x1f, 0x7f);
	BODY("jog-vpot", 0xb0, 0x5c, 0x41, 0xb0, 0x45, 0x3f, 0x58, 0x10);
	BODY("cc-other", 0xb0, 0x60, 0x10);
	BODY("zone-key", 0x90, 0x05, 0x58, 0x90, 0x05, 0x1d);
	/* each edge of the zones and of the control changes, from both sides: strip 23, zone 18,
	 * zone 1D, id 1E; CC 20 alone, 3F, the first and the last V-Pot, 58, the jog; a fader MSB
	 * followed by a key on 20 + tt, which is no LSB */
	BODY("key-edges", 0x90, 0x05, 0x57, 0x90, 0x05, 0x58, 0x90, 0x05, 0x5d, 0x90, 0x05, 0x1e);
	BODY("cc-edges", 0xb0, 0x20, 0x10, 0xb0, 0x3f, 0x10, 0xb0, 0x40, 0x41, 0xb0, 0x57, 0x3f, 0xb0, 0x58,
	     0x41, 0xb0, 0x5b, 0x41, 0xb0, 0x5c, 0x40, 0xb0, 0x03, 0x40, 0x90, 0x23, 0x40);
	BODY("touch", 0x90, 0x09, 0x45);
	BODY("sysex-short", 0xf0, 0x13, 0x01, 0xf7);
	BODY("sysex-other-maker", 0xf0, 0x12, 0x01, 0x10, 0xf7);
	BODY("sysex-other-fn", 0xf0, 0x13, 0x01, 0x55, 0x00, 0xf7);
	BODY("meter-not-thermometer", 0xf0, 0x13, 0x01, 0x10, 0x00, 0x00, 0x05, 0xf7);
	BODY("sysex-wrong-sizes", 0xf0, 0x13, 0x01, 0x00, 0x01, 0xf7, 0xf0, 0x13, 0x01, 0x10, 0x00, 0xf7,
	     0xf0, 0x13, 0x01, 0x20, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0xf7, 0xf0, 0x13, 0x01, 0x30,
	     0x19, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	     0x48, 0x49, 0xf7);

	/* the system family: whole, cut short, inside another sysex */
	BODY("system-whole", 0xf0, 0x13, 0x01, 0x70, 0x00, 0xf7);
	BODY("system-cut-short", 0xf0, 0x13, 0x01, 0x70);
	BODY("system-in-sysex", 0xf0, 0x01, 0xf0, 0x13, 0x01, 0x70, 0xf7);
	BODY("system-after-message", 0x90, 0x08, 0x40, 0xf0, 0x13, 0x00, 0x70, 0x01, 0x02);
	/* function 70 of another maker is not the family */
	BODY("system-other-maker", 0xf0, 0x12, 0x01, 0x70, 0xf7);

	/* what the encoders make, read by both personalities */
	if (diginet_ring_encode(c24, 5, diginet_ring_fill(9) | 1, &c) == DIGINET_OK)
		body_seed(1, c.bytes, c.len, "ring");
	if (diginet_strip_leds_encode(c24, 2, DIGINET_AUTO_WRITE | DIGINET_AUTO_READ, &c) == DIGINET_OK)
		body_seed(1, c.bytes, c.len, "strip-leds");
	if (diginet_meter_encode(pc, 3, 1, 14, &c) == DIGINET_OK)
		body_seed(2, c.bytes, c.len, "meter-right");
	if (diginet_scribble_encode(pc, 0x10, (const uint8_t *)"ProCtrl8", &c) == DIGINET_OK)
		body_seed(2, c.bytes, c.len, "scribble-procontrol");
	body_seed(0, golden("running_status")->bytes + DIGINET_BODY_OFFSET, 14, "no-personality");
}

/* ---- fuzz_codec: operations ---- */

enum { NONE = 0, C24 = 1, PC = 2 };
static void op(unsigned kind, unsigned desk) { put8(desk * 15 + kind); }

static void codec_seeds(void)
{
	static const uint8_t seg[8] = { 0x7e, 0x30, 0x6d, 0x79, 0x33, 0x5b, 0x5f, 0x70 };
	static const uint8_t pl[3] = { 0x01, 0x02, 0x03 };

	/* every encoder, in range, for both desks */
	for (unsigned desk = C24; desk <= PC; desk++) {
		op(0, desk); put32(1); put32(700);
		op(1, desk); put32(DIGINET_BTN_MUTE); put32(2); put32(1);
		op(1, desk); put32(DIGINET_BTN_TOUCH); put32(3); put32(0);
		op(1, desk); put32(0x10); put32(DIGINET_ZONE_FIRST); put32(1);
		op(2, desk); put32(4); put32(1);
		op(3, desk); put32(5); put32((uint32_t)-3);
		op(4, desk); put32(7);
		op(5, desk); put32(6); put16(0x7fff);
		op(6, desk); put32(7); put32(1); put32(10);
		op(6, desk); put32(24); put32(0); put32(0);
		op(7, desk); put32(1); put32(DIGINET_AUTO_TOUCH);
		op(8, desk); put32(0x7f);
		op(9, desk); put32(0x20); put("OMX1Mix8", 8);
		op(10, desk); put8(0x05); put(seg, 8);
		op(11, desk); put8(0x01); put8(DIGINET_FN_METER); putlen(3); put(pl, 3);
		emit("codec", desk == C24 ? "encoders-control24" : "encoders-procontrol");
	}

	/* every encoder out of range, and without a personality */
	op(0, C24); put32(0); put32(DIGINET_FADER_MAX + 1);
	op(1, C24); put32(0x80); put32(0); put32(0);
	op(1, C24); put32(0); put32(0x40); put32(0);
	op(2, C24); put32(24); put32(1);
	op(3, C24); put32(0); put32(64);
	op(3, C24); put32(24); put32(0);
	op(4, C24); put32((uint32_t)-65);
	op(5, C24); put32(0); put16(0x8000);
	op(5, C24); put32(24); put16(1);
	op(6, C24); put32(0x20); put32(0); put32(1);
	op(6, C24); put32(0); put32(0); put32(15);
	op(7, C24); put32(0); put32(0x80);
	op(7, C24); put32(24); put32(0);
	op(8, C24); put32(0x80);
	op(9, C24); put32(0x80); put("abcdefgh", 8);
	op(9, C24); put32(0x01); put("ab\x80" "defgh", 8);
	op(10, C24); put8(0x80); put(seg, 8);
	op(10, C24); put8(0); put8(0x80); put(seg + 1, 7);
	op(11, C24); put8(0x80); put8(0x10); putlen(0);
	op(11, C24); put8(0x01); put8(0x80); putlen(0);
	op(11, C24); put8(0x01); put8(0x10); putlen(20); put("01234567890123456789", 20);
	op(11, C24); put8(0x01); put8(0x10); putlen(1); put8(0x80);
	/* each argument 1, at its width: only the missing personality is wrong */
	for (unsigned k = 0; k <= 10; k++) {
		static const uint8_t U32S[11] = { 2, 3, 2, 2, 1, 1, 3, 2, 1, 1, 0 };
		op(k, NONE);
		for (unsigned i = 0; i < U32S[k]; i++)
			put32(1);
		if (k == 5)
			put16(1);
		if (k >= 9)
			put("\x01\x02\x03\x04\x05\x06\x07\x08\x09", k == 9 ? 8 : 9);
	}
	emit("codec", "out-of-range");

	/* every range at its last accepted value, for both desks: out-of-range holds the first
	 * refused one, so a bound moved by one either way shows on one of the two */
	for (unsigned desk = C24; desk <= PC; desk++) {
		unsigned last = desk == C24 ? 23 : 7;
		static const uint8_t pl19[19] = { 0x7f };
		op(0, desk); put32(last); put32(DIGINET_FADER_MAX);
		op(1, desk); put32(0x7f); put32(0x3f); put32(1);
		op(2, desk); put32(last); put32(1);
		op(3, desk); put32(last); put32((uint32_t)-64);
		op(3, desk); put32(0); put32(63);
		op(4, desk); put32((uint32_t)-64);
		op(4, desk); put32(63);
		op(5, desk); put32(last); put16(0x7fff);
		op(6, desk); put32(0x1f); put32(1); put32(14);
		op(7, desk); put32(last); put32(0x7f);
		op(8, desk); put32(0x7f);
		op(9, desk); put32(0x7f); put("\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f", 8);
		op(10, desk); put8(0x7f); put("\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f", 8);
		op(11, desk); put8(0x7f); put8(0x7f); putlen(19); put(pl19, 19);
	}
	emit("codec", "edges");

	/* each argument wider than a byte (or than 16 bits) whose low byte (or 16 bits) is in range,
	 * so an encoder that cuts it short before its range check shows; and the flags on with
	 * their low byte zero */
	op(0, C24); put32(0x100); put32(0);
	op(0, C24); put32(0); put32(0x10000);
	op(1, C24); put32(0x100); put32(0); put32(0);
	op(1, C24); put32(0); put32(0x100); put32(0);
	op(1, C24); put32(1); put32(1); put32(0x100);
	op(1, C24); put32(1); put32(1); put32(0x80000000);
	op(2, C24); put32(0x100); put32(1);
	op(2, C24); put32(1); put32(0x100);
	op(3, C24); put32(0x100); put32(0);
	op(3, C24); put32(0); put32(0x10000);
	op(3, C24); put32(0); put32((uint32_t)-0x10000);
	op(4, C24); put32(0x10000);
	op(4, C24); put32((uint32_t)-0x10000);
	op(4, C24); put32(0x80000000);
	op(5, C24); put32(0x100); put16(1);
	op(6, C24); put32(0x100); put32(0); put32(1);
	op(6, C24); put32(0); put32(0x100); put32(1);
	op(6, C24); put32(0); put32(0); put32(0x100);
	op(7, C24); put32(0x100); put32(0);
	op(7, C24); put32(0); put32(0x100);
	op(8, C24); put32(0x100);
	op(9, C24); put32(0x100); put("abcdefgh", 8);
	op(14, NONE); put32(0x100); put16(0);
	op(14, NONE); put32(0x10001); put16(0);
	op(14, NONE); put32(0x80000000); put16(0);
	emit("codec", "wide-arguments");

	/* the mutants' seeds */
	op(0, C24); put32(24); put32(0);
	emit("codec", "fader-past-last-strip");
	op(0, C24); put32(256); put32(0);
	emit("codec", "fader-strip-256");
	op(0, C24); put32(0); put32(DIGINET_FADER_MAX);
	emit("codec", "fader-full");
	op(11, C24); put8(0x01); put8(DIGINET_FN_SYSTEM); putlen(2); put("\x00\x00", 2);
	op(11, C24); put8(0x80); put8(DIGINET_FN_SYSTEM); putlen(0);
	emit("codec", "sysex-system");
	op(11, C24); put8(0x01); put8(0x10); putlen(260); put8(0x80);
	emit("codec", "sysex-len-260");
	op(11, C24); put8(0x01); put8(0x10); putlen(UINT64_MAX - 4); put8(0x00);
	emit("codec", "sysex-len-wraps");
	op(13, C24); put16(9); put("12345678.", 9);
	emit("codec", "counter-text-last-dot");

	/* the text helpers */
	static const char *const TEXT[] = {
		"Kick", "Vox.2", "a.1.9", "\xc3\xa9t\xc3\xa9", "", "longer than eight",
	};
	for (size_t i = 0; i < sizeof TEXT / sizeof TEXT[0]; i++) {
		op(12, i & 1 ? PC : C24); put8(0x10 + i); put16(strlen(TEXT[i])); put(TEXT[i], strlen(TEXT[i]));
	}
	op(12, NONE); put8(0x01); put16(3); put("abc", 3);
	emit("codec", "scribble-text");
	static const char *const COUNTER[] = {
		"12.5", "1.2.3.4.5.6.7.8", "123456789", "0:00", "-HELLO-", "..", "", "1..2",
		/* every character the display shows */
		"01234567", "89AaBbCc", "DdEeFfHh", "JjLlOoPp", "RrSsUuYy", "Zz- ",
	};
	for (size_t i = 0; i < sizeof COUNTER / sizeof COUNTER[0]; i++) {
		op(13, C24); put16(strlen(COUNTER[i])); put(COUNTER[i], strlen(COUNTER[i]));
	}
	emit("codec", "counter-text");
	/* text read as an announce name: each desk's name, each with its first byte changed, and
	 * cut one byte short */
	static const char *const NAMES[] = { "CNTRL|24", "MAINUNIT", "XNTRL|24", "XAINUNIT", "CNTRL|2", "MAINUNI", "" };
	for (size_t i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++) {
		op(12, NONE); put8(0x10); put16(strlen(NAMES[i])); put(NAMES[i], strlen(NAMES[i]));
	}
	emit("codec", "personality-names");
	op(14, NONE); put32(0); put16(0);
	op(14, NONE); put32(10); put16(0x3ff);
	op(14, NONE); put32(14); put16(0x3fff);
	op(14, NONE); put32(15); put16(0x7fff);
	op(14, NONE); put32(200); put16(0x0005);
	emit("codec", "masks");
}

/* ---- fuzz_transport: a session ---- */

enum { F_AUTO = 1, F_ZERO = 2, F_DESKSET = 4, F_RAW = 8, F_OTHER_IF = 128 };

/* the config, in the harness's units: each argument is the value the session gets */
static void config(unsigned flags, unsigned retries, unsigned ack_ms, unsigned ka_ms, unsigned backoff_ms,
		   unsigned offline_ms, unsigned wake_ms, unsigned gap_us, unsigned max_cmds, unsigned max_body)
{
	put8(flags);
	put8(retries);
	put8(ack_ms - 1);
	put16(ka_ms - 1);
	put8(backoff_ms);
	put16(offline_ms - 1);
	put16(wake_ms - 1);
	put16(gap_us);
	put8(max_cmds - 1);
	put16(max_body - DIGINET_CMD_MAX_LEN);
}

/* the default config, as diginet_session_config_default() gives it, scaled to fit u16 ms */
static void config_default(unsigned flags)
{
	config(flags, 5, 100, 10000, 255, 25000, 3000, 2000, 48, 314);
}

enum { T_RAW = 0, T_FRAME, T_ANNOUNCE, T_TIME, T_SUBMIT, T_WAKE, T_CLOSE, T_FAIL, T_POLL };
enum { C_DATA = 0, C_ACK, C_E0, C_E1, C_E2, C_E3, C_UNKNOWN };
enum { FROM_DESK = 0, FROM_DESK2 = 1 << 3, FROM_HOST = 2 << 3, FROM_NOTDD = 3 << 3 };
enum { TO_HOST = 0, TO_BCAST = 1 << 5, TO_OTHER = 2 << 5 };
#define ACK_LAST 0x80

static void t_frame(unsigned sel, unsigned send, unsigned ack, unsigned retry, const uint8_t *b, size_t n)
{
	put8(T_FRAME);
	put8(sel);
	put16(send);
	put16(ack);
	put8(retry);
	put_rec(b, n);
}

/* mac: < 10 the host's MAC at that offset, 10..12 another host's, else none */
static void t_announce(int e1, unsigned mac, unsigned name)
{
	put8(T_ANNOUNCE);
	put8(e1);
	put8(mac);
	put8(name);
}

static void t_time(unsigned scale, unsigned n)
{
	put8(T_TIME);
	put8(scale);
	put16(n);
}

enum { US = 0, MSEC = 1, DECI = 2, SEC = 3 };

static void t_tagged(unsigned kind, unsigned addr, unsigned display, unsigned len, const char *fill)
{
	put8(T_SUBMIT);
	put8(kind - 1);
	put8(addr);
	put8(display);
	put8(len - 3);
	put(fill, len - 3);
}

static void t_rawcmd(unsigned kind, unsigned addr, unsigned display, const uint8_t *b, size_t n)
{
	put8(T_SUBMIT);
	put8(kind - 1);
	put8(addr);
	put8(display);
	put_rec(b, n);
}

/* a ProControl: e0, our e2, its a0, an e1 naming us: online */
static void online(void)
{
	t_announce(0, 13, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 1);
}

static const uint8_t MUTE[3] = { 0x90, 0x08, 0x40 };

static void transport_seeds(void)
{
	uint8_t f[DIGINET_MAX_FRAME_LEN];
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .send_counter = 0x200 };
	struct diginet_cmd c;
	const struct diginet_personality *c24 = diginet_personality_of(DIGINET_DESK_CONTROL24);

	config_default(F_AUTO);
	put8(T_POLL); put8(0); put_rec(NULL, 0);   /* idle: nothing due */
	online();
	emit("transport", "online");

	/* data from the desk, ACKed with its send counter, a retry ACKed again */
	config_default(F_AUTO);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0x22, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_BCAST, 0x106, 0x22, 1, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x106, 0x22, 1, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x107, 0x22, 0, (const uint8_t *)"\0", 1);
	t_time(DECI, 4);
	emit("transport", "data-acked");

	/* data before any session, from a desk the config names, then closed */
	config_default(F_DESKSET);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x10, 0x01, 0, MUTE, sizeof MUTE);
	put8(T_CLOSE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x11, 0x01, 0, MUTE, sizeof MUTE);
	put8(T_WAKE);
	emit("transport", "data-before-session");

	/* frames the session does not take: from us, for another host, from another desk, from
	 * a MAC that is not Digidesign's, of a command it does not know, a desk's e2, an ACK of a
	 * frame not in flight */
	config_default(F_AUTO);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 1, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_E0 | FROM_NOTDD | TO_BCAST, 1, 0, 0, NULL, 0);
	online();
	t_frame(C_DATA | FROM_HOST | TO_HOST, 2, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_OTHER, 3, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK2 | TO_HOST, 4, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_UNKNOWN | FROM_DESK | TO_HOST, 5, 0, 0, NULL, 0);
	t_frame(C_E2 | FROM_DESK | TO_HOST, 6, 0, 0, NULL, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST, 7, 0x999, 0, NULL, 0);
	t_frame(C_E1 | FROM_DESK | TO_BCAST, 8, 0, 0, MUTE, sizeof MUTE);   /* an announce too short */
	put8(T_RAW); put_rec(golden("fader_move")->bytes, 20);
	emit("transport", "filters");

	/* an e2 nobody answers: retried until max_retries, dropped, then the wake times out */
	config(F_AUTO, 3, 1, 60000, 0, 60000, 50, 0, 48, 314);
	t_announce(0, 13, 1);
	for (int i = 0; i < 5; i++)
		t_time(MSEC, 1);
	t_time(MSEC, 60);
	emit("transport", "wake-unanswered");

	/* an e2 nobody answers, one retry: a tick after that retry finds it waiting for its timeout,
	 * then the timeout drops it */
	config(F_AUTO, 1, 10, 60000, 0, 60000, 50, 0, 48, 314);
	t_announce(0, 13, 1);
	t_time(MSEC, 10);
	t_time(MSEC, 1);
	t_time(MSEC, 9);
	emit("transport", "ack-lost-waits-its-timeout");

	/* a retransmission whose send fails still counts */
	config(F_AUTO, 2, 1, 60000, 0, 60000, 50, 0, 48, 314);
	t_announce(0, 13, 1);
	put8(T_FAIL);
	for (int i = 0; i < 4; i++)
		t_time(MSEC, 1);
	emit("transport", "retransmit-fails");

	/* a frame in flight, a wake whose send fails, then the retransmission of that frame */
	config(F_AUTO, 3, 1, 1, 0, 60000, 3000, 0, 48, 314);
	online();
	t_time(MSEC, 2);
	put8(T_FAIL);
	put8(T_WAKE);
	t_time(DECI, 5);
	emit("transport", "wake-fails-in-flight");

	/* online, then a wake whose send fails, which leaves the session online with no e1 since:
	 * the desk's e0 still ends it, and auto_wake wakes it again */
	config_default(F_AUTO);
	online();
	put8(T_FAIL);
	put8(T_WAKE);
	t_announce(0, 13, 1);
	emit("transport", "e0-after-failed-wake");

	/* online, a wake whose send fails, then the desk's e1 naming us: the session is still online,
	 * and that first e1 since the failed wake is RENEWED (the host shows everything again) */
	config_default(F_AUTO);
	online();
	put8(T_FAIL);
	put8(T_WAKE);
	t_announce(1, 0, 1);
	emit("transport", "e1-after-failed-wake");

	/* a frame of commands that goes, then no ACK for ack_timeout: the same frame again */
	config(F_AUTO, 3, 10, 60000, 0, 60000, 3000, 0, 48, 314);
	online();
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	t_time(MSEC, 1);
	t_time(MSEC, 10);
	emit("transport", "retransmit-data");

	/* keepalives on their own clock, a desk retry holding them back, then silence */
	config(F_AUTO, 1, 1, 10, 30, 1000, 3000, 0, 48, 314);
	online();
	for (int i = 0; i < 3; i++) {
		t_time(MSEC, 11);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	}
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x30, 0, 1, MUTE, sizeof MUTE);
	t_time(MSEC, 11);
	t_time(MSEC, 40);
	t_time(SEC, 2);
	emit("transport", "keepalive-silence");

	/* the ways a session ends: e0, a desk e3, another host's e1, close */
	config_default(F_AUTO);
	online();
	t_announce(0, 13, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 3, 1);
	t_frame(C_E3 | FROM_DESK | TO_HOST, 1, 0, 0, NULL, 0);
	t_announce(0, 13, 2);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 10, 1);
	put8(T_WAKE);
	t_announce(0, 13, 1);
	put8(T_CLOSE);
	put8(T_CLOSE);
	t_announce(0, 13, 1);
	emit("transport", "session-ends");

	/* a wake asked for while another host holds the desk */
	config_default(0);
	t_announce(1, 11, 1);
	put8(T_WAKE);
	emit("transport", "wake-foreign");

	/* a close while another host holds the desk: no e3 */
	config_default(0);
	t_announce(1, 11, 1);
	put8(T_CLOSE);
	emit("transport", "close-foreign");

	/* without auto_wake: woken by hand, online, then the desk's e0 ends it */
	config_default(0);
	t_announce(0, 13, 1);
	put8(T_WAKE);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 1);
	t_announce(0, 13, 1);
	emit("transport", "offline-e0");

	/* online, then nothing from the desk for longer than offline_ms */
	config(F_AUTO, 5, 100, 60000, 0, 1000, 3000, 0, 48, 314);
	online();
	t_time(SEC, 2);
	emit("transport", "silence");

	/* the e1 naming the host before the a0 of the e2: online only with both */
	config_default(F_AUTO);
	t_announce(0, 13, 1);
	t_announce(1, 0, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	emit("transport", "e1-before-ack");

	/* the host's MAC at the last offset of the 15 leading bytes it fits */
	config_default(F_AUTO);
	t_announce(0, 13, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 9, 1);
	emit("transport", "e1-mac-at-9");

	/* an e2 unanswered, with time passing in steps of 6 and 5 ms against a 10 ms ack timeout */
	config(F_AUTO, 3, 10, 60000, 0, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 1);
	t_time(MSEC, 6);
	t_time(MSEC, 5);
	t_time(MSEC, 6);
	t_time(MSEC, 5);
	emit("transport", "retry-timing");

	/* a 10 ms keepalive, time passing in steps of 5 ms, each keepalive ACKed */
	config(F_AUTO, 5, 100, 10, 0, 60000, 3000, 0, 48, 314);
	online();
	for (int i = 0; i < 6; i++) {
		t_time(MSEC, 5);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	}
	emit("transport", "keepalive-clock");

	/* two display writes, one a frame, against a 2000 us gap: the second goes exactly when
	 * the gap has passed */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 2000, 1, 314);
	online();
	t_tagged(DIGINET_KEY_SCRIBBLE, 1, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	t_tagged(DIGINET_KEY_SCRIBBLE, 2, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	t_time(US, 1000);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	t_time(US, 2000);
	emit("transport", "display-gap-exact");

	/* a desk retry holds the host back 10 ms; a command waits, then goes exactly as the
	 * back-off ends */
	config(F_AUTO, 5, 100, 60000, 10, 60000, 3000, 0, 48, 314);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x40, 0, 1, MUTE, sizeof MUTE);
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	t_time(MSEC, 5);
	t_time(MSEC, 5);
	emit("transport", "backoff-exact");

	/* the wake timeout and the silence, each reached exactly */
	config(F_AUTO, 0, 100, 60000, 0, 60000, 5, 0, 48, 314);
	t_announce(0, 13, 1);
	t_time(MSEC, 5);
	emit("transport", "wake-timeout-exact");
	config(F_AUTO, 5, 100, 60000, 0, 7, 3000, 0, 48, 314);
	online();
	t_time(MSEC, 7);
	emit("transport", "silence-exact");

	/* the same desk counter twice, with no retry: two frames, both delivered */
	config_default(F_AUTO);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0, 0, MUTE, sizeof MUTE);
	emit("transport", "data-repeat");

	/* a manual wake, in the zero-sum mode, through poll */
	config_default(F_ZERO);
	put8(T_WAKE);
	t_announce(0, 13, 1);
	put8(T_WAKE);
	h.cmd = DIGINET_CMD_ACK;
	h.ack_counter = 0;
	int n = diginet_frame_build(f, sizeof f, HOST, DESK, &h, NULL, 0, DIGINET_SUM_BODY);
	put8(T_POLL); put8(0); put_rec(f, (size_t)n);
	h.cmd = DIGINET_CMD_DATA;
	n = diginet_frame_build(f, sizeof f, HOST, DESK, &h, MUTE, sizeof MUTE, DIGINET_SUM_BODY);
	put8(T_POLL); put8(0); put_rec(f, (size_t)n);
	t_announce(1, 4, 1);
	put8(T_POLL); put8(1); put_rec(f, (size_t)n);   /* and its retransmission behind it */
	put8(T_POLL); put8(2); put_rec(f, (size_t)n);   /* recv fails */
	put8(T_POLL); put8(0); put_rec(NULL, 0);
	emit("transport", "wake-poll");

	/* online, one command queued, then a poll whose recv hands over the desk's a0 for counter
	 * 1 twice: the tick after the first copy sends the command at counter 1, and the second
	 * copy is its ACK */
	config_default(F_AUTO);
	online();
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	h.cmd = DIGINET_CMD_ACK;
	h.ack_counter = 1;
	n = diginet_frame_build(f, sizeof f, HOST, DESK, &h, NULL, 0, DIGINET_SUM_BODY);
	put8(T_POLL); put8(1); put_rec(f, (size_t)n);
	emit("transport", "poll-twice-ack-new-frame");

	/* a Control|24 online on its a0, a poll whose recv hands its e0 over twice, then its a0 for
	 * the e2: the tick between the copies sends the e2 the first copy owes, the second copy
	 * owes another, and that one goes after the a0 */
	static const uint8_t BCAST[DIGINET_MAC_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct diginet_header e0 = { .cmd = DIGINET_CMD_ANNOUNCE };
	uint8_t ann[DIGINET_ANNOUNCE_BODY_LEN];
	memset(ann, 0, sizeof ann);
	memcpy(ann + 15, "1.37", 4);
	memcpy(ann + 24, "CNTRL|24", 8);
	config_default(F_AUTO);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	n = diginet_frame_build(f, sizeof f, BCAST, DESK, &e0, ann, sizeof ann, DIGINET_SUM_BODY);
	put8(T_POLL); put8(1); put_rec(f, (size_t)n);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 2, 0, 0, NULL, 0);
	emit("transport", "c24-poll-twice-e0-e2-owed");

	/* latest wins: two values for one fader, then sent; one value for an input key, twice */
	config_default(F_AUTO);
	online();
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x11\x21");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_time(MSEC, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	emit("transport", "coalesce");

	/* frames full by count, by bytes, and display writes paced */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 2000, 3, 30);
	online();
	for (unsigned i = 0; i < 8; i++)
		t_tagged(DIGINET_KEY_RING, i, 0, 10, "\x01\x02\x03\x04\x05\x06\x07");
	for (unsigned i = 0; i < 4; i++)
		t_tagged(DIGINET_KEY_SCRIBBLE, i, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	for (int i = 0; i < 8; i++) {
		t_time(US, 700);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
		put8(T_POLL); put8(0); put_rec(NULL, 0);   /* the deadline of a paced queue */
	}
	emit("transport", "batches");

	/* two commands each whole alone that are F0 13 xx 70 together: the first ends F0 13, and
	 * the second is serial 112, so its A0 70 follows */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 0, 255, DIGINET_MAX_BODY_LEN);
	for (unsigned i = 0; i < 111; i++)
		t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 5, "\xf0\x13");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	online();
	t_time(MSEC, 1);
	emit("transport", "split-system");

	/* the queue filled while no session lives */
	config_default(F_AUTO);
	for (unsigned i = 0; i < DIGINET_QUEUE_MAX + 1; i++)
		t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_METER, 1, 0, 3, "");
	emit("transport", "queue-full");

	/* raw commands: the system family refused whole and cut short, others queued and sent */
	static const uint8_t SYS[6] = { 0xf0, 0x13, 0x01, 0x70, 0x00, 0xf7 };
	config_default(F_AUTO | F_RAW);
	online();
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, SYS, 6);
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, NULL, 0);
	if (diginet_fader_encode(c24, 2, 300, &c) == DIGINET_OK)
		t_rawcmd(DIGINET_KEY_FADER, 2, 0, c.bytes, c.len);
	t_time(MSEC, 1);
	emit("transport", "submit-system");
	config_default(F_AUTO | F_RAW);
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, SYS, 4);
	emit("transport", "submit-system-cut-short");
	/* a Control|24 just booted: online on the a0 alone, its keepalive ACKed; its e0 then is
	 * owed an e2 in the frame slot, which it ACKs, and it announces e1 naming us */
	config(F_AUTO, 5, 100, 10, 0, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_time(MSEC, 10);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 2, 0, 0, NULL, 0);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 3, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	emit("transport", "c24-session");

	/* a Control|24 online on its a0 whose data frame was a retry: its e0 is owed an e2, which
	 * waits for the back-off to end, so the deadline is that end; then the e2 goes, the desk
	 * ACKs it and announces e1 naming us */
	config(F_AUTO, 5, 100, 10000, 10, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x40, 0, 1, MUTE, sizeof MUTE);
	t_announce(0, 13, 0);
	t_time(MSEC, 10);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 2, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	emit("transport", "c24-e0-during-backoff");

	/* a Control|24 rebooted while online, its keepalive having moved the counter: its e0 ends
	 * the session, and the wake that follows carries 0 */
	config(F_AUTO, 5, 100, 10, 0, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	t_time(MSEC, 20);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 2, 0, 0, NULL, 0);
	t_announce(0, 13, 0);
	emit("transport", "c24-reboot");

	/* a Control|24 online that stops ACKing: its keepalive lost after max_retries ends the
	 * session, and its next e0 wakes it again */
	config(F_AUTO, 2, 1, 10, 0, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	t_time(MSEC, 10);
	for (int i = 0; i < 3; i++)
		t_time(MSEC, 1);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	emit("transport", "c24-ack-lost");

	/* a Control|24 announcing its session in e1: e1 naming us after its a0, then its e0 ends
	 * the session and wakes it again */
	config_default(F_AUTO);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	t_announce(0, 13, 0);
	emit("transport", "c24-e1-then-e0");

	/* a desk no name selects is held to e1: its a0 alone is not online, the e1 then is */
	config_default(F_AUTO);
	t_announce(0, 13, 2);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 2);
	emit("transport", "unknown-desk-e1");

	/* a Control|24 that still announces our closed session in e1 (#33): another host's e1 is
	 * no wake, the e1 naming us is, at once; its a0 brings the session online, and the next
	 * e1 naming us is no second e2 */
	config_default(F_AUTO);
	t_announce(1, 11, 0);
	t_announce(1, 0, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	emit("transport", "retake-e1");

	/* the host restarted while the desk holds the session: the e1 naming us wakes it, and the
	 * a0 for that e2 brings it online with no new e1 after it */
	config_default(F_AUTO);
	t_announce(1, 0, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	emit("transport", "restart-in-session");

	/* without auto_wake the e1 naming us wakes nothing */
	config_default(0);
	t_announce(1, 0, 0);
	emit("transport", "retake-e1-manual");

	/* a Control|24 moved here from another interface of this host (#40): its e1 naming that
	 * interface's MAC is no foreign session but ours, woken at once; its a0 brings it online,
	 * and the next such e1 is no second e2 */
	config_default(F_AUTO | F_OTHER_IF);
	t_announce(1, 10, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 10, 0);
	emit("transport", "retake-other-if");

	/* A deaf Control|24 (#35): it announces and lets every e2 time out. Deaf at the third
	 * timeout, each 100 ms after an announce, within offline_ms (500); not again at the fourth. */
	config(F_AUTO, 0, 100, 60000, 0, 500, 100, 0, 48, 314);
	for (int i = 0; i < 4; i++) {
		t_announce(0, 13, 0);
		t_time(MSEC, 100);
	}
	emit("transport", "deaf");

	/* two timeouts, an a0 for the third e2 (online), the desk's e3, then one timeout: one,
	 * not three */
	config(F_AUTO, 0, 100, 60000, 0, 500, 100, 0, 48, 314);
	for (int i = 0; i < 2; i++) {
		t_announce(0, 13, 0);
		t_time(MSEC, 100);
	}
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_frame(C_E3 | FROM_DESK | TO_HOST, 2, 0, 0, NULL, 0);
	t_announce(0, 13, 0);
	t_time(MSEC, 100);
	emit("transport", "deaf-reset-ack");

	/* two timeouts, an e1 naming another host, then one timeout after its e0 */
	config(F_AUTO, 0, 100, 60000, 0, 500, 100, 0, 48, 314);
	for (int i = 0; i < 2; i++) {
		t_announce(0, 13, 0);
		t_time(MSEC, 100);
	}
	t_announce(1, 10, 0);
	t_announce(0, 13, 0);
	t_time(MSEC, 100);
	emit("transport", "deaf-foreign");

	/* two timeouts, a second of silence, a wake by hand that times out with no recent
	 * announce, then one more timeout after an announce: the run started again */
	config(F_AUTO, 0, 100, 60000, 0, 500, 100, 0, 48, 314);
	for (int i = 0; i < 2; i++) {
		t_announce(0, 13, 0);
		t_time(MSEC, 100);
	}
	t_time(SEC, 1);
	put8(T_WAKE);
	t_time(MSEC, 100);
	t_announce(0, 13, 0);
	t_time(MSEC, 100);
	emit("transport", "deaf-silent");

	/* each timeout exactly offline_ms after the announce: not announcing, never deaf */
	config(F_AUTO, 0, 100, 60000, 0, 100, 100, 0, 48, 314);
	for (int i = 0; i < 3; i++) {
		t_announce(0, 13, 0);
		t_time(MSEC, 100);
	}
	emit("transport", "deaf-window-exact");

	/* deaf_wakes 0 (flags bits 4-5 = 3): a wake by hand that times out on a silent desk is
	 * no report */
	config(3 << 4, 0, 100, 60000, 0, 500, 100, 0, 48, 314);
	t_announce(0, 13, 0);
	t_time(SEC, 1);
	put8(T_WAKE);
	t_time(MSEC, 100);
	emit("transport", "deaf-off");
}

/* ---- fuzz_mux: the desk mux ---- */

enum { M_ANN = 0, M_FRAME, M_RAW, M_TIME, M_ATTACH, M_DETACH, M_SUBMIT, M_POLL };
enum { K_E1 = 1, K_C24 = 0, K_PC = 2, K_OTHER = 4, K_NAMES_US = 8, K_SHORT = 16 };
enum { MS_DATA = 0, MS_ACK = 1, MS_E3 = 5, MS_BCAST = 8, MS_ACK_LAST = 0x80 };

/* the config, in the harness's units */
static void mux_config(unsigned flags, unsigned gone_ms, unsigned offline_ms, unsigned wake_ms)
{
	put8(flags);
	put16(gone_ms - 1);
	put16(offline_ms - 1);
	put16(wake_ms - 1);
}

/* `ifx` is the interface itself, 1..3 */
static void m_ann(unsigned who, unsigned ifx, unsigned kind)
{
	put8(M_ANN);
	put8(who);
	put8(ifx - 1);
	put8(kind);
}

static void m_frame(unsigned who, unsigned ifx, unsigned sel, unsigned send, const uint8_t *b, size_t n)
{
	put8(M_FRAME);
	put8(who);
	put8(ifx - 1);
	put8(sel);
	put16(send);
	put_rec(b, n);
}

static void m_time(unsigned scale, unsigned n)
{
	put8(M_TIME);
	put8(scale);
	put16(n);
}

static void m_op(unsigned op, unsigned slot)
{
	put8(op);
	put8(slot);
}

static void mux_seeds(void)
{
	static const uint8_t junk[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	uint8_t f[DIGINET_MAX_FRAME_LEN], body[DIGINET_ANNOUNCE_BODY_LEN];

	/* two desks on interfaces 1 and 2, each attached as it appears: a Control|24 online on its
	 * a0, a ProControl on its a0 and the e1 naming this host; a key from each, a fader to
	 * each, an announce again, time */
	mux_config(1, 30000, 25000, 3000);
	m_ann(0, 1, K_C24);
	m_frame(0, 1, MS_ACK | MS_ACK_LAST, 1, NULL, 0);
	m_ann(1, 2, K_PC);
	m_frame(1, 2, MS_ACK | MS_ACK_LAST, 1, NULL, 0);
	m_ann(1, 2, K_PC | K_E1 | K_NAMES_US);
	m_frame(0, 1, MS_DATA, 0x40, MUTE, sizeof MUTE);
	m_frame(1, 2, MS_DATA, 0x40, MUTE, sizeof MUTE);
	m_op(M_SUBMIT, 0);
	m_op(M_SUBMIT, 1);
	m_frame(0, 1, MS_ACK | MS_ACK_LAST, 2, NULL, 0);
	m_frame(1, 2, MS_ACK | MS_ACK_LAST, 2, NULL, 0);
	m_time(MSEC, 10);
	m_ann(0, 1, K_C24);
	emit("mux", "two-desks");

	/* a desk online on its a0 says goodbye with an e3 to this host: its session reads it */
	mux_config(1, 30000, 25000, 3000);
	m_ann(0, 1, K_C24);
	m_frame(0, 1, MS_ACK | MS_ACK_LAST, 1, NULL, 0);
	m_frame(0, 1, MS_E3, 2, NULL, 0);
	emit("mux", "desk-leaves");

	/* the same desk heard on another interface: set aside */
	mux_config(1, 30000, 25000, 3000);
	m_ann(0, 1, K_C24);
	m_ann(0, 2, K_C24);
	m_frame(0, 2, MS_DATA, 0x40, MUTE, sizeof MUTE);
	emit("mux", "pinned");

	/* attached in its APPEARED notice: the announce is its session's first frame */
	mux_config(1, 30000, 25000, 3000);
	m_ann(0, 1, K_C24);
	emit("mux", "auto-attach");

	/* nothing appears: an announce from a MAC that is no Digidesign's, a data frame from a desk
	 * that never announced, a frame of no grammar, an announce one byte short */
	mux_config(1, 30000, 25000, 3000);
	m_ann(9, 1, K_C24);
	m_frame(2, 1, MS_DATA, 0x40, MUTE, sizeof MUTE);
	put8(M_RAW);
	put8(0);
	put_rec(junk, sizeof junk);
	m_ann(3, 1, K_C24 | K_SHORT);
	emit("mux", "set-aside");

	/* gone exactly gone_ms (500) after its last frame; the next desk takes the lowest slot */
	mux_config(0, 500, 25000, 3000);
	m_ann(0, 1, K_C24);
	m_time(MSEC, 499);
	m_time(MSEC, 1);
	m_ann(1, 1, K_OTHER);
	emit("mux", "gone-exact");

	/* an attached ProControl online, then silent: its session ends at offline_ms (100), and
	 * it is gone with it, long before gone_ms */
	mux_config(1, 30000, 100, 3000);
	m_ann(0, 1, K_PC);
	m_frame(0, 1, MS_ACK | MS_ACK_LAST, 1, NULL, 0);
	m_ann(0, 1, K_PC | K_E1 | K_NAMES_US);
	m_time(MSEC, 50);
	m_time(MSEC, 50);
	emit("mux", "gone-silence");

	/* nine desks, eight slots */
	mux_config(0, 30000, 25000, 3000);
	for (unsigned who = 0; who < 9; who++)
		m_ann(who, 1, K_C24);
	emit("mux", "table-full");

	/* attach: an empty slot, a desk on an interface with no MAC, one that has, twice, out of
	 * range; detach: attached, twice, and one never attached */
	mux_config(0, 30000, 25000, 3000);
	m_op(M_ATTACH, 0);
	m_ann(0, 3, K_C24);
	m_op(M_ATTACH, 0);
	m_ann(1, 1, K_C24);
	m_op(M_ATTACH, 1);
	m_op(M_ATTACH, 1);
	m_op(M_ATTACH, 8);
	m_op(M_DETACH, 1);
	m_op(M_DETACH, 1);
	m_op(M_DETACH, 0);
	emit("mux", "attach-refusals");

	/* through diginet_mux_poll(): an announce on interface 2, then a recv that fails */
	struct diginet_header h = { .cmd = DIGINET_CMD_ANNOUNCE };
	static const uint8_t BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	memset(body, 0, sizeof body);
	memcpy(body + 15, "1.08", 4);
	memcpy(body + 24, "CNTRL|24", 8);
	int n = diginet_frame_build(f, sizeof f, BC, DESK, &h, body, sizeof body, DIGINET_SUM_BODY);
	mux_config(1, 30000, 25000, 3000);
	put8(M_POLL);
	put8(0);
	put8(1);
	put_rec(f, (size_t)n);
	put8(M_POLL);
	put8(1);
	put8(0);
	put_rec(NULL, 0);
	emit("mux", "poll");
}

int main(int argc, char **argv)
{
	(void)fails;
	if (argc != 3) {
		fprintf(stderr, "usage: %s <golden frames> <corpus dir>\n", argv[0]);
		return 2;
	}
	golden_load(argv[1]);
	g_root = argv[2];
	mkdir_p(g_root);
	frame_seeds();
	decode_seeds();
	codec_seeds();
	transport_seeds();
	mux_seeds();
	free(S.p);
	return 0;
}
