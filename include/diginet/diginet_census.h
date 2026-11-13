/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * The census: every control of a desk as the library knows it, in the order an operator walks
 * the desk, with the frame the desk sends for an input and the write that exercises an output.
 * diginet-census walks it against a real desk; tests/test_census walks it against the emulator
 * and reads a desk's recorded bodies back (docs/census.md).
 */
#ifndef DIGINET_CENSUS_H
#define DIGINET_CENSUS_H

#include <diginet/diginet_codec.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A section button: 90 bb (40|zone) pressed, 90 bb zone released; lamp when the desk has one
 * behind it (the host lights it with the same bytes). src/diginet_census_c24.c carries the
 * Control|24's, read out of ReaControl24's map. */
struct diginet_section_button {
	uint8_t zone, id, lamp;
	const char *name, *group;
};
extern const struct diginet_section_button diginet_c24_section_buttons[];
extern const size_t diginet_c24_section_button_count;

enum diginet_control_kind {
	/* inputs: the desk sends them */
	DIGINET_CTL_FADER_IN = 1,  /* the operator moves the fader */
	DIGINET_CTL_TOUCH,         /* the operator touches the fader cap */
	DIGINET_CTL_STRIP_BUTTON,  /* a strip button pressed */
	DIGINET_CTL_VPOT,          /* a V-Pot turned */
	DIGINET_CTL_JOG,           /* the jog wheel turned */
	DIGINET_CTL_SECTION_BUTTON,
	/* outputs: the host writes them */
	DIGINET_CTL_FADER_OUT,     /* the motor takes the fader to a position */
	DIGINET_CTL_STRIP_LAMP,    /* the lamp of a strip button */
	DIGINET_CTL_RING,          /* the V-Pot's 15 LEDs */
	DIGINET_CTL_METER,         /* a meter column, left or right */
	DIGINET_CTL_STRIP_LEDS,    /* the strip's automation LEDs */
	DIGINET_CTL_SCRIBBLE,      /* a scribble address of the strip (0x00+n, then 0x20+n) */
	DIGINET_CTL_COUNTER,       /* the eight-digit counter */
	DIGINET_CTL_COUNTER_LEDS,  /* the counter-mode LEDs */
	DIGINET_CTL_SECTION_LAMP,
};

struct diginet_control {
	enum diginet_control_kind kind;
	int input;             /* 1: the desk sends it, the census waits; 0: the host writes, the census asks */
	unsigned strip;        /* 0-based, strip controls only */
	uint8_t button;        /* strip button or section button id */
	uint8_t zone;          /* section controls */
	uint8_t addr;          /* scribble address */
	uint8_t right;         /* the right meter column */
	const char *name;      /* "MUTE", "Play" ... */
	const char *group;     /* a section button's group, or "" */
	char slug[48];         /* "s01_mute", "sec_1c_10_play" ...: the name in the recorded bodies */
	char what[96];         /* what the operator is asked to do or to look at */
};

/* How many controls the census of a desk has. */
size_t diginet_census_count(const struct diginet_personality *p);
/* Control i (0..count-1) in walking order: strip by strip, its inputs then its outputs; the
 * jog, the counter; the section buttons zone by zone, a lamp right after its button.
 * DIGINET_E_RANGE past the end. */
int diginet_census_control(const struct diginet_personality *p, size_t i, struct diginet_control *out);
/* The body the desk sends when an input control is pressed, touched, moved or turned once
 * (a press, a touch, one MSB+LSB fader pair, one click): what the census expects to decode.
 * DIGINET_E_ARG for an output. */
int diginet_census_expect(const struct diginet_personality *p, const struct diginet_control *c,
			  struct diginet_cmd *out);
/* The write that exercises an output control (on) and the one that clears it (off): a lamp
 * lit, a ring and a meter full, the fader at three quarters, the scribble naming the strip, the
 * counter showing its digits. DIGINET_E_ARG for an input. */
int diginet_census_write(const struct diginet_personality *p, const struct diginet_control *c, int on,
			 struct diginet_cmd *out);
/* 1 when a decoded event is the input control acting (a press, not a release; a touch, not
 * a let-go; any fader position or turn), else 0. */
int diginet_census_matches(const struct diginet_control *c, const struct diginet_event *ev);
/* The control a slug names, or DIGINET_E_RANGE. */
int diginet_census_find(const struct diginet_personality *p, const char *slug, struct diginet_control *out);

#ifdef __cplusplus
}
#endif
#endif
