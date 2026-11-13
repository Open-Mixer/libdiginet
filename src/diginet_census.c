/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * The census of a desk: the controls in walking order, built from the personality (strips,
 * scribble width, counter address) and the section-button table. docs/census.md.
 */
#include <diginet/diginet_census.h>
#include <stdio.h>
#include <string.h>

/* The strip buttons, in the order they sit on a Control|24 strip from the top, with their
 * ids (docs/protocol.md, "Buttons and LEDs"). TOUCH (0x09) is the fader cap, not a button. */
static const struct { uint8_t id; const char *name, *slug; } strip_buttons[] = {
	{ DIGINET_BTN_REC_ARM, "REC", "rec" },         { DIGINET_BTN_PAN_SEND, "PAN/SEND", "pansend" },
	{ DIGINET_BTN_EQ, "EQ", "eq" },                { DIGINET_BTN_DYNAMICS, "DYN", "dyn" },
	{ DIGINET_BTN_ACTIVE, "ACTIVE", "active" },    { DIGINET_BTN_AUTO_MODE, "AUTO", "auto" },
	{ DIGINET_BTN_SELECT, "SELECT", "select" },    { DIGINET_BTN_SOLO, "SOLO", "solo" },
	{ DIGINET_BTN_MUTE, "MUTE", "mute" },          { DIGINET_BTN_INSERTS, "INSERTS", "inserts" },
	{ DIGINET_BTN_PEAK, "PEAK", "peak" },          { DIGINET_BTN_SOURCE, "SOURCE", "source" },
	{ DIGINET_BTN_ROLL_OFF, "ROLL-OFF", "rolloff" },
};
#define NSTRIP_BUTTONS (sizeof strip_buttons / sizeof strip_buttons[0])

/* Per strip: fader, touch, the buttons, the V-Pot (inputs); the fader, the lamps, the ring,
 * two meters, the LEDs, two scribble addresses (outputs). */
#define PER_STRIP_IN  (3 + NSTRIP_BUTTONS)
#define PER_STRIP_OUT (1 + NSTRIP_BUTTONS + 1 + 2 + 1 + 2)
#define PER_STRIP     (PER_STRIP_IN + PER_STRIP_OUT)
#define GLOBALS       3   /* jog, counter, counter LEDs */

static const struct diginet_section_button *sections(const struct diginet_personality *p, size_t *n)
{
	/* The ProControl's section buttons are not mapped yet: its census walks the strips. */
	if (p->desk != DIGINET_DESK_CONTROL24) {
		*n = 0;
		return NULL;
	}
	*n = diginet_c24_section_button_count;
	return diginet_c24_section_buttons;
}

static size_t section_steps(const struct diginet_personality *p)
{
	size_t n, steps = 0;
	const struct diginet_section_button *s = sections(p, &n);
	for (size_t i = 0; i < n; i++)
		steps += 1 + (s[i].lamp ? 1 : 0);
	return steps;
}

size_t diginet_census_count(const struct diginet_personality *p)
{
	if (!p)
		return 0;
	return p->strips * PER_STRIP + GLOBALS + section_steps(p);
}

static void slugify(char *out, size_t n, const char *name)
{
	/* a button whose name is a sign: the keypad's and the channel-bar scroll's */
	static const struct { const char *sign, *word; } signs[] = {
		{ "<", "left" }, { ">", "right" }, { "+", "plus" }, { "-", "minus" }, { "*", "star" },
		{ "/", "slash" }, { "=", "equals" }, { ".", "dot" },
	};
	for (size_t i = 0; i < sizeof signs / sizeof signs[0]; i++)
		if (!strcmp(name, signs[i].sign)) {
			snprintf(out, n, "%s", signs[i].word);
			return;
		}
	size_t o = 0;
	for (const char *s = name; *s && o + 1 < n; s++) {
		char c = *s;
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			out[o++] = c;
		else if (c >= 'A' && c <= 'Z')
			out[o++] = (char)(c - 'A' + 'a');
		else if (o && out[o - 1] != '_' && (c == ' ' || c == '-' || c == '_' || c == '/'))
			out[o++] = '_';
	}
	while (o && out[o - 1] == '_')
		o--;
	out[o] = '\0';
}

static void set(struct diginet_control *c, enum diginet_control_kind kind, const char *name, const char *slug,
		const char *what)
{
	c->kind = kind;
	c->input = kind <= DIGINET_CTL_SECTION_BUTTON;
	c->name = name;
	c->group = "";
	snprintf(c->slug, sizeof c->slug, "%s", slug);
	snprintf(c->what, sizeof c->what, "%s", what);
}

int diginet_census_control(const struct diginet_personality *p, size_t i, struct diginet_control *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	memset(out, 0, sizeof *out);
	char slug[48], what[96];
	if (i < (size_t)p->strips * PER_STRIP) {
		unsigned strip = (unsigned)(i / PER_STRIP), k = (unsigned)(i % PER_STRIP);
		out->strip = strip;
		unsigned n = strip + 1;
		if (k == 0) {
			snprintf(slug, sizeof slug, "s%02u_fader", n);
			snprintf(what, sizeof what, "move fader %u", n);
			set(out, DIGINET_CTL_FADER_IN, "fader", slug, what);
		} else if (k == 1) {
			snprintf(slug, sizeof slug, "s%02u_touch", n);
			snprintf(what, sizeof what, "touch fader %u's cap", n);
			set(out, DIGINET_CTL_TOUCH, "touch", slug, what);
			out->button = DIGINET_BTN_TOUCH;
		} else if (k < 2 + NSTRIP_BUTTONS) {
			unsigned b = k - 2;
			snprintf(slug, sizeof slug, "s%02u_%s", n, strip_buttons[b].slug);
			snprintf(what, sizeof what, "press strip %u %s", n, strip_buttons[b].name);
			set(out, DIGINET_CTL_STRIP_BUTTON, strip_buttons[b].name, slug, what);
			out->button = strip_buttons[b].id;
		} else if (k == 2 + NSTRIP_BUTTONS) {
			snprintf(slug, sizeof slug, "s%02u_vpot", n);
			snprintf(what, sizeof what, "turn V-Pot %u one click", n);
			set(out, DIGINET_CTL_VPOT, "V-Pot", slug, what);
		} else {
			k -= (unsigned)PER_STRIP_IN;
			if (k == 0) {
				snprintf(slug, sizeof slug, "s%02u_fader_out", n);
				snprintf(what, sizeof what, "fader %u went to three quarters of its travel", n);
				set(out, DIGINET_CTL_FADER_OUT, "fader", slug, what);
			} else if (k < 1 + NSTRIP_BUTTONS) {
				unsigned b = k - 1;
				snprintf(slug, sizeof slug, "s%02u_%s_lamp", n, strip_buttons[b].slug);
				snprintf(what, sizeof what, "strip %u %s is lit", n, strip_buttons[b].name);
				set(out, DIGINET_CTL_STRIP_LAMP, strip_buttons[b].name, slug, what);
				out->button = strip_buttons[b].id;
			} else if (k == 1 + NSTRIP_BUTTONS) {
				snprintf(slug, sizeof slug, "s%02u_ring", n);
				snprintf(what, sizeof what, "all 15 LEDs of V-Pot %u's ring are lit", n);
				set(out, DIGINET_CTL_RING, "ring", slug, what);
			} else if (k < 4 + NSTRIP_BUTTONS) {
				int right = k == 3 + NSTRIP_BUTTONS;
				snprintf(slug, sizeof slug, "s%02u_meter_%c", n, right ? 'r' : 'l');
				snprintf(what, sizeof what, "strip %u's %s meter is full", n, right ? "right" : "left");
				set(out, DIGINET_CTL_METER, right ? "meter R" : "meter L", slug, what);
				out->right = (uint8_t)right;
			} else if (k == 4 + NSTRIP_BUTTONS) {
				snprintf(slug, sizeof slug, "s%02u_leds", n);
				snprintf(what, sizeof what, "strip %u's automation LEDs are all lit", n);
				set(out, DIGINET_CTL_STRIP_LEDS, "strip LEDs", slug, what);
			} else {
				int second = k == 6 + NSTRIP_BUTTONS;
				out->addr = (uint8_t)((second ? 0x20 : 0x00) + strip);
				snprintf(slug, sizeof slug, "s%02u_scribble_%02x", n, out->addr);
				snprintf(what, sizeof what, "strip %u's scribble shows %c%02u (write at 0x%02x)", n,
					 second ? 'D' : 'C', n, out->addr);
				set(out, DIGINET_CTL_SCRIBBLE, "scribble", slug, what);
			}
		}
		return DIGINET_OK;
	}
	i -= (size_t)p->strips * PER_STRIP;
	if (i < GLOBALS) {
		if (i == 0) {
			set(out, DIGINET_CTL_JOG, "jog", "jog", "turn the jog wheel one click");
		} else if (i == 1) {
			set(out, DIGINET_CTL_COUNTER, "counter", "counter", "the counter shows 12345678");
		} else {
			set(out, DIGINET_CTL_COUNTER_LEDS, "counter LEDs", "counter_leds",
			    "the counter-mode LEDs are all lit");
		}
		return DIGINET_OK;
	}
	i -= GLOBALS;
	size_t n;
	const struct diginet_section_button *s = sections(p, &n);
	for (size_t j = 0; j < n; j++) {
		size_t steps = 1 + (s[j].lamp ? 1 : 0);
		if (i < steps) {
			char name[24];
			slugify(name, sizeof name, s[j].name);
			out->zone = s[j].zone;
			out->button = s[j].id;
			if (i == 0) {
				snprintf(slug, sizeof slug, "sec_%02x_%02x_%s", s[j].zone, s[j].id, name);
				snprintf(what, sizeof what, "press %s%s%s", s[j].name,
					 s[j].group[0] != '-' ? " in " : "", s[j].group[0] != '-' ? s[j].group : "");
				set(out, DIGINET_CTL_SECTION_BUTTON, s[j].name, slug, what);
			} else {
				snprintf(slug, sizeof slug, "sec_%02x_%02x_%s_lamp", s[j].zone, s[j].id, name);
				snprintf(what, sizeof what, "%s%s%s is lit", s[j].name,
					 s[j].group[0] != '-' ? " in " : "", s[j].group[0] != '-' ? s[j].group : "");
				set(out, DIGINET_CTL_SECTION_LAMP, s[j].name, slug, what);
			}
			out->group = s[j].group[0] != '-' ? s[j].group : "";
			return DIGINET_OK;
		}
		i -= steps;
	}
	return DIGINET_E_RANGE;
}

int diginet_census_expect(const struct diginet_personality *p, const struct diginet_control *c,
			  struct diginet_cmd *out)
{
	if (!p || !c || !out || !c->input)
		return DIGINET_E_ARG;
	switch (c->kind) {
	case DIGINET_CTL_FADER_IN:
		return diginet_fader_encode(p, c->strip, 512, out);
	case DIGINET_CTL_TOUCH:
		return diginet_touch_encode(p, c->strip, 1, out);
	case DIGINET_CTL_STRIP_BUTTON:
		return diginet_button_encode(c->button, c->strip, 1, out);
	case DIGINET_CTL_VPOT:
		return diginet_vpot_encode(p, c->strip, 1, out);
	case DIGINET_CTL_JOG:
		return diginet_jog_encode(1, out);
	case DIGINET_CTL_SECTION_BUTTON:
		return diginet_button_encode(c->button, c->zone, 1, out);
	default:
		return DIGINET_E_ARG;
	}
}

int diginet_census_write(const struct diginet_personality *p, const struct diginet_control *c, int on,
			 struct diginet_cmd *out)
{
	if (!p || !c || !out || c->input)
		return DIGINET_E_ARG;
	uint8_t text[DIGINET_SCRIBBLE_MAX], seg[DIGINET_COUNTER_DIGITS], dots = 0;
	char s[16];
	switch (c->kind) {
	case DIGINET_CTL_FADER_OUT:
		return diginet_fader_encode(p, c->strip, on ? 768 : 0, out);
	case DIGINET_CTL_STRIP_LAMP:
		return diginet_button_encode(c->button, c->strip, on, out);
	case DIGINET_CTL_RING:
		return diginet_ring_encode(p, c->strip, on ? 0x7fff : 0, out);
	case DIGINET_CTL_METER:
		return diginet_meter_encode(p, c->strip, c->right, on ? DIGINET_METER_SEGMENTS : 0, out);
	case DIGINET_CTL_STRIP_LEDS:
		return diginet_strip_leds_encode(p, c->strip, on ? 0x7f : 0, out);
	case DIGINET_CTL_SCRIBBLE:
		snprintf(s, sizeof s, "%c%02u", c->addr >= 0x20 ? 'D' : 'C', c->strip + 1);
		diginet_scribble_text(on ? s : "", text, p->scribble_chars);
		return diginet_scribble_encode(p, c->addr, text, out);
	case DIGINET_CTL_COUNTER:
		if (diginet_counter_text(on ? "12345678" : "", seg, &dots) != DIGINET_OK)
			return DIGINET_E_RANGE;
		return diginet_counter_encode(p, seg, dots, out);
	case DIGINET_CTL_COUNTER_LEDS:
		return diginet_counter_leds_encode(p, on ? 0x7f : 0, out);
	case DIGINET_CTL_SECTION_LAMP:
		return diginet_button_encode(c->button, c->zone, on, out);
	default:
		return DIGINET_E_ARG;
	}
}

int diginet_census_matches(const struct diginet_control *c, const struct diginet_event *ev)
{
	if (!c || !ev || !c->input)
		return 0;
	switch (c->kind) {
	case DIGINET_CTL_FADER_IN:
		return ev->kind == DIGINET_EV_FADER && ev->strip == c->strip;
	case DIGINET_CTL_TOUCH:
		return ev->kind == DIGINET_EV_TOUCH && ev->strip == c->strip && ev->on;
	case DIGINET_CTL_STRIP_BUTTON:
		return ev->kind == DIGINET_EV_STRIP_BUTTON && ev->strip == c->strip && ev->button == c->button && ev->on;
	case DIGINET_CTL_VPOT:
		return ev->kind == DIGINET_EV_VPOT && ev->strip == c->strip && ev->delta != 0;
	case DIGINET_CTL_JOG:
		return ev->kind == DIGINET_EV_JOG && ev->delta != 0;
	case DIGINET_CTL_SECTION_BUTTON:
		return ev->kind == DIGINET_EV_SECTION_BUTTON && ev->zone == c->zone && ev->button == c->button && ev->on;
	default:
		return 0;
	}
}

int diginet_census_find(const struct diginet_personality *p, const char *slug, struct diginet_control *out)
{
	if (!p || !slug || !out)
		return DIGINET_E_ARG;
	size_t n = diginet_census_count(p);
	for (size_t i = 0; i < n; i++)
		if (diginet_census_control(p, i, out) == DIGINET_OK && !strcmp(out->slug, slug))
			return DIGINET_OK;
	return DIGINET_E_RANGE;
}
