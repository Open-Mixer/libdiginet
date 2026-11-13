/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet: the DigiNet frame. The Ethernet II envelope (EtherType 0x885F), the 16-byte
 * header, the announce body and the MIDI-shaped command stream of a data frame. This is
 * the C reading of protocol/diginet.ksy; docs/protocol.md names the source of every field.
 *
 * Nothing here opens a socket, reads a clock or allocates. Parsing points into the caller's
 * buffer; building writes into the caller's buffer.
 */
#ifndef DIGINET_H
#define DIGINET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIGINET_VERSION_MAJOR  0
#define DIGINET_VERSION_MINOR  1
#define DIGINET_VERSION_PATCH  8
#define DIGINET_VERSION_STRING "0.1.10"
/* The sonames' majors: libdiginet.so.DIGINET_ABI and libdiginet-transport.so.DIGINET_TRANSPORT_ABI.
 * packaging/libdiginet.spec and debian/ carry copies; tests/conformance-packaging.sh holds them
 * to these, and the version to the VERSION file. */
#define DIGINET_ABI            0
#define DIGINET_TRANSPORT_ABI  0

#define DIGINET_ETHERTYPE      0x885F
#define DIGINET_MAC_LEN        6
#define DIGINET_ETH_HDR_LEN    14
#define DIGINET_HDR_LEN        16                      /* the DigiNet header */
#define DIGINET_BODY_OFFSET    (DIGINET_ETH_HDR_LEN + DIGINET_HDR_LEN)
#define DIGINET_MIN_FRAME_LEN  60                      /* Ethernet minimum, FCS excluded */
#define DIGINET_MAX_FRAME_LEN  1514
#define DIGINET_MAX_BODY_LEN   (DIGINET_MAX_FRAME_LEN - DIGINET_BODY_OFFSET)
#define DIGINET_ANNOUNCE_BODY_LEN 34                   /* numbytes 50 */

/* The Digidesign OUI a desk sends from. */
#define DIGINET_OUI_0 0x00
#define DIGINET_OUI_1 0xa0
#define DIGINET_OUI_2 0x7e

/* Header byte 28 (`c24cmd`). */
enum diginet_command {
	DIGINET_CMD_DATA             = 0x00,
	DIGINET_CMD_ACK              = 0xa0,
	DIGINET_CMD_ANNOUNCE         = 0xe0, /* idle, not in a session */
	DIGINET_CMD_ANNOUNCE_SESSION = 0xe1, /* in a session; names the host */
	DIGINET_CMD_WAKE             = 0xe2, /* host asks for a session */
	DIGINET_CMD_DISCONNECT       = 0xe3,
};

/* Return codes: 0 is success, every failure is a negative code. Classify by code,
 * diginet_strerror() is for logs only. */
enum diginet_status {
	DIGINET_OK           = 0,
	DIGINET_E_ARG        = -1,  /* a NULL pointer or an impossible argument */
	DIGINET_E_SHORT      = -2,  /* fewer bytes than the header needs */
	DIGINET_E_ETHERTYPE  = -3,  /* not 0x885F */
	DIGINET_E_LENGTH     = -4,  /* numbytes < 16, or past the end of the buffer */
	DIGINET_E_SPACE      = -5,  /* the output buffer is too small */
	DIGINET_E_TRUNCATED  = -6,  /* a message runs past the end of the body */
	DIGINET_E_NO_STATUS  = -7,  /* a data byte with no running status in force */
	DIGINET_E_STATUS     = -8,  /* a status byte the grammar does not carry */
	DIGINET_E_NOT_ANNOUNCE = -9,
	DIGINET_E_REFUSED    = -10, /* a message the library will not encode */
	DIGINET_E_RANGE      = -11, /* a value outside what the wire can carry */
	DIGINET_E_NOT_MINE   = -12, /* a well-formed message of another kind */
};

const char *diginet_strerror(int code);

/* How the header sum is filled when building a frame. */
enum diginet_sum_mode {
	DIGINET_SUM_BODY = 0, /* the 16-bit additive sum of the body, as the desk sends */
	DIGINET_SUM_ZERO = 1, /* zero, as ReaControl24 and C24-Engine send */
};

struct diginet_header {
	uint16_t numbytes;     /* 16 + body length */
	uint16_t sum;          /* body sum as received */
	uint32_t send_counter;
	uint32_t ack_counter;
	uint16_t retry;
	uint8_t  cmd;          /* enum diginet_command */
	uint8_t  num_commands;
};

struct diginet_frame {
	uint8_t  dst[DIGINET_MAC_LEN];
	uint8_t  src[DIGINET_MAC_LEN];
	uint16_t ethertype;
	struct diginet_header h;
	const uint8_t *body;   /* points into the parsed buffer */
	size_t   body_len;     /* h.numbytes - 16 */
	size_t   pad_len;      /* bytes after the body */
	uint16_t body_sum;     /* the sum computed over the body */
	uint8_t  sum_matches;  /* h.sum == body_sum */
};

/* 16-bit additive sum of n bytes. */
uint16_t diginet_sum16(const uint8_t *p, size_t n);

/* Parse one whole Ethernet frame. A sum that does not match is not an error: hosts send
 * zero, so the caller decides (f->sum_matches). Returns DIGINET_OK or a negative code. */
int diginet_frame_parse(const uint8_t *buf, size_t len, struct diginet_frame *f);

/* Build a frame into buf: Ethernet header, header `h` (its numbytes and sum are ignored and
 * computed here), body, zero padding to 60 bytes. Returns the frame length, or a negative
 * code: DIGINET_E_SPACE when cap is too small, DIGINET_E_REFUSED when the body holds an
 * F0 13 xx 70 message (see diginet_codec.h). */
int diginet_frame_build(uint8_t *buf, size_t cap,
			const uint8_t dst[DIGINET_MAC_LEN], const uint8_t src[DIGINET_MAC_LEN],
			const struct diginet_header *h, const uint8_t *body, size_t body_len,
			enum diginet_sum_mode mode);

/* 1 when f is a keepalive: a data frame whose body is the single byte 00. */
int diginet_frame_is_keepalive(const struct diginet_frame *f);

/* 1 when mac carries the Digidesign OUI. */
int diginet_mac_is_digidesign(const uint8_t mac[DIGINET_MAC_LEN]);

/* The announce body (e0 or e1). The two strings are copied and NUL-terminated. */
struct diginet_announce {
	char version[10];
	char name[10];
	const uint8_t *unknown; /* the first 15 body bytes */
	size_t unknown_len;
};

int diginet_announce_parse(const struct diginet_frame *f, struct diginet_announce *a);

/* ---- the command stream of a data frame ---------------------------------------------- */

/* One message, with running status expanded: `status` is always the effective status. */
struct diginet_msg {
	uint8_t  status;       /* 0x80..0xEF channel status, or 0xF0 */
	uint8_t  running;      /* 1 when the status byte was implied */
	uint8_t  d1, d2;       /* channel data bytes (d2 is 0 for C0/D0) */
	const uint8_t *sysex;  /* for F0: the bytes after F0, before F7 */
	size_t   sysex_len;
	size_t   offset;       /* where the message starts in the body */
	size_t   len;          /* bytes it took in the body */
};

struct diginet_cursor {
	const uint8_t *body;
	size_t len;
	size_t pos;
	uint8_t status;        /* running status in force, 0 for none */
};

void diginet_cursor_init(struct diginet_cursor *c, const uint8_t *body, size_t len);

/* The next message. Returns 1 with *m filled, 0 at the end of the body, or a negative code.
 * After DIGINET_E_NO_STATUS or DIGINET_E_STATUS the cursor has stepped past the offending
 * byte, so a caller may log and go on; after DIGINET_E_TRUNCATED it is at the end. */
int diginet_msg_next(struct diginet_cursor *c, struct diginet_msg *m);

#ifdef __cplusplus
}
#endif

#endif
