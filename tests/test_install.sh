#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# `make install` into a scratch root, then build and run a consumer against that root
# through pkg-config alone: every installed header, archive and .pc file has to be there.
set -u
command -v pkg-config >/dev/null 2>&1 || { echo "no pkg-config: nothing tested"; exit 77; }
top=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
make -s -C "$top" install PREFIX=/usr DESTDIR="$tmp/root" >/dev/null || { echo "FAIL: make install"; exit 1; }
cat > "$tmp/consumer.c" <<'C'
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_session.h>
#include <diginet/transport/diginet_mux.h>
int main(void)
{
	struct diginet_session_config c;
	struct diginet_mux_config mc;
	struct diginet_cmd cmd;
	diginet_session_config_default(&c);
	diginet_mux_config_default(&mc);
	if (mc.gone_ms != 30000)
		return 1;
	if (diginet_fader_encode(diginet_personality_of(DIGINET_DESK_CONTROL24), 0, 512, &cmd) || cmd.len != 5)
		return 1;
	return c.keepalive_ms == 10000 && diginet_sum16(cmd.bytes, cmd.len) == 0x110 ? 0 : 1;
}
C
PKG_CONFIG_SYSROOT_DIR="$tmp/root" PKG_CONFIG_LIBDIR="$tmp/root/usr/lib/pkgconfig" \
	sh -c "${CC:-cc} '$tmp/consumer.c' \$(pkg-config --cflags --libs libdiginet-transport) -o '$tmp/consumer'" ||
	{ echo "FAIL: a consumer does not build against the installed tree"; exit 1; }
"$tmp/consumer" || { echo "FAIL: the consumer gave the wrong answer"; exit 1; }

[ -x "$tmp/root/usr/bin/diginet-packet-helper" ] && [ -f "$tmp/root/usr/share/man/man1/diginet-packet-helper.1" ] ||
	{ echo "FAIL: diginet-packet-helper or its manual page is not installed"; exit 1; }
[ -x "$tmp/root/usr/bin/diginet-census" ] && [ -f "$tmp/root/usr/share/man/man1/diginet-census.1" ] &&
	[ -f "$tmp/root/usr/include/diginet/diginet_census.h" ] ||
	{ echo "FAIL: diginet-census, its manual page or diginet_census.h is not installed"; exit 1; }

# The desk emulator is installed test support (libdiginet-emu): a consumer builds against it
# through pkg-config alone, same as the protocol and transport above, and gets a real emulator
# back, not a stub.
cat > "$tmp/emu_consumer.c" <<'C'
#include <string.h>
#include <diginet/diginet.h>
#include <diginet/testsupport/desk_emu.h>
int main(void)
{
	static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	struct desk_emu e;
	uint8_t buf[DIGINET_MAX_FRAME_LEN];
	emu_init(&e, mac, "Control|24", "1.0");
	emu_announce(&e, 0);
	size_t n = emu_pop(&e, buf, sizeof buf);
	if (n == 0)
		return 1;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	if (memcmp(buf, bcast, 6) != 0 || memcmp(buf + 6, mac, 6) != 0)
		return 1;
	return buf[12] == 0x88 && buf[13] == 0x5f ? 0 : 1;
}
C
PKG_CONFIG_SYSROOT_DIR="$tmp/root" PKG_CONFIG_LIBDIR="$tmp/root/usr/lib/pkgconfig" \
	sh -c "${CC:-cc} '$tmp/emu_consumer.c' \$(pkg-config --cflags --libs libdiginet-emu) -o '$tmp/emu_consumer'" ||
	{ echo "FAIL: a consumer does not build against the installed libdiginet-emu"; exit 1; }
"$tmp/emu_consumer" || { echo "FAIL: the installed desk emulator gave the wrong answer"; exit 1; }

# A second install to another prefix names that prefix: nothing from the first one is reused.
make -s -C "$top" install PREFIX=/opt/elsewhere DESTDIR="$tmp/other" >/dev/null || { echo "FAIL: second make install"; exit 1; }
for pc in libdiginet libdiginet-transport libdiginet-emu; do
	grep -qx 'includedir=/opt/elsewhere/include' "$tmp/other/opt/elsewhere/lib/pkgconfig/$pc.pc" ||
		{ echo "FAIL: $pc.pc of the second install names another prefix"; exit 1; }
done
# The packages install with install-shared: their development package carries the emulator too.
make -s -C "$top" install-shared PREFIX=/usr DESTDIR="$tmp/pkg" >/dev/null || { echo "FAIL: make install-shared"; exit 1; }
for f in usr/lib/libdiginet-emu.a usr/lib/pkgconfig/libdiginet-emu.pc usr/include/diginet/testsupport/desk_emu.h \
	usr/include/diginet/testsupport/emu_pump.h usr/include/diginet/testsupport/netns.h \
	usr/include/diginet/testsupport/emu_child.h; do
	[ -f "$tmp/pkg/$f" ] || { echo "FAIL: install-shared does not install $f"; exit 1; }
done
echo "test_install: ok"
