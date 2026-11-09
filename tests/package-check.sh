#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The packages, installed in a clean Fedora or Debian container that holds nothing else:
#
#   tests/package-check.sh <directory holding the .rpm or .deb files>
#
# installs libdiginet, its development package and diginet-tools with what they pull in; builds a
# consumer outside the tree against the development package through pkg-config alone, and runs it
# against the installed shared libraries; checks diginet-probe runs and that it and
# diginet-packet-helper carry cap_net_raw, owned by root and the group diginet, mode 0750.
set -eu
dir=$(cd "$1" && pwd)
if command -v dnf >/dev/null 2>&1; then
	dnf install -y -q --setopt=install_weak_deps=False gcc pkgconf-pkg-config libcap \
		$(ls "$dir"/libdiginet-[0-9]*.rpm "$dir"/libdiginet-devel-[0-9]*.rpm "$dir"/diginet-tools-[0-9]*.rpm | grep -v -e debuginfo -e debugsource -e '\.src\.rpm')
	rpm -q libdiginet libdiginet-devel diginet-tools
else
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends gcc libc6-dev pkgconf libcap2-bin \
		"$dir"/libdiginet0_*.deb "$dir"/libdiginet-transport0_*.deb "$dir"/libdiginet-dev_*.deb "$dir"/diginet-tools_*.deb
	dpkg -l libdiginet0 libdiginet-transport0 libdiginet-dev diginet-tools | tail -n 4
fi

tmp=$(mktemp -d)
cat > "$tmp/consumer.c" <<'C'
#include <stdio.h>
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>
int main(void)
{
	struct diginet_session_config c;
	struct diginet_cmd cmd;
	diginet_session_config_default(&c);
	if (diginet_fader_encode(diginet_personality_from_name("CNTRL|24"), 0, 512, &cmd) || cmd.len != 5)
		return 1;
	printf("consumer: libdiginet %s, fader 1 at 512 = %02x %02x %02x %02x %02x, keepalive %u ms\n",
	       DIGINET_VERSION_STRING, cmd.bytes[0], cmd.bytes[1], cmd.bytes[2], cmd.bytes[3], cmd.bytes[4],
	       c.keepalive_ms);
	return c.keepalive_ms == 10000 && cmd.bytes[2] == 0x40 ? 0 : 1;
}
C
cc "$tmp/consumer.c" $(pkg-config --cflags --libs libdiginet-transport) -o "$tmp/consumer"
"$tmp/consumer"
# linked against the shared objects, not a copy
ldd "$tmp/consumer" | grep -q 'libdiginet-transport\.so\.0 => /' || { echo "FAIL: not linked to libdiginet-transport.so.0"; exit 1; }
ldd "$tmp/consumer" | grep -q 'libdiginet\.so\.0 => /' || { echo "FAIL: not linked to libdiginet.so.0"; exit 1; }
pkg-config --modversion libdiginet
test -f /usr/share/diginet/diginet.ksy

# R14 (docs/protocol.md): install drops file capabilities, so each binary that needs one is asked.
for b in /usr/bin/diginet-probe /usr/bin/diginet-packet-helper; do
	caps=$(getcap "$b")
	echo "$caps"
	echo "$caps" | grep -q 'cap_net_raw[=+]ep' || { echo "FAIL: $b has no cap_net_raw"; exit 1; }
	# only root and the group diginet may run it (docs/threat-model.md)
	own=$(stat -c '%a %U %G' "$b")
	[ "$own" = "750 root diginet" ] || { echo "FAIL: $b is $own, not 750 root diginet"; exit 1; }
done
# The helper loads no shared library of ours while it holds the capability (read from a copy,
# for the reason below).
cp /usr/bin/diginet-packet-helper "$tmp/helper"
if ldd "$tmp/helper" | grep -q 'libdiginet'; then
	echo "FAIL: diginet-packet-helper is linked to a shared libdiginet"; exit 1
fi
# A container whose bounding set lacks CAP_NET_RAW refuses to exec a binary that carries it (EPERM),
# so the binary itself is run from a copy, which carries no capability.
cp /usr/bin/diginet-probe "$tmp/probe"
"$tmp/probe" --help | grep -q 'cap_net_raw'
ldd "$tmp/probe" | grep -q 'libdiginet-transport\.so\.0 => /' || { echo "FAIL: diginet-probe is not linked to the shared library"; exit 1; }
echo "package-check: ok"
