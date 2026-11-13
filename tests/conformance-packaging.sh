#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The version and the sonames have one definition each, and every copy must agree with it:
#   ARM 1  VERSION is the version: diginet.h's DIGINET_VERSION_STRING, the spec's Version and the top
#          entry of debian/changelog say the same;
#   ARM 2  DIGINET_ABI of diginet.h is the spec's %global abi and the N of the libdiginetN package;
#   ARM 3  DIGINET_TRANSPORT_ABI is the spec's %global tabi and the N of libdiginet-transportN, and
#          debian/libdiginet-dev depends on both packages by those names;
#   ARM 4  the two binaries that carry cap_net_raw (diginet-probe, diginet-packet-helper) are owned
#          by root and the group diginet, mode 0750, in both packagings: the spec's %files gives each
#          %attr(0750,root,diginet) beside its %caps and ships the sysusers file that makes the group;
#          debian's postinst makes the group, then sets owner and mode, then the capability (a chown
#          drops file capabilities, so setcap comes last).
# It reads files, not git, so it also runs from a release tarball. A planted good tree and a planted
# A planted copy with the spec at another version runs first and must be refused, so the check
# cannot pass vacuously.
#
# Exit 0 conforms, 1 an arm found an offence, 2 the planted copy was not refused (NOT A RESULT).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)

check() {
	t=$1 bad=0
	ver=$(cat "$t/VERSION" 2>/dev/null)
	hdr=$t/include/diginet/diginet.h spec=$t/packaging/libdiginet.spec
	hver=$(sed -n 's/^#define DIGINET_VERSION_STRING "\(.*\)"/\1/p' "$hdr")
	abi=$(sed -n 's/^#define DIGINET_ABI  *\([0-9][0-9]*\)$/\1/p' "$hdr")
	tabi=$(sed -n 's/^#define DIGINET_TRANSPORT_ABI  *\([0-9][0-9]*\)$/\1/p' "$hdr")
	if [ -z "$ver" ] || [ -z "$abi" ] || [ -z "$tabi" ]; then
		echo "  could not read VERSION, DIGINET_ABI or DIGINET_TRANSPORT_ABI"
		return 1
	fi
	spec_ver=$(sed -n 's/^Version: *//p' "$spec")
	spec_abi=$(sed -n 's/^%global abi  *//p' "$spec")
	spec_tabi=$(sed -n 's/^%global tabi  *//p' "$spec")
	deb_ver=$(sed -n '1s/^[^ ]* (\([^)]*\)).*/\1/p' "$t/debian/changelog")
	deb_ver=${deb_ver%%~*}   # an untagged build stamps ~git<sha> on the top entry
	deb_abi=$(sed -n 's/^Package: libdiginet\([0-9][0-9]*\)$/\1/p' "$t/debian/control")
	deb_tabi=$(sed -n 's/^Package: libdiginet-transport\([0-9][0-9]*\)$/\1/p' "$t/debian/control")

	[ "$hver" = "$ver" ] || { echo "  ARM 1: diginet.h says $hver, VERSION says $ver"; bad=1; }
	[ "$spec_ver" = "$ver" ] || { echo "  ARM 1: the spec says Version $spec_ver, VERSION says $ver"; bad=1; }
	[ "$deb_ver" = "$ver" ] || { echo "  ARM 1: debian/changelog says $deb_ver, VERSION says $ver"; bad=1; }
	[ "$spec_abi" = "$abi" ] || { echo "  ARM 2: the spec's abi is $spec_abi, DIGINET_ABI is $abi"; bad=1; }
	[ "$deb_abi" = "$abi" ] || { echo "  ARM 2: debian/control builds libdiginet$deb_abi, DIGINET_ABI is $abi"; bad=1; }
	[ "$spec_tabi" = "$tabi" ] || { echo "  ARM 3: the spec's tabi is $spec_tabi, DIGINET_TRANSPORT_ABI is $tabi"; bad=1; }
	[ "$deb_tabi" = "$tabi" ] || { echo "  ARM 3: debian/control builds libdiginet-transport$deb_tabi, DIGINET_TRANSPORT_ABI is $tabi"; bad=1; }
	for p in "libdiginet$abi" "libdiginet-transport$tabi"; do
		[ -f "$t/debian/$p.install" ] || { echo "  ARM 3: debian/$p.install is missing"; bad=1; }
		grep -q "^Depends:.* $p (= \${binary:Version})" "$t/debian/control" ||
			{ echo "  ARM 3: libdiginet-dev does not depend on $p"; bad=1; }
	done
	sysusers=$t/packaging/diginet-tools.sysusers postinst=$t/debian/diginet-tools.postinst
	grep -q '^g diginet -' "$sysusers" 2>/dev/null ||
		{ echo "  ARM 4: packaging/diginet-tools.sysusers does not declare the group diginet"; bad=1; }
	grep -q '^%{_sysusersdir}/diginet-tools\.conf$' "$spec" ||
		{ echo "  ARM 4: the spec does not ship the sysusers file"; bad=1; }
	sed -n '/^Package: diginet-tools$/,/^$/p' "$t/debian/control" | grep -q '^Depends:.*adduser' ||
		{ echo "  ARM 4: debian/control: diginet-tools does not depend on adduser"; bad=1; }
	grep -q 'addgroup --system diginet' "$postinst" 2>/dev/null ||
		{ echo "  ARM 4: debian postinst does not make the group diginet"; bad=1; }
	for b in diginet-probe diginet-census diginet-packet-helper; do
		grep -q "^%attr(0750,root,diginet) %caps(cap_net_raw=ep) %{_bindir}/$b\$" "$spec" ||
			{ echo "  ARM 4: the spec does not install $b as %attr(0750,root,diginet) with cap_net_raw"; bad=1; }
	done
	own=$(grep -n 'chown root:diginet "\$b"' "$postinst" 2>/dev/null | cut -d: -f1 | head -n 1)
	mode=$(grep -n 'chmod 0750 "\$b"' "$postinst" 2>/dev/null | cut -d: -f1 | head -n 1)
	cap=$(grep -n 'setcap cap_net_raw=ep "\$b"' "$postinst" 2>/dev/null | cut -d: -f1 | head -n 1)
	if [ -z "$own" ] || [ -z "$mode" ] || [ -z "$cap" ]; then
		echo "  ARM 4: debian postinst does not chown root:diginet, chmod 0750 and setcap each binary"; bad=1
	elif [ "$cap" -lt "$own" ] || [ "$cap" -lt "$mode" ]; then
		echo "  ARM 4: debian postinst sets the capability before owner and mode; the chown drops it"; bad=1
	fi
	grep -q 'for b in /usr/bin/diginet-probe /usr/bin/diginet-census /usr/bin/diginet-packet-helper' "$postinst" 2>/dev/null ||
		{ echo "  ARM 4: debian postinst does not cover the three binaries"; bad=1; }
	return $bad
}

plant() { # dir [sed-expression file]
	mkdir -p "$1/include/diginet" "$1/packaging" "$1/debian"
	cp "$ROOT/VERSION" "$1/"
	cp "$ROOT/include/diginet/diginet.h" "$1/include/diginet/"
	cp "$ROOT/packaging/libdiginet.spec" "$1/packaging/"
	cp "$ROOT/debian/changelog" "$ROOT/debian/control" "$ROOT"/debian/*.install "$ROOT"/debian/*.postinst "$1/debian/"
	cp "$ROOT/packaging/diginet-tools.sysusers" "$1/packaging/" 2>/dev/null || :
	[ $# -lt 3 ] || sed -i "$2" "$1/$3"
}

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
plant "$tmp/bad" 's/^Version: .*/Version: 9.9.9/' packaging/libdiginet.spec
if check "$tmp/bad" >/dev/null; then
	echo "NOT A RESULT: a tree with the spec at 9.9.9 was not refused"
	exit 2
fi
# ARM 4's own planted copies: a spec that drops the helper's mode, and a postinst that sets the
# capability before the chown that would drop it.
plant "$tmp/mode" 's/^%attr(0750,root,diginet) \(%caps(cap_net_raw=ep) %{_bindir}\/diginet-packet-helper\)$/\1/' packaging/libdiginet.spec
if check "$tmp/mode" >/dev/null; then
	echo "NOT A RESULT: a spec that installs diginet-packet-helper without %attr(0750,root,diginet) was not refused"
	exit 2
fi
plant "$tmp/order" '/chown root:diginet/d' debian/diginet-tools.postinst
printf '\t\tchown root:diginet "$b"\n' >> "$tmp/order/debian/diginet-tools.postinst"
if check "$tmp/order" >/dev/null; then
	echo "NOT A RESULT: a postinst that chowns after setcap was not refused"
	exit 2
fi
check "$ROOT" || exit 1
echo "conformance-packaging: VERSION $(cat "$ROOT/VERSION"), sonames $(sed -n 's/^#define DIGINET_ABI  *//p' "$ROOT/include/diginet/diginet.h")/$(sed -n 's/^#define DIGINET_TRANSPORT_ABI  *//p' "$ROOT/include/diginet/diginet.h") agree everywhere; the cap_net_raw binaries are root:diginet 0750"
