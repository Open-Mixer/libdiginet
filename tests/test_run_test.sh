#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# tests/run-test.sh turns a test's exit 77 ("nothing tested") into a reported SKIP, and in CI that
# must be red: DIGINET_TEST_SKIP_IS_FAIL=1 makes a SKIP a failure for every test not named in
# DIGINET_TEST_SKIP_OK (test_packet, test_anyif and test_emu_child by default: a container cannot make an
# unprivileged user+net namespace). The workflows set the switch (checked at the end), so a test that runs nothing in
# CI is red.
set -u
top=$(cd "$(dirname "$0")/.." && pwd)
rt="$top/tests/run-test.sh"
d=$(mktemp -d) || exit 2
trap 'rm -rf "$d"' EXIT
printf '#!/bin/sh\nexit 77\n' > "$d/test_nothing"
printf '#!/bin/sh\nexit 77\n' > "$d/test_packet"
printf '#!/bin/sh\nexit 0\n' > "$d/test_ok"
chmod +x "$d"/test_*
bad=0
want() { # <expected rc> <description> <env...> -- ; runs run-test on $TEST
	exp=$1; shift; desc=$1; shift
	env "$@" "$rt" "$TEST" >/dev/null 2>&1; rc=$?
	if [ "$rc" = "$exp" ]; then echo "ok   $desc"; else echo "FAIL $desc: rc $rc, wanted $exp"; bad=1; fi
}
TEST=$d/test_nothing
want 0 "a SKIP is not a failure outside CI" DIGINET_TEST_SKIP_IS_FAIL=
want 1 "a SKIP is a failure when DIGINET_TEST_SKIP_IS_FAIL=1" DIGINET_TEST_SKIP_IS_FAIL=1
TEST=$d/test_packet
want 0 "test_packet may skip (user namespaces) in CI" DIGINET_TEST_SKIP_IS_FAIL=1
TEST=$d/test_ok
want 0 "a pass stays a pass in CI" DIGINET_TEST_SKIP_IS_FAIL=1
# every workflow that runs `make test` sets the switch, or a cell could run nothing and pass
for w in "$top"/.github/workflows/*.yml; do
	grep -v '^ *#' "$w" | grep -q 'make test' || continue
	if grep -q 'DIGINET_TEST_SKIP_IS_FAIL' "$w"; then echo "ok   $(basename "$w") sets DIGINET_TEST_SKIP_IS_FAIL"
	else echo "FAIL $(basename "$w") runs make test without DIGINET_TEST_SKIP_IS_FAIL=1"; bad=1; fi
done
exit $bad
