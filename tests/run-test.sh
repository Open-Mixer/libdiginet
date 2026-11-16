#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# Every test ends with a verdict. `make test` runs each one through this:
#
#   tests/run-test.sh ./test_x [args...]
#
#   0      PASS
#   77     SKIP: the test proved this environment cannot host it; its own output says
#          nothing was tested. Reported, and not counted as a failure, except in CI:
#          with DIGINET_TEST_SKIP_IS_FAIL=1 a SKIP is a failure (exit 1) for every test
#          whose name is not in DIGINET_TEST_SKIP_OK (default: test_packet test_anyif test_emu_child,
#          which need an unprivileged user+net namespace a container cannot make). A test that runs nothing in CI is red.
#   124    TIMEOUT after $DIGINET_TEST_TIMEOUT seconds (default 120): a hang is a failure.
#   other  FAIL, passed through (2 is a test's own NOT A RESULT).
set -u
t=${DIGINET_TEST_TIMEOUT:-120}
name=$1
timeout --kill-after=10 "$t" "$@"
rc=$?
case $rc in
	0)   echo "PASS: $name"; exit 0 ;;
	77)  if [ "${DIGINET_TEST_SKIP_IS_FAIL:-}" = 1 ]; then
	       for ok in ${DIGINET_TEST_SKIP_OK:-test_packet test_anyif test_emu_child}; do
	         [ "$(basename "$name")" = "$ok" ] && { echo "SKIP: $name (exit 77, allowed to skip)"; exit 0; }
	       done
	       echo "FAIL: $name skipped (exit 77) and ran nothing, a failure under DIGINET_TEST_SKIP_IS_FAIL=1" >&2
	       exit 1
	     fi
	     echo "SKIP: $name (exit 77, this environment cannot host it)"; exit 0 ;;
	124|137)
	     echo "FAIL: $name timed out after ${t}s" >&2; exit 124 ;;
	*)   echo "FAIL: $name exited $rc" >&2; exit "$rc" ;;
esac
