#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# tests/test_census.c derives every count (controls, inputs, writes, the STEP N/total and
# SUMMARY lines) from the inventory. Sabotage: add one lamped section button to a scratch copy of the
# table; the census test must still pass without an edit. A count typed into the test fails here.
set -u
top=$(cd "$(dirname "$0")/.." && pwd)
d=$(mktemp -d) || exit 2
trap 'rm -rf "$d"' EXIT
for p in src include tools tests testsupport transport Makefile VERSION; do cp -r "$top/$p" "$d/"; done
rm -f "$d"/src/*.o "$d"/src/*.d "$d"/*.a
cd "$d" || exit 2
python3 - <<'PY' || exit 2
p = "src/diginet_census_c24.c"
s = open(p).read()
k = "const struct diginet_section_button diginet_c24_section_buttons[] = {\n"
assert k in s
open(p, "w").write(s.replace(k, k + '\t{ 0x1d, 0x3f, 1, "sabotage", "Sabotage" },\n', 1))
PY
make -s tests/test_census tools/diginet-census >build.log 2>&1 || { cat build.log; echo "FAIL: the sabotaged tree does not build"; exit 1; }
if tests/test_census tools/diginet-census >run.log 2>&1; then
	echo "ok   one control added to the inventory: tests/test_census passes unedited"
else
	tail -5 run.log
	echo "FAIL: adding one control to the inventory needs an edit of tests/test_census.c"
	exit 1
fi
