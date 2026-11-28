#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# make fuzz-records: EVERY CHECK NAMES THE BUG IT CATCHES, AND CATCHES IT. Each abort() of
# fuzz/ carries in its comment one or more records, a one-line change of src/ or include/ and
# the seed it shows on
#
#   mutant: <path>:<line> `<old>` -> `<new>`
#   input: <seed of the harness's corpus>
#
# or one line `not a property: <reason>` for a stop after an allocation of the harness's own
# fails (fuzz/checks.awk reads them as OSS Verify's tools/check does). A check with neither, or
# with lines not of that form, turns this red before anything is built: the ratchet.
#
# Each record is then proved alone. The harness, plain and native, no sanitizer, driven by
# fuzz/standalone.c and linked against the library compiled the same way, exits 0 on the seed
# as the tree is; with the change made (`<old>` must occur once on that line) and the library
# and the harness built again it exits 134 on the seed, and the abort() it reached is the
# record's own, which each abort() of the harness names on stderr in this build. So is each
# patch of fuzz/sabotage/, applied alone: the seed its header names aborts at the check it
# names. The source is restored before each run and on every exit path. The count of records
# and patches met is the proof.
#
# Usage: FUZZ_BUILD=build/fuzz FUZZ_CC=clang records.sh [<harness>...]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
B=${FUZZ_BUILD:-build/fuzz}/records
CC=${FUZZ_CC:-clang}
CFLAGS="-O0 -g -std=c11 -D_DEFAULT_SOURCE -w"
HARNESSES=${*:-frame decode codec transport mux}
LIB="src/diginet_frame.c src/diginet_msg.c src/diginet_codec.c src/diginet_decode.c transport/src/diginet_session.c transport/src/diginet_mux.c"
SEP=$(printf '\037')
mkdir -p "$B/base"
# an aborting run leaves no core in the tree
ulimit -c 0

# each abort() of a harness says which it is, then exits 134 as abort() would; by _exit, not
# SIGABRT, so no core goes to the core_pattern helper (a pipe ignores ulimit -c), whose wait
# under load outlasted the timeout and read a met abort as 124
cat >"$B/record-abort.h" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static inline void fuzz_record_abort(const char *file, int line)
{
	fprintf(stderr, "fuzz-records: abort at %s:%d\n", file, line);
	fflush(stderr);
	_exit(134);
}
#define abort() fuzz_record_abort(__FILE__, __LINE__)
EOF

# the library into <dir>, then fuzz_<harness> against it
build() {
	for s in $LIB; do
		$CC $CFLAGS -Iinclude -c -o "$2/lib_$(basename "$s" .c).o" "$s" || return 1
	done
	$CC $CFLAGS -Iinclude -Ifuzz -include "$B/record-abort.h" -o "$2/fuzz_$1" "fuzz/fuzz_$1.c" \
		fuzz/standalone.c "$2"/lib_*.o
}

saved=
applied=
restore() {
	[ -n "$saved" ] && cp "$B/orig" "$saved"
	[ -n "$applied" ] && git apply -R "$applied"
	saved=
	applied=
}
trap 'restore' EXIT
trap 'restore; exit 130' INT TERM

if ! git diff --quiet -- src include transport/src; then
	echo "fuzz-records: src/, include/ or transport/src/ has uncommitted changes; refusing to change them" >&2
	exit 2
fi

# the ratchet: every abort() of fuzz/ has records or is not a property (a run of some harnesses
# reads every source of fuzz/ but the other harnesses')
sources=$(for f in fuzz/*.c fuzz/*.h; do
	case $f in
	fuzz/fuzz_*.c) h=${f#fuzz/fuzz_}; case " $HARNESSES " in *" ${h%.c} "*) echo "$f" ;; esac ;;
	*) echo "$f" ;;
	esac
done)
bad=$(for f in $sources; do awk '{ print NR "|0|" $0 }' "$f" | awk -v file="$f" -f fuzz/checks.awk; done |
	awk -F: '$5 == "NONE" || $5 == "BAD" { print "  " $1 ":" $3 " (" $5 ")" }')
if [ -n "$bad" ]; then
	echo "$bad"
	echo "make fuzz-records: RED -- checks with no record and no 'not a property' line, or records not of the form"
	exit 1
fi
checks=$(for f in $sources; do awk '{ print NR "|0|" $0 }' "$f" | awk -v file="$f" -f fuzz/checks.awk; done |
	awk -F: '$5 ~ /^records=/ { n++ } END { print n + 0 }')

for h in $HARNESSES; do
	build "$h" "$B/base" >"$B/base/$h.log" 2>&1 ||
		{ cat "$B/base/$h.log"; echo "records.sh: fuzz_$h does not build"; exit 1; }
done

n=0
red=0

# the harness as the tree is passes on the seed: else nothing a change makes it do shows the
# change
passes() {
	if [ -z "$2" ] || [ ! -f "fuzz/corpus/$2/$3" ]; then
		echo "RED  $1: no seed $3 in fuzz/corpus/$2/"
	elif ! "$B/base/fuzz_$2" "fuzz/corpus/$2/$3" >"$B/run.log" 2>&1; then
		echo "RED  $1: the harness as the tree is fails on the seed: $(tail -n 1 "$B/run.log")"
	else
		return 0
	fi
	red=$((red + 1))
	return 1
}

# the changed tree built into $B/mutant, the source restored, then the seed run: 134, at the
# abort() of `want`
judge() {
	name=$1 h=$2 seed=$3 want=$4
	rm -rf "$B/mutant"
	mkdir -p "$B/mutant"
	build "$h" "$B/mutant" >"$B/mutant/build.log" 2>&1
	built=$?
	restore
	if [ "$built" -ne 0 ]; then
		echo "RED  $name: the change does not build: $(grep -m1 error "$B/mutant/build.log")"
		red=$((red + 1))
		return
	fi
	# in a subshell, so the shell's own word on the abort is not printed
	(timeout 120 "$B/mutant/fuzz_$h" "fuzz/corpus/$h/$seed" >"$B/run.log" 2>&1; exit $?) 2>/dev/null
	rc=$?
	hit=$(sed -n 's/^fuzz-records: abort at //p' "$B/run.log" | tail -n 1)
	if [ "$rc" -eq 134 ] && [ "$hit" = "$want" ]; then
		[ -z "${REC_VERBOSE:-}" ] || echo "ok   $name"
	else
		echo "RED  $name: exit $rc, ${hit:-no check}${hit:+ aborted}"
		red=$((red + 1))
	fi
}

for f in $sources; do
	awk '{ print NR "|0|" $0 }' "$f" | awk -v file="$f" -v records=1 -v sep="$SEP" -f fuzz/checks.awk
done >"$B/records.txt"
while IFS=$SEP read -r file at path line old new seed; do
	h=$(basename "$file" .c)
	h=${h#fuzz_}
	case " $HARNESSES " in *" $h "*) ;; *) continue ;; esac
	n=$((n + 1))
	name="$file:$at $path:$line on $seed"
	passes "$name" "$h" "$seed" || continue
	case $path in
	src/* | include/* | transport/src/*) ;;
	*)
		echo "RED  $name: the change is not to src/, include/ or transport/src/"
		red=$((red + 1))
		continue
		;;
	esac
	cp "$path" "$B/orig"
	saved=$path
	if ! O=$old N=$new awk -v l="$line" '
		NR == l { s = $0; out = ""; k = 0
			  while ((i = index(s, ENVIRON["O"])) > 0) { k++; out = out substr(s, 1, i - 1) ENVIRON["N"]
								     s = substr(s, i + length(ENVIRON["O"])) }
			  $0 = out s; if (k != 1) bad = 1 }
		{ print }
		END { exit bad }' "$B/orig" >"$path"; then
		restore
		echo "RED  $name: \`$old\` is not once on $path:$line"
		red=$((red + 1))
		continue
	fi
	judge "$name" "$h" "$seed" "$file:$at"
done <"$B/records.txt"
records=$n

# the breakage patches of fuzz/sabotage/, each the same way: the check and the seed its header
# names
for p in fuzz/sabotage/*.patch; do
	[ -f "$p" ] || continue
	h=$(basename "$p" .patch)
	h=${h%%-*}
	case " $HARNESSES " in *" $h "*) ;; *) continue ;; esac
	n=$((n + 1))
	at=$(sed -n "s|^Breaks the check of \(fuzz/fuzz_$h\.c:[0-9]*\) (.*)\.\$|\1|p" "$p" | head -n 1)
	seed=$(sed -n "s|^Caught by the seed input \"\([^\"]*\)\" of fuzz_$h\.\$|\1|p" "$p" | head -n 1)
	name="$at $p on $seed"
	if [ -z "$at" ]; then
		echo "RED  $p: its header names no check of fuzz/fuzz_$h.c"
		red=$((red + 1))
		continue
	fi
	passes "$name" "$h" "$seed" || continue
	if ! git apply "$p"; then
		echo "RED  $name: the patch does not apply"
		red=$((red + 1))
		continue
	fi
	applied=$p
	judge "$name" "$h" "$seed" "$at"
done

if [ "$n" -eq 0 ]; then
	echo "make fuzz-records: RED -- no record in fuzz/"
	exit 1
fi
if [ "$red" -ne 0 ]; then
	echo "make fuzz-records: RED -- $red of $n records and patches not met"
	exit 1
fi
echo "make fuzz-records: all $records records and $((n - records)) patches met, each by its own check on its own seed ($checks checks)"
