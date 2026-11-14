#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The release's install checks ask only for the cells the release built. The 0.1.10 release (run 43592063308)
# built the quick set through the shared build-rpm / build-deb workflows (fc44 and fc45 x86_64, trixie amd64 and
# arm64). Its own install checks, a hand-written matrix, then asked download-artifact for bookworm and fc44 aarch64,
# cells no job had built: red on this repository's own jobs after a green publish.
#
# The rule (ruling D25; Open-Mixer/.github#80, "plan the cells with release-matrix"): an install check takes its
# cells from a plan job that runs the shared release-matrix action with the same inputs the shared build hands it,
# so the build and the check read the same set.
#
# Over release.yml:
#   A. no strategy.matrix dimension is a literal list; each is fromJSON of a plan job's output;
#   B. a literal cell (debian:<suite>, fedora:<n>, fc<n>, a bare Debian suite) and a JSON array of cell names are
#      written only on a plan step's releases / arches input, the one place the whole matrix is declared;
#   C. each install check needs its build and a plan job whose step is release-matrix of the build's kind (the
#      build set, never a check's), reading vars.OMX_RELEASE_MATRIX; it runs only when the plan's count is not 0,
#      its matrix is the plan's cells, and its download-artifact name is built from that cell.
# Then, with a checkout of Open-Mixer/.github (OPENMIXER_DOTGITHUB):
#   D. each plan's releases and arches are the defaults build-rpm.yml / build-deb.yml hand release-matrix (this
#      repository passes the builds none), so the two plans cannot drift from the builds;
#   E. each plan, rendered by the shared matrix.sh on a tag, is the quick set of its kind with a quick wave and the
#      whole matrix with a full one.
# Without the checkout D and E are reported as not run (exit 77), never as a pass.
set -u
top=$(cd "$(dirname "$0")/.." && pwd)
python3 -c 'import yaml' 2>/dev/null || { echo "no python3 yaml module: nothing tested"; exit 77; }
rel="$top/.github/workflows/release.yml"
[ -f "$rel" ] || { echo "no release workflow (a release tarball): nothing tested"; exit 77; }
plans=$(mktemp); trap 'rm -f "$plans"' EXIT
python3 - "$rel" "$plans" <<'PY' || exit 1
import json, re, sys, yaml
path, out = sys.argv[1], sys.argv[2]
text = open(path).read()
doc = yaml.safe_load(text) or {}
jobs = doc.get("jobs") or {}
bad = 0
def no(msg):
    global bad
    print("FAIL " + msg); bad = 1

# A
for jn, job in jobs.items():
    m = ((job or {}).get("strategy") or {}).get("matrix")
    if isinstance(m, dict):
        for dim, val in m.items():
            if isinstance(val, list):
                no("job %s: strategy.matrix.%s is a literal list %s (A)" % (jn, dim, val))
            elif isinstance(val, str) and "fromJSON(" not in val:
                no("job %s: strategy.matrix.%s is not fromJSON of a plan output: %s (A)" % (jn, dim, val))
# B
CELL = re.compile(r"debian:[a-z]|fedora:\d|\bfc\d\d\b|\b(buster|bullseye|bookworm|trixie|forky)\b")
ARRAY = re.compile(r"\[\s*['\"](\d\d|buster|bullseye|bookworm|trixie|forky|x86_64|aarch64|amd64|arm64)['\"]")
INPUT = re.compile(r"^\s*(releases|arches):")
for i, line in enumerate(text.splitlines(), 1):
    s = line.split("#", 1)[0]
    if not s.strip() or INPUT.match(s):
        continue
    if CELL.search(s):
        no("release.yml:%d: a literal cell outside a plan step's input: %s (B)" % (i, line.strip()))
    if ARRAY.search(s):
        no("release.yml:%d: a cell array outside a plan step's input: %s (B)" % (i, line.strip()))
# C
plans = {}
for jn, job in jobs.items():
    for st in (job or {}).get("steps") or []:
        if "actions/release-matrix" in str(st.get("uses", "")):
            w = st.get("with") or {}
            plans[jn] = {"kind": w.get("kind"), "releases": w.get("releases", "[]"), "arches": w.get("arches", "[]"),
                         "wave": str(w.get("wave", "")), "outputs": (job.get("outputs") or {})}
art = {"rpm": "libdiginet-rpms-fc${{ matrix.cell.fedora }}-${{ matrix.cell.arch }}",
       "deb": "libdiginet-debs-${{ matrix.cell.suite }}-${{ matrix.cell.arch }}"}
for kind in ("rpm", "deb"):
    inst = jobs.get("install-" + kind)
    if not inst:
        no("no install-%s job (C)" % kind); continue
    needs = inst.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    if kind not in needs:
        no("install-%s does not need the %s build (C): needs %s" % (kind, kind, needs))
    plan = [n for n in needs if n in plans]
    if not plan:
        no("install-%s follows no release-matrix plan job (C): needs %s" % (kind, needs)); continue
    pn, p = plan[0], plans[plan[0]]
    if p["kind"] != kind:
        no("install-%s: its plan %s is kind %s, not %s (C)" % (kind, pn, p["kind"], kind))
    if "vars.OMX_RELEASE_MATRIX" not in p["wave"]:
        no("install-%s: its plan %s does not read vars.OMX_RELEASE_MATRIX (C)" % (kind, pn))
    for o in ("cells", "count"):
        if o not in p["outputs"]:
            no("install-%s: its plan %s does not output %s (C)" % (kind, pn, o))
    if "needs.%s.outputs.count != '0'" % pn not in str(inst.get("if", "")):
        no("install-%s: no `if: needs.%s.outputs.count != '0'` (C): %r" % (kind, pn, inst.get("if")))
    cell = str(((inst.get("strategy") or {}).get("matrix") or {}).get("cell", ""))
    if "needs.%s.outputs.cells" % pn not in cell:
        no("install-%s: matrix.cell is not the plan's cells (C): %r" % (kind, cell))
    dl = [st for st in inst.get("steps") or [] if "download-artifact" in str(st.get("uses", ""))]
    got = (dl[0].get("with") or {}).get("name") if dl else None
    if got != art[kind]:
        no("install-%s: download-artifact asks for %r, not %r (C)" % (kind, got, art[kind]))
    with open(out, "a") as f:
        f.write("%s\t%s\t%s\n" % (kind, json.dumps(json.loads(p["releases"])), json.dumps(json.loads(p["arches"]))))
print("release.yml: %d jobs, %d release-matrix plans" % (len(jobs), len(plans)))
sys.exit(bad)
PY
dg=${OPENMIXER_DOTGITHUB:-}
if [ -z "$dg" ] || [ ! -f "$dg/.github/actions/release-matrix/matrix.sh" ]; then
  echo "no Open-Mixer/.github checkout (OPENMIXER_DOTGITHUB): D and E not run"; exit 77
fi
rc=0
default() { # <workflow> <input> -> its default, as JSON
  python3 -c 'import json,sys,yaml; d=yaml.safe_load(open(sys.argv[1])); on=d.get("on", d.get(True)); print(json.dumps(json.loads(on["workflow_call"]["inputs"][sys.argv[2]]["default"])))' "$1" "$2"
}
render() { # <kind> <releases> <arches> <wave> -> "rel arch" per line, sorted
  KIND=$1 RELEASES=$2 ARCHES=$3 MATRIX= WAVE=$4 STAGED=false EVENT=push REF_TYPE=tag REF_NAME=v0.0.0 SOURCE_REF= \
    CATCH_UP=false GITHUB_OUTPUT= bash "$dg/.github/actions/release-matrix/matrix.sh" 2>/dev/null | sed -n 's/^cells=//p' \
    | python3 -c 'import json,sys; [print(c.get("fedora") or c.get("suite"), c["arch"]) for c in json.loads(sys.stdin.read() or "[]")]' | sort
}
while IFS="$(printf '\t')" read -r kind rels arches; do
  case $kind in
    rpm) wrel=$(default "$dg/.github/workflows/build-rpm.yml" fedora-versions); warch=$(default "$dg/.github/workflows/build-rpm.yml" arch-matrix) ;;
    deb) wrel=$(default "$dg/.github/workflows/build-deb.yml" suite-matrix); warch=$(default "$dg/.github/workflows/build-deb.yml" arch-matrix) ;;
  esac
  if [ "$rels $arches" = "$wrel $warch" ]; then echo "ok   $kind plan declares the build's matrix $rels x $arches (D)"
  else echo "FAIL $kind plan declares $rels x $arches, the shared build is handed $wrel x $warch (D)"; rc=1; fi
  q=$(render "$kind" "$rels" "$arches" quick)
  want=$(awk -v k="$kind" '$1 == k { print $2, $3 }' "$dg/.github/actions/release-matrix/quick.txt" | sort)
  if [ -n "$q" ] && [ "$q" = "$want" ]; then echo "ok   $kind quick wave renders the quick set: $(echo $q) (E)"
  else echo "FAIL $kind quick wave rendered '$(echo $q)', the quick set is '$(echo $want)' (E)"; rc=1; fi
  f=$(render "$kind" "$rels" "$arches" full)
  n=$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])) * len(json.loads(sys.argv[2])))' "$rels" "$arches")
  if [ "$(echo "$f" | grep -c .)" = "$n" ]; then echo "ok   $kind full wave renders the whole matrix ($n cells) (E)"
  else echo "FAIL $kind full wave rendered '$(echo $f)', not $n cells (E)"; rc=1; fi
done < "$plans"
[ -s "$plans" ] || { echo "FAIL no plan to render"; rc=1; }
exit $rc
