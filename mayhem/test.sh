#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libbacktrace's own `make check` suite (built by mayhem/build.sh into
# mayhem/build-tests). exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build-tests"
[ -f "$T/Makefile" ] || { echo "test.sh: $T not built — run mayhem/build.sh" >&2; emit_ctrf "automake-check" 0 1 0; exit 1; }

# Fresh results each run.
rm -f "$T"/*.log "$T"/*.trs
make -k -C "$T" check >"$T/check-output.txt" 2>&1
make_rc=$?

# Programs that report their own known-answer checks as "PASS: <what>" lines (symbolized function
# names, file:line values, decompressed bytes, ...). A clean exit without those lines means the
# program did not actually check anything, which counts as a failure.
self_reporting='^(btest|ctest|dwarf5|edtest|mtest|mdtest|m2test|b2test|b3test|strippedtest|ttest|unittest|xztest|zstdtest|ztest)'

passed=0 failed=0 skipped=0
for trs in "$T"/*.trs; do
  [ -e "$trs" ] || continue
  name=$(basename "$trs" .trs)
  log="$T/$name.log"
  res=$(sed -n 's/^:test-result: //p' "$trs" | head -1)
  npass=$(grep -c '^PASS: ' "$log" 2>/dev/null || true)
  nfail=$(grep -c '^FAIL: ' "$log" 2>/dev/null || true)
  case "$res" in
    PASS|XFAIL)
      if [ "${nfail:-0}" -gt 0 ] || { [[ "$name" =~ $self_reporting ]] && [ "${npass:-0}" -eq 0 ]; }; then
        echo "FAIL: $name (exit 0 but ${npass:-0} PASS / ${nfail:-0} FAIL lines)"; failed=$((failed+1))
      else
        passed=$((passed+1))
      fi ;;
    SKIP) skipped=$((skipped+1)) ;;
    *) echo "FAIL: $name ($res)"; sed 's/^/    /' "$log" | tail -20; failed=$((failed+1)) ;;
  esac
done
# The suite must actually have run: btest + dwarf5 are the core symbolization checks.
for must in btest dwarf5 ztest; do
  [ -f "$T/$must.trs" ] || { echo "FAIL: $must did not run"; failed=$((failed+1)); }
done
if [ "$make_rc" -ne 0 ] && [ "$failed" -eq 0 ]; then
  echo "FAIL: make check exited $make_rc"; tail -30 "$T/check-output.txt"; failed=1
fi
emit_ctrf "automake-check" "$passed" "$failed" "$skipped"
