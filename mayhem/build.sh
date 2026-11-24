#!/usr/bin/env bash
# mayhem/build.sh — build the libbacktrace fuzz targets and the upstream test suite.
#
# Runs as `mayhem` in /mayhem (re-runnable, offline). Everything goes to gitignored
# mayhem/build/ (fuzz build) and mayhem/build-tests/ (test suite), both out of tree.
#
# Fuzz build: upstream's configure only generates config.h + backtrace-supported.h; the
# library sources are then compiled directly, once per object-format backend
# (elf.c / pecoff.c / macho.c / xcoff.c each define backtrace_initialize, so one per binary),
# with read.c + alloc.c (malloc-backed views: ASan sees overflows, and a truncated file is a
# clean "file too short" instead of a SIGBUS from mmap past EOF). Per-format config.h tweaks
# (generated files, not upstream sources):
#   - HAVE_DL_ITERATE_PHDR removed: otherwise elf.c also loads every shared object of the
#     fuzzer process itself on each input (slow, and not attacker-controlled data).
#   - xcoff: BACKTRACE_XCOFF_SIZE 64 (configure leaves it "unused" on Linux).
# Library TUs get malloc/realloc/free/strdup renamed to the harness's per-input tracker
# (mayhem/harnesses/fuzz_track.h) because libbacktrace has no destroy API.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
H="$SRC/mayhem/harnesses"
mkdir -p "$B/cfg"

# 1) configure (out of tree) just for the generated headers.
( cd "$B/cfg" && env -u CFLAGS -u LDFLAGS "$SRC/configure" --disable-shared CC="$CC" CFLAGS="-O1" >configure.log 2>&1 ) \
  || { cat "$B/cfg/configure.log" >&2; exit 1; }

COMMON_SRCS="atomic dwarf fileline posix print sort state backtrace simple read alloc"
RENAME="-Dmalloc=fz_malloc -Drealloc=fz_realloc -Dfree=fz_free -Dstrdup=fz_strdup -include $H/fuzz_track.h"
# SanCov on the library + harness objects (the libFuzzer link adds the runtime; the standalone
# link gets the sanitizer runtime's weak no-op callbacks). Dropped when LIB_FUZZING_ENGINE is empty.
COV_FLAGS=""
[ -n "$LIB_FUZZING_ENGINE" ] && COV_FLAGS="-fsanitize=fuzzer-no-link"
CFLAGS_F="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O1"

$CC $CFLAGS_F -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
$CC $CFLAGS_F -c "$H/fuzz_track.c" -o "$B/fuzz_track.o"
$CC $CFLAGS_F -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

build_fmt() {
  local fmt="$1" d="$B/$1"
  mkdir -p "$d/inc"
  sed -e '/#define HAVE_DL_ITERATE_PHDR/d' "$B/cfg/config.h" > "$d/inc/config.h.new"
  if [ "$fmt" = xcoff ]; then
    sed -i -e 's/^#define BACKTRACE_XCOFF_SIZE .*/#define BACKTRACE_XCOFF_SIZE 64/' "$d/inc/config.h.new"
  fi
  # Only replace when changed so a re-run keeps make-free timestamps sane.
  cmp -s "$d/inc/config.h.new" "$d/inc/config.h" 2>/dev/null || mv "$d/inc/config.h.new" "$d/inc/config.h"
  rm -f "$d/inc/config.h.new"
  cp "$B/cfg/backtrace-supported.h" "$d/inc/"
  local objs=() s
  for s in $COMMON_SRCS "$fmt"; do
    $CC $CFLAGS_F $RENAME -DHAVE_CONFIG_H -I"$d/inc" -I"$SRC" -c "$SRC/$s.c" -o "$d/$s.o"
    objs+=("$d/$s.o")
  done
  $CC $CFLAGS_F -I"$d/inc" -I"$SRC" -I"$H" -c "$H/fuzz_backtrace.c" -o "$d/fuzz_backtrace.o"
  $CC $CFLAGS_F $LIB_FUZZING_ENGINE "$d/fuzz_backtrace.o" "${objs[@]}" "$B/fuzz_track.o" "$B/lsan_off.o" \
      -o "$SRC/fuzz_$fmt"
  $CC $CFLAGS_F "$B/standalone_main.o" "$d/fuzz_backtrace.o" "${objs[@]}" "$B/fuzz_track.o" "$B/lsan_off.o" \
      -o "$SRC/fuzz_$fmt-standalone"
}

for fmt in elf pecoff macho xcoff; do
  build_fmt "$fmt" &
done
wait_all() { local rc=0 p; for p in $(jobs -p); do wait "$p" || rc=1; done; return $rc; }
wait_all

# 2) Upstream's test suite, normal flags, its own out-of-tree build (test.sh runs it).
T="$SRC/mayhem/build-tests"
mkdir -p "$T"
if [ ! -f "$T/Makefile" ]; then
  ( cd "$T" && env -u CFLAGS -u LDFLAGS "$SRC/configure" CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" >configure.log 2>&1 ) \
    || { cat "$T/configure.log" >&2; exit 1; }
fi
# Build every check program/derived test file without running them.
make -C "$T" -j"$MAYHEM_JOBS" check TESTS= >"$T/build.log" 2>&1 || { tail -50 "$T/build.log" >&2; exit 1; }
# ...and the tests that are derived files (stripped / debuglink / minidebuginfo copies), so test.sh only runs.
maketests=$(printf 'print-maketests:\n\t@echo $(MAKETESTS)\n' | make -s -C "$T" -f Makefile -f - print-maketests)
if [ -n "$maketests" ]; then
  # shellcheck disable=SC2086
  make -C "$T" -j"$MAYHEM_JOBS" $maketests >>"$T/build.log" 2>&1 || { tail -50 "$T/build.log" >&2; exit 1; }
fi
echo "build.sh: done"
