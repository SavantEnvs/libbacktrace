/* libbacktrace fuzz harness: the input is an object file (the "executable"
   that backtrace_create_state is told to symbolize).  The same source is
   linked against one object-format backend per target -- elf.c, pecoff.c,
   macho.c or xcoff.c -- since each defines backtrace_initialize.

   Parsing is lazy: nothing is read until the first backtrace_pcinfo /
   backtrace_syminfo, and DWARF line info for a unit is only decoded when a
   queried PC falls inside it, so the harness queries a spread of PCs: common
   load addresses, the ELF entry point when the header has one, and PCs taken
   from the tail of the input.

   backtrace_create_state needs a real file name (it open()s it), so the input
   is written to a per-process file under $TMPDIR.  Everything libbacktrace
   allocates is freed after each input by fz_reset() (fuzz_track.h).  */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "backtrace.h"
#include "fuzz_track.h"

static char fz_path[4096];
volatile size_t fz_sink;

static void error_cb (void *data, const char *msg, int errnum) {
  (void) data; (void) msg; (void) errnum;
}

static int pcinfo_cb (void *data, uintptr_t pc, const char *filename,
                      int lineno, const char *function) {
  /* Touch the strings so a dangling/unterminated name is caught by ASan.  */
  size_t *acc = data;
  if (filename) *acc += strlen (filename);
  if (function) *acc += strlen (function);
  *acc += (size_t) lineno + (size_t) pc;
  return 0;
}

static void syminfo_cb (void *data, uintptr_t pc, const char *symname,
                        uintptr_t symval, uintptr_t symsize) {
  size_t *acc = data;
  if (symname) *acc += strlen (symname);
  *acc += (size_t) (pc + symval + symsize);
}

static void query (struct backtrace_state *st, uintptr_t pc, size_t *acc) {
  backtrace_pcinfo (st, pc, pcinfo_cb, error_cb, acc);
  backtrace_syminfo (st, pc, syminfo_cb, error_cb, acc);
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
  static const uintptr_t fixed_pcs[] = {
    0, 0x1000, 0x1040, 0x1100, 0x1139, 0x2000, 0x10000,
    0x400000, 0x401000, 0x401136, 0x140001000, 0x100000000, 0x100000f50,
    0x10000000, 0x100000100,
  };
  struct backtrace_state *st;
  FILE *f;
  size_t acc = 0, i, n;

  if (fz_path[0] == '\0') {
    const char *tmp = getenv ("TMPDIR");
    if (tmp == NULL || *tmp == '\0') tmp = "/tmp";
    snprintf (fz_path, sizeof fz_path, "%s/fuzz_backtrace_%ld.obj", tmp,
              (long) getpid ());
  }
  f = fopen (fz_path, "wb");
  if (f == NULL) return 0;
  if (size > 0 && fwrite (data, 1, size, f) != size) {
    fclose (f);
    unlink (fz_path);
    return 0;
  }
  fclose (f);

  st = backtrace_create_state (fz_path, 0, error_cb, NULL);
  if (st != NULL) {
    for (i = 0; i < sizeof fixed_pcs / sizeof fixed_pcs[0]; i++)
      query (st, fixed_pcs[i], &acc);
    /* ELF64 e_entry (offset 24) and a few PCs after it: a convenient PC that
       usually lies inside a compilation unit.  Only used to pick queries.  */
    if (size >= 32 && memcmp (data, "\177ELF", 4) == 0 && data[4] == 2) {
      uint64_t entry;
      memcpy (&entry, data + 24, sizeof entry);
      for (i = 0; i < 64; i += 16)
        query (st, (uintptr_t) (entry + i), &acc);
    }
    n = size / sizeof (uint64_t);
    if (n > 8) n = 8;
    for (i = 0; i < n; i++) {
      uint64_t pc;
      memcpy (&pc, data + size - sizeof pc * (i + 1), sizeof pc);
      query (st, (uintptr_t) pc, &acc);
    }
  }

  unlink (fz_path);
  fz_reset ();
  fz_sink = acc;
  return 0;
}
