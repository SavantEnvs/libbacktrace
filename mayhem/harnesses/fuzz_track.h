/* Per-input allocation tracking for the libbacktrace fuzz harnesses.
   libbacktrace has no API to destroy a backtrace_state: everything it parses
   lives until process exit.  For a fuzzer that would grow RSS without bound,
   so the library sources are compiled with malloc/realloc/free/strdup renamed
   to the fz_* functions below (via -D on the compile line, upstream files are
   unchanged), and the harness frees every live allocation after each input
   with fz_reset().  Allocations are still exact-size malloc blocks, so ASan
   keeps its redzones past the end of every buffer.  */
#ifndef FUZZ_TRACK_H
#define FUZZ_TRACK_H
#include <stddef.h>
void *fz_malloc (size_t);
void *fz_realloc (void *, size_t);
void fz_free (void *);
char *fz_strdup (const char *);
void fz_reset (void);
#endif
