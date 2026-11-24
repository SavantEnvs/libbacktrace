/* See fuzz_track.h.  Built WITHOUT the malloc renames.  */
#include <stdlib.h>
#include <string.h>
#include "fuzz_track.h"

/* Each tracked block carries a header in front of the payload.  It is kept
   ASan-poisoned except while the tracker itself touches it, so a read or
   write a few bytes before a libbacktrace buffer is still reported (as
   use-after-poison) instead of landing silently in the header.  */
#if defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define FZ_ASAN 1
# endif
#endif
#if defined(__SANITIZE_ADDRESS__)
# define FZ_ASAN 1
#endif
#ifdef FZ_ASAN
# include <sanitizer/asan_interface.h>
#else
# define ASAN_POISON_MEMORY_REGION(a, n) ((void) (a), (void) (n))
# define ASAN_UNPOISON_MEMORY_REGION(a, n) ((void) (a), (void) (n))
#endif

struct fz_hdr {
  struct fz_hdr *prev, *next;
  size_t size, pad;            /* keeps the payload 16-byte aligned */
};

static struct fz_hdr fz_head = { &fz_head, &fz_head, 0, 0 };

/* fz_head is a static and is never poisoned.  */
static void fz_open (struct fz_hdr *h) {
  if (h != &fz_head) ASAN_UNPOISON_MEMORY_REGION (h, sizeof *h);
}

static void fz_close (struct fz_hdr *h) {
  if (h != &fz_head) ASAN_POISON_MEMORY_REGION (h, sizeof *h);
}

/* Link a block whose header is unpoisoned; leaves it poisoned.  */
static void fz_link (struct fz_hdr *h) {
  struct fz_hdr *n = fz_head.next;
  fz_open (n);
  h->next = n; h->prev = &fz_head;
  n->prev = h; fz_head.next = h;
  fz_close (n);
  fz_close (h);
}

/* Unlink a block; leaves its header unpoisoned for the caller.  */
static void fz_unlink (struct fz_hdr *h) {
  struct fz_hdr *p, *n;
  fz_open (h);
  p = h->prev; n = h->next;
  fz_open (p); fz_open (n);
  p->next = n; n->prev = p;
  fz_close (p); fz_close (n);
}

/* libbacktrace sizes many buffers straight from header fields (section
   sizes, uncompressed lengths) and handles a failed allocation by reporting
   it through the error callback (upstream tests this: allocfail.sh).  A
   multi-gigabyte request from a few-KB input would only make the fuzzer stop
   with an OOM / allocation-size-too-big report, so requests above
   FZ_MAX_ALLOC fail the way malloc fails on a memory-limited host.  */
#define FZ_MAX_ALLOC ((size_t) 256 << 20)

void *fz_malloc (size_t n) {
  struct fz_hdr *h;
  if (n > FZ_MAX_ALLOC) return NULL;
  h = malloc (sizeof *h + n);
  if (h == NULL) return NULL;
  h->size = n;
  fz_link (h);
  return h + 1;
}

void *fz_realloc (void *p, size_t n) {
  struct fz_hdr *h, *nh;
  if (p == NULL) return fz_malloc (n);
  if (n > FZ_MAX_ALLOC) return NULL;
  h = (struct fz_hdr *) p - 1;
  fz_unlink (h);
  nh = realloc (h, sizeof *h + n);
  if (nh == NULL) { fz_link (h); return NULL; }
  ASAN_UNPOISON_MEMORY_REGION (nh, sizeof *nh);
  nh->size = n;
  fz_link (nh);
  return nh + 1;
}

void fz_free (void *p) {
  struct fz_hdr *h;
  if (p == NULL) return;
  h = (struct fz_hdr *) p - 1;
  fz_unlink (h);
  free (h);
}

char *fz_strdup (const char *s) {
  size_t n = strlen (s) + 1;
  char *r = fz_malloc (n);
  if (r != NULL) memcpy (r, s, n);
  return r;
}

void fz_reset (void) {
  while (fz_head.next != &fz_head) {
    struct fz_hdr *h = fz_head.next;
    fz_unlink (h);
    free (h);
  }
}
