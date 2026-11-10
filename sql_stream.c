/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Structural media validators and streamed (>64 MiB) payloads.
 *
 * Every JPG/MP4 value gets the signature check (JPG: SOI..EOI, MP4: ftyp
 * box).  Fields declared STRICT additionally get a structural walk:
 *   JPG: marker segments with valid lengths, a frame header (SOF) and scan
 *        (SOS), entropy data up to EOI, and EOI as the final two bytes.
 *   MP4: top-level boxes (32-bit, 64-bit and to-end sizes) that tile the file
 *        exactly, ftyp first, and a moov box present.
 * Validators read through a Src that is either memory or a file descriptor,
 * so payloads above the 64 MiB in-memory bound are validated, imported,
 * captured and RAW-output in bounded chunks. */
#include "sql_local.h"
#define CHUNK (1u << 20)
typedef struct {
  const unsigned char *b;
  int fd;
  size_t z;
  unsigned char *win; /* sequential window for fd sources */
  size_t wo, wn;
} Src;
static int rd(Src *s, size_t off, void *out, size_t n) {
  if (off > s->z || n > s->z - off)
    return -1;
  if (s->b) {
    memcpy(out, s->b + off, n);
    return 0;
  }
  if (s->win && off >= s->wo && off + n <= s->wo + s->wn) {
    memcpy(out, s->win + (off - s->wo), n);
    return 0;
  }
  if (n > 64) { /* direct */
    size_t done = 0;
    while (done < n) {
      ssize_t r = pread(s->fd, (char *)out + done, n - done, off + done);
      if (r <= 0)
        return -1;
      done += r;
    }
    return 0;
  }
  if (!s->win && !(s->win = malloc(CHUNK)))
    return -1;
  size_t want = s->z - off < CHUNK ? s->z - off : CHUNK, done = 0;
  while (done < want) {
    ssize_t r = pread(s->fd, s->win + done, want - done, off + done);
    if (r <= 0)
      return -1;
    done += r;
  }
  s->wo = off;
  s->wn = want;
  memcpy(out, s->win, n);
  return 0;
}
static int byte(Src *s, size_t off) {
  unsigned char c;
  return rd(s, off, &c, 1) ? -1 : c;
}
static int jpeg_strict(Src *s) {
  if (s->z < 4 || byte(s, 0) != 0xff || byte(s, 1) != 0xd8)
    return 0;
  size_t pos = 2;
  int sof = 0, sos = 0;
  for (;;) {
    if (byte(s, pos) != 0xff)
      return 0;
    while (byte(s, pos + 1) == 0xff)
      pos++;
    int m = byte(s, pos + 1);
    if (m < 0)
      return 0;
    if (m == 0xd9)
      return sof && sos && pos + 2 == s->z;
    if (m == 0x00 || m == 0xd8)
      return 0;
    if (m == 0x01 || (m >= 0xd0 && m <= 0xd7)) {
      pos += 2;
      continue;
    }
    int hi = byte(s, pos + 2), lo = byte(s, pos + 3);
    if (hi < 0 || lo < 0)
      return 0;
    size_t len = (size_t)hi << 8 | (size_t)lo;
    if (len < 2 || pos + 2 + len > s->z)
      return 0;
    if (m >= 0xc0 && m <= 0xcf && m != 0xc4 && m != 0xc8 && m != 0xcc)
      sof = 1;
    pos += 2 + len;
    if (m != 0xda)
      continue;
    if (!sof)
      return 0;
    sos = 1;
    /* Entropy-coded data: FF00 stuffing and RSTn continue the scan. */
    for (;;) {
      int c = byte(s, pos);
      if (c < 0)
        return 0;
      if (c != 0xff) {
        pos++;
        continue;
      }
      int d = byte(s, pos + 1);
      if (d < 0)
        return 0;
      if (d == 0x00 || (d >= 0xd0 && d <= 0xd7)) {
        pos += 2;
        continue;
      }
      if (d == 0xff) {
        pos++;
        continue;
      }
      break;
    }
  }
}
static int mp4_strict(Src *s) {
  size_t off = 0;
  int moov = 0, first = 1;
  while (off < s->z) {
    unsigned char h[16];
    if (rd(s, off, h, 8))
      return 0;
    unsigned long long size = (unsigned long long)h[0] << 24 | h[1] << 16 |
                              h[2] << 8 | h[3],
                       header = 8;
    if (size == 1) {
      if (rd(s, off, h, 16))
        return 0;
      size = 0;
      for (int i = 8; i < 16; i++)
        size = size << 8 | h[i];
      header = 16;
    } else if (size == 0)
      size = s->z - off;
    for (int i = 4; i < 8; i++)
      if (h[i] < 0x20 || h[i] > 0x7e)
        return 0;
    if (size < header || size > s->z - off)
      return 0;
    if (first && memcmp(h + 4, "ftyp", 4))
      return 0;
    moov |= !memcmp(h + 4, "moov", 4);
    first = 0;
    off += size;
  }
  return off == s->z && moov;
}
static int utf8_stream(Src *s) {
  unsigned char *b = malloc(CHUNK + 4);
  size_t carry = 0, off = 0;
  int ok = b != NULL;
  while (ok && off < s->z) {
    size_t n = s->z - off < CHUNK ? s->z - off : CHUNK;
    if (rd(s, off, b + carry, n)) {
      ok = 0;
      break;
    }
    off += n;
    size_t len = carry + n, cut = len;
    if (off < s->z) {
      /* Hold back a trailing incomplete sequence for the next chunk. */
      size_t k = len;
      int back = 0;
      while (k > 0 && back < 3 && (b[k - 1] & 0xc0) == 0x80)
        k--, back++;
      if (k > 0) {
        unsigned x = b[k - 1];
        size_t need = x >= 0xf0 ? 4 : x >= 0xe0 ? 3 : x >= 0xc0 ? 2 : 1;
        if (need > 1 && len - (k - 1) < need)
          cut = k - 1;
      }
    }
    ok = sql_utf8(b, cut);
    carry = len - cut;
    memmove(b, b + cut, carry);
  }
  if (ok && carry)
    ok = 0;
  free(b);
  return ok;
}
static int check(Env *e, Node *n, Src *s) {
  const char *t = n->type;
  int valid = 1;
  if (!strcmp(t, "TEXT") || !strcmp(t, "SH"))
    valid = s->b ? sql_utf8(s->b, s->z) : utf8_stream(s);
  else if (!strcmp(t, "JPG"))
    valid = n->strict ? jpeg_strict(s)
                      : s->z >= 4 && byte(s, 0) == 255 && byte(s, 1) == 216 &&
                            byte(s, s->z - 2) == 255 && byte(s, s->z - 1) == 217;
  else if (!strcmp(t, "MP4")) {
    unsigned char h[4];
    valid = n->strict ? mp4_strict(s)
                      : s->z >= 12 && !rd(s, 4, h, 4) && !memcmp(h, "ftyp", 4);
  } else if (strcmp(t, "OCTETS")) {
    /* INT64/UINT64/BOOL: small by definition; read and use the text check. */
    if (s->z > 64)
      valid = 0;
    else {
      unsigned char b[65];
      if (rd(s, 0, b, s->z))
        valid = 0;
      else
        return SQLi_value_check_bytes(e, n, b, s->z);
    }
  }
  free(s->win);
  s->win = NULL;
  if (!valid)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid %s%s value for %s", t,
                     n->strict ? " (STRICT)" : "", n->name);
  return 0;
}
int SQLi_media_check(Env *e, Node *n, const unsigned char *b, size_t z) {
  Src s = {.b = b, .fd = -1, .z = z};
  return check(e, n, &s);
}
int SQLi_value_check_fd(Env *e, Node *n, int fd, size_t z) {
  Src s = {.b = NULL, .fd = fd, .z = z};
  return check(e, n, &s);
}
/* Bounded-memory copy; hash is FNV-1a 64 when non-NULL. */
int SQLi_copy_fd(Env *e, int in, int out, size_t z, unsigned long long *hash) {
  unsigned char *b = malloc(CHUNK);
  if (!b)
    return SQLi_fail(e, SQL_IO, "out of memory");
  size_t off = 0;
  int rc = 0;
  while (off < z && !rc) {
    size_t n = z - off < CHUNK ? z - off : CHUNK, got = 0;
    while (got < n) {
      ssize_t r = pread(in, b + got, n - got, off + got);
      if (r <= 0) {
        rc = SQLi_fail(e, SQL_IO, "short streamed payload read");
        break;
      }
      got += r;
    }
    if (rc)
      break;
    if (hash)
      for (size_t i = 0; i < n; i++) {
        *hash ^= b[i];
        *hash *= 1099511628211ULL;
      }
    if (sql_write_all(out, b, n))
      rc = SQLi_fail(e, SQL_IO, "streamed payload write: %s", strerror(errno));
    off += n;
  }
  free(b);
  return rc;
}
int SQLi_batch_put_fd(Env *e, Batch *b, const char *path, int in, size_t z) {
  char slot[32];
  snprintf(slot, sizeof(slot), "data.%d", b->count);
  int fd = openat(b->fd, slot,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create staged payload");
  int rc = SQLi_copy_fd(e, in, fd, z, NULL);
  if (!rc && fsync(fd))
    rc = SQLi_fail(e, SQL_IO, "durable staged payload write");
  close(fd);
  if (rc)
    return -1;
  return SQLi_batch_op(e, b, 'P', path, slot);
}
/* RAW output of one large member without buffering it. */
int SQLi_stream_out(Env *e, int in, size_t z, FILE *out) {
  fflush(out);
  unsigned char *b = malloc(CHUNK);
  if (!b)
    return SQLi_fail(e, SQL_IO, "out of memory");
  size_t off = 0;
  int rc = 0;
  while (off < z && !rc) {
    size_t n = z - off < CHUNK ? z - off : CHUNK;
    ssize_t r = pread(in, b, n, off);
    if (r <= 0)
      rc = SQLi_fail(e, SQL_IO, "short streamed read");
    else if (fwrite(b, 1, r, out) != (size_t)r)
      rc = SQLi_fail(e, SQL_IO, "write streamed output");
    else
      off += r;
  }
  free(b);
  return rc;
}
