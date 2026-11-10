/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#define _GNU_SOURCE
#include <sys/sysmacros.h>
/* Immutable record IDs.  INSERT writes <record>/.sql-id.  Records that
 * existed before the table was defined (DEFINE, or data copied in) are never
 * modified; instead ALTER TABLE ADOPT IDS (and DEFINE itself) records an ID
 * for them in the table-private registry .sql/ids/id-<dev>-<ino>, keyed by
 * the record directory's inode so renames keep the ID.  Each entry also holds
 * the directory's birth time (statx btime, when the filesystem has one) so a
 * recycled inode is not mistaken for the adopted record.  The record_id
 * pseudo-field reads .sql-id first, then the registry, else NULL. */
#include "sql_local.h"
static int hex32(const char *s) {
  for (int i = 0; i < 32; i++)
    if (!isxdigit((unsigned char)s[i]))
      return 0;
  return 1;
}
static int key(int base, const char *rel, char *name, size_t z, char *birth,
               size_t bz) {
  struct statx sx;
  if (statx(base, rel, AT_SYMLINK_NOFOLLOW, STATX_INO | STATX_BTIME, &sx) ||
      !S_ISDIR(sx.stx_mode))
    return -1;
  snprintf(name, z, "id-%llx-%llx",
           (unsigned long long)makedev(sx.stx_dev_major, sx.stx_dev_minor),
           (unsigned long long)sx.stx_ino);
  if (sx.stx_mask & STATX_BTIME)
    snprintf(birth, bz, "%lld.%09u", (long long)sx.stx_btime.tv_sec,
             sx.stx_btime.tv_nsec);
  else
    snprintf(birth, bz, "0");
  return 0;
}
static int own_id(int fd, const char *record, char *out) {
  char path[PATH_MAX];
  if (snprintf(path, sizeof(path), "%s/.sql-id", record) >= PATH_MAX)
    return 0;
  int f = openat(fd, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (f < 0)
    return 0;
  char b[40];
  ssize_t n = read(f, b, sizeof(b));
  close(f);
  if (n != 32 || !hex32(b))
    return 0;
  memcpy(out, b, 32);
  out[32] = 0;
  return 1;
}
static int registry_id(int base, const char *record, char *out) {
  char name[96], birth[48], path[160], b[256];
  if (key(base, record, name, sizeof(name), birth, sizeof(birth)))
    return 0;
  snprintf(path, sizeof(path), ".sql/ids/%s", name);
  int f = openat(base, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (f < 0)
    return 0;
  ssize_t n = read(f, b, sizeof(b) - 1);
  close(f);
  if (n < 34 || !hex32(b) || b[32] != '\n')
    return 0;
  b[n] = 0;
  char *eol = strchr(b + 33, '\n');
  if (eol)
    *eol = 0;
  if (strcmp(b + 33, birth) && strcmp(b + 33, "0") && strcmp(birth, "0"))
    return 0; /* recycled inode */
  memcpy(out, b, 32);
  out[32] = 0;
  return 1;
}
/* 1 found (out = 32 hex), 0 none. */
int sql_id_lookup(Env *e, Table *t, const char *record, char *out) {
  (void)e;
  if (own_id(t->fd, record, out))
    return 1;
  /* In a transaction the snapshot's directories are copies; adopted IDs
   * belong to the live record inodes. */
  int base = t->has_live_root ? t->live_root : t->fd;
  if (own_id(base, record, out))
    return 1;
  return registry_id(base, record, out);
}
static int durable(Env *e, int dir, const char *name, const char *text) {
  char temp[NAME_MAX + 1];
  snprintf(temp, sizeof(temp), ".tmp.%d.%.180s", getpid(), name);
  unlinkat(dir, temp, 0);
  int fd = openat(dir, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create ID entry: %s", strerror(errno));
  size_t len = strlen(text);
  int bad = write(fd, text, len) != (ssize_t)len || fsync(fd);
  close(fd);
  if (bad || renameat(dir, temp, dir, name) || fsync(dir)) {
    unlinkat(dir, temp, 0);
    return SQLi_fail(e, SQL_IO, "persist ID entry");
  }
  return 0;
}
static int private_dir(Env *e, int parent, const char *name) {
  if (mkdirat(parent, name, 0700) && errno != EEXIST)
    return SQLi_fail(e, SQL_IO, "create %s: %s", name, strerror(errno));
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || fsync(parent)) {
    if (fd >= 0)
      close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "unsafe private directory %s", name);
  }
  return fd;
}
/* Scanned, write-locked live table.  Gives every record without an ID one;
 * prunes registry entries whose record no longer exists. */
int sql_ids_adopt(Env *e, Table *t, int *adopted, int *existing, int *pruned) {
  int a = 0, x = 0, p = 0, rc = -1;
  int sql = private_dir(e, t->fd, ".sql");
  if (sql < 0)
    return -1;
  int ids = private_dir(e, sql, "ids");
  close(sql);
  if (ids < 0)
    return -1;
  char **keep = calloc(t->nr + 1, sizeof(*keep));
  int nk = 0;
  if (!keep) {
    SQLi_fail(e, SQL_IO, "out of memory");
    goto done;
  }
  for (int i = 0; i < t->nr; i++) {
    char id[33], name[96], birth[48];
    const char *r = t->r[i].path;
    if (key(t->fd, r, name, sizeof(name), birth, sizeof(birth)))
      continue;
    if (own_id(t->fd, r, id)) {
      x++;
      continue;
    }
    if (!(keep[nk] = strdup(name))) {
      SQLi_fail(e, SQL_IO, "out of memory");
      goto done;
    }
    nk++;
    if (registry_id(t->fd, r, id)) {
      x++;
      continue;
    }
    unsigned char raw[16];
    if (getrandom(raw, 16, 0) != 16) {
      SQLi_fail(e, SQL_IO, "random ID unavailable");
      goto done;
    }
    char text[PATH_MAX + 128];
    for (int j = 0; j < 16; j++)
      sprintf(id + 2 * j, "%02x", raw[j]);
    /* Third line: path at adoption time (diagnostic only). */
    snprintf(text, sizeof(text), "%s\n%s\n%s\n", id, birth, r);
    if (durable(e, ids, name, text))
      goto done;
    a++;
  }
  DIR *d = fdopendir(dup(ids));
  if (d) {
    struct dirent *de;
    while ((de = readdir(d))) {
      if (strncmp(de->d_name, "id-", 3))
        continue;
      int live = 0;
      for (int k = 0; k < nk && !live; k++)
        live = !strcmp(keep[k], de->d_name);
      if (!live && !unlinkat(ids, de->d_name, 0))
        p++;
    }
    closedir(d);
    if (p)
      fsync(ids);
  }
  rc = 0;
done:
  if (keep)
    for (int k = 0; k < nk; k++)
      free(keep[k]);
  free(keep);
  close(ids);
  if (adopted)
    *adopted = a;
  if (existing)
    *existing = x;
  if (pruned)
    *pruned = p;
  return rc;
}
