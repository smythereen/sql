/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_event.h"
#include "sql_local.h"
typedef struct {
  uint32_t magic, version;
  uint64_t owner;
} JHeader;
typedef struct {
  uint32_t type, a, b, slot;
} JEntry;
static int valid_journal_name(const char *name) {
  if (strncmp(name, ".sql-txn.", 9) || strlen(name) != 41)
    return 0;
  for (const char *p = name + 9; *p; p++)
    if (!isxdigit((unsigned char)*p))
      return 0;
  return 1;
}
static int writeall(int fd, const void *v, size_t n) {
  const char *s = v;
  while (n) {
    ssize_t z = write(fd, s, n);
    if (z < 0 && errno == EINTR)
      continue;
    if (z <= 0)
      return -1;
    s += z;
    n -= z;
  }
  return 0;
}
static int readall(int fd, void *v, size_t n) {
  char *s = v;
  while (n) {
    ssize_t z = read(fd, s, n);
    if (z < 0 && errno == EINTR)
      continue;
    if (z <= 0)
      return -1;
    s += z;
    n -= z;
  }
  return 0;
}
/* Retire the reader gate atomically BEFORE reclaiming journal payloads. A
 * crash while unlinking payloads must never leave a COMMIT with missing redo.
 * GARBAGE is retained until all other children are gone. */
typedef struct {
  uint32_t magic, version;
  uint64_t uid, device, inode;
  char id[33];
} GCProof;
static int gc_proof(Env *e, int root, const char *name, int fd) {
  struct stat st;
  GCProof proof;
  int f = sql_regular_open(e, fd, "GARBAGE", 0, &st);
  if (f < 0)
    return -1;
  int bad = st.st_size != sizeof(proof) || readall(f, &proof, sizeof(proof));
  close(f);
  struct stat identity;
  bad |= fstat(root, &identity) != 0;
  if (bad || proof.magic != MAGIC || proof.version != 1 ||
      proof.uid != getuid() || proof.device != (uint64_t)identity.st_dev ||
      proof.inode != (uint64_t)identity.st_ino || !memchr(proof.id, 0, 33) ||
      strlen(proof.id) != 32 || strcmp(name + 11, proof.id))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid/foreign journal garbage proof");
  return 0;
}
static int gc_finish(Env *e, int root, const char *name, int fd) {
  if (gc_proof(e, root, name, fd))
    return -1;
  DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan retired journal");
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") ||
        !strcmp(de->d_name, "GARBAGE"))
      continue;
    if (sql_tree_remove(e, fd, de->d_name)) {
      rc = -1;
      break;
    }
    if (getenv("SQL_TEST_CRASH") &&
        !strcmp(getenv("SQL_TEST_CRASH"), "journal-during-gc"))
      _exit(92);
  }
  closedir(d);
  if (!rc && (fsync(fd) || unlinkat(fd, "GARBAGE", 0) || fsync(fd)))
    rc = SQLi_fail(e, SQL_IO, "persist retired payload reclamation");
  if (!rc && getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "journal-after-proof-remove"))
    _exit(93);
  if (!rc && (unlinkat(root, name, AT_REMOVEDIR) || fsync(root)))
    rc = SQLi_fail(e, SQL_IO, "finish retired journal cleanup");
  return rc;
}
static int cleanbatch(Env *e, int root, const char *name, int fd) {
  char garbage[80];
  snprintf(garbage, sizeof(garbage), ".sql-clean.%s", name + 9);
  struct stat rootinfo, current, held;
  int rc = -1;
  if (fstat(root, &rootinfo) || fstat(fd, &held) ||
      fstatat(root, name, &current, AT_SYMLINK_NOFOLLOW) ||
      held.st_dev != current.st_dev || held.st_ino != current.st_ino) {
    SQLi_fail(e, SQL_CONSTRAINT, "journal identity changed before retirement");
    goto done;
  }
  GCProof proof = {.magic = MAGIC,
                   .version = 1,
                   .uid = getuid(),
                   .device = rootinfo.st_dev,
                   .inode = rootinfo.st_ino};
  memcpy(proof.id, name + 9, 33);
  int f = openat(fd, "GARBAGE",
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (f < 0 && errno == EEXIST) {
    f = sql_regular_open(e, fd, "GARBAGE", 1, NULL);
  }
  if (f < 0) {
    SQLi_fail(e, SQL_IO, "create journal retirement proof");
    goto done;
  }
  int failed = writeall(f, &proof, sizeof(proof)) ||
               ftruncate(f, sizeof(proof)) || fsync(f);
  close(f);
  if (failed || fsync(fd) ||
      renameat2(root, name, root, garbage, RENAME_NOREPLACE) || fsync(root)) {
    SQLi_fail(e, SQL_IO, "durably retire journal reader gate");
    goto done;
  }
  if (getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "journal-after-retire"))
    _exit(91);
  rc = gc_finish(e, root, garbage, fd);
done:
  close(fd);
  return rc;
}
static int recover_garbage(Env *e, int root, const char *name, int change) {
  if (strlen(name) != 43)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid garbage journal name");
  for (const char *p = name + 11; *p; p++)
    if (!isxdigit((unsigned char)*p))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid garbage journal ID");
  int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0 || fstat(fd, &st) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    if (fd >= 0)
      close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid retired journal owner/mode");
  }
  struct stat proof;
  if (fstatat(fd, "GARBAGE", &proof, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) {
    /* A crash after removing the last proof can leave only an empty directory.
       rmdir cannot recursively erase any unknown data. */
    int rc = 0;
    DIR *scan = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY));
    if (!scan) {
      close(fd);
      return SQLi_fail(e, SQL_IO, "inspect unproven retired directory");
    }
    struct dirent *entry;
    int nonempty = 0;
    while ((entry = readdir(scan)))
      if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
        nonempty = 1;
    closedir(scan);
    if (nonempty) {
      close(fd);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "unproven retired directory contains data; preserved");
    }
    if (change && (unlinkat(root, name, AT_REMOVEDIR) || fsync(root)))
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "unproven retired directory is not empty; preserved");
    close(fd);
    return rc;
  }
  int rc = gc_proof(e, root, name, fd);
  if (!rc && change)
    rc = gc_finish(e, root, name, fd);
  else if (!rc)
    fprintf(e->stream, "%s reclaim retired journal only (no replay)\n",
            name + 11);
  close(fd);
  return rc;
}
int SQLi_batch_begin(Env *e, int root, Batch *b) {
  memset(b, 0, sizeof(*b));
  b->fd = -1;
  b->root = root;
  unsigned char id[16];
  if (getrandom(id, 16, 0) != 16)
    return SQLi_fail(e, SQL_IO, "random transaction ID failed");
  char *p = b->name;
  p += sprintf(p, ".sql-txn.");
  for (int i = 0; i < 16; i++)
    p += sprintf(p, "%02x", id[i]);
  if (sql_command_local(e, b->name + 9, root))
    return -1;
  if (mkdirat(root, b->name, 0700))
    return SQLi_fail(e, SQL_IO, "create journal: %s", strerror(errno));
  b->fd =
      openat(root, b->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (b->fd < 0)
    return SQLi_fail(e, SQL_IO, "open journal");
  int fd = openat(b->fd, "manifest",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  JHeader h = {MAGIC, 2, getuid()};
  if (fd < 0 || writeall(fd, &h, sizeof(h))) {
    if (fd >= 0)
      close(fd);
    SQLi_batch_abort(b);
    return SQLi_fail(e, SQL_IO, "write journal header");
  }
  close(fd);
  return 0;
}

static int destination_device(Env *e, int root, const char *path) {
  if (!sql_safe_relative(path))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid journal destination path");
  struct stat expected;
  if (fstat(root, &expected))
    return SQLi_fail(e, SQL_IO, "stat journal destination root");
  char *copy = strdup(path);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "destination allocation");
  int fd = dup(root), rc = 0;
  if (fd < 0) {
    free(copy);
    return SQLi_fail(e, SQL_IO, "pin destination root");
  }
  char *save = NULL;
  for (char *name = strtok_r(copy, "/", &save); name;
       name = strtok_r(NULL, "/", &save)) {
    struct stat st;
    if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno == ENOENT)
        break;
      rc = SQLi_fail(e, SQL_IO, "stat existing destination component");
      break;
    }
    if (st.st_dev != expected.st_dev) {
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "cross-device destination refused before decision");
      break;
    }
    if (!save || !*save)
      break;
    int next =
        openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "unsafe destination directory component");
      break;
    }
    close(fd);
    fd = next;
  }
  close(fd);
  free(copy);
  return rc;
}
/* Test-only storage-exhaustion injection (SQL_TEST_FAIL=<point>): the write
 * fails with ENOSPC exactly as a full filesystem would, before any decision. */
static int injected_enospc(const char *point) {
  const char *f = getenv("SQL_TEST_FAIL");
  if (f && !strcmp(f, point)) {
    errno = ENOSPC;
    return 1;
  }
  return 0;
}
int SQLi_batch_op(Env *e, Batch *b, char op, const char *a, const char *v) {
  if (destination_device(e, b->root, a) ||
      (op == 'T' && destination_device(e, b->root, v)))
    return -1;
  if (!sql_safe_relative(a))
    return SQLi_fail(e, SQL_CONSTRAINT, "unsafe operation path");
  if (!strcmp(a, ".table") || !strcmp(a, ".view"))
    b->schema_changed = 1; /* definition carries its own generation */
  size_t al = strlen(a), bl = v ? strlen(v) : 0;
  if (bl >= PATH_MAX)
    return SQLi_fail(e, SQL_CONSTRAINT, "operation operand too long");
  if (sql_command_data(e, b, op, a, v))
    return -1;
  JEntry ent = {(uint32_t)op, al, bl, b->count++};
  int fd =
      openat(b->fd, "manifest", O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open journal manifest");
  int rc = injected_enospc("manifest-enospc") ||
           writeall(fd, &ent, sizeof(ent)) || writeall(fd, a, al) ||
           (bl && writeall(fd, v, bl));
  int saved = errno;
  close(fd);
  return rc ? SQLi_fail(e, SQL_IO, "append journal operation: %s",
                        strerror(saved))
            : 0;
}
int SQLi_batch_put(Env *e, Batch *b, const char *path, const void *data,
                   size_t len) {
  char slot[32];
  snprintf(slot, sizeof(slot), "data.%d", b->count);
  int fd = openat(b->fd, slot,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create staged payload");
  int rc = injected_enospc("payload-enospc") || writeall(fd, data, len) ||
           fsync(fd);
  int saved = errno;
  close(fd);
  if (rc)
    return SQLi_fail(e, SQL_IO, "durable staged payload write: %s",
                     strerror(saved));
  return SQLi_batch_op(e, b, 'P', path, slot);
}
void SQLi_batch_abort(Batch *b) {
  if (b->fd >= 0) {
    struct stat st;
    if (fstatat(b->fd, "COMMIT", &st, AT_SYMLINK_NOFOLLOW)) {
      Env ignored = {0};
      SQL_Result result = {0};
      ignored.out = &result;
      cleanbatch(&ignored, b->root, b->name, b->fd);
    } else
      close(b->fd);
    b->fd = -1;
  }
}
static int apply(Env *e, int root, const char *name, int journal) {
  int fd = openat(journal, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  JHeader h;
  if (fd < 0 || readall(fd, &h, sizeof(h)) || h.magic != MAGIC ||
      (h.version != 1 && h.version != 2) || h.owner != getuid()) {
    if (fd >= 0)
      close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid or foreign journal; manual inspection required");
  }
  int rc = 0, operations = 0;
  for (;;) {
    JEntry ent;
    ssize_t z = read(fd, &ent, sizeof(ent));
    if (!z)
      break;
    if (z != sizeof(ent) || !ent.a || ent.a >= PATH_MAX || ent.b >= PATH_MAX) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "corrupt journal entry");
      break;
    }
    operations++;
    char a[PATH_MAX], v[PATH_MAX], base[NAME_MAX + 1];
    if (readall(fd, a, ent.a) || (ent.b && readall(fd, v, ent.b))) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "truncated journal");
      break;
    }
    a[ent.a] = 0;
    v[ent.b] = 0;
    int parent = sql_parentfd(e, root, a, base);
    if (parent < 0) {
      rc = -1;
      break;
    }
    struct stat st;
    switch (ent.type) {
    case 'M':
      if (mkdirat(parent, base, 0700) && errno != EEXIST)
        rc = -1;
      else if (fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) ||
               !S_ISDIR(st.st_mode))
        rc = -1;
      break;
    case 'N': /* cross-table notice: event-only, no filesystem change */
      break;
    case 'D':
      if (unlinkat(parent, base, 0) && errno != ENOENT)
        rc = -1;
      break;
    case 'R':
      if (unlinkat(parent, base, AT_REMOVEDIR) && errno != ENOENT)
        rc = -1;
      break;
    case 'T': {
      char dest[NAME_MAX + 1];
      int dp = sql_parentfd(e, root, v, dest);
      if (dp < 0) {
        rc = -1;
        break;
      }
      if (renameat(parent, base, dp, dest)) {
        if (errno != ENOENT || fstatat(dp, dest, &st, AT_SYMLINK_NOFOLLOW))
          rc = -1;
      }
      if (fsync(dp))
        rc = -1;
      close(dp);
      break;
    }
    case 'H': {
      if (h.version < 2 || strncmp(v, "data.", 5) || strchr(v, '/')) {
        rc = -1;
        break;
      }
      struct stat payload;
      if (fstatat(journal, v, &payload, AT_SYMLINK_NOFOLLOW) ||
          !S_ISREG(payload.st_mode)) {
        rc = -1;
        break;
      }
      char temp[80];
      snprintf(temp, sizeof(temp), ".sql-apply.%u", ent.slot);
      unlinkat(journal, temp, 0);
      if (linkat(journal, v, journal, temp, 0) ||
          renameat(journal, temp, parent, base) || fsync(journal))
        rc = -1;
      break;
    }
    case 'P': {
      if (strncmp(v, "data.", 5) || strchr(v, '/')) {
        rc = -1;
        if (!rc && fsync(journal))
          rc = -1;
        break;
      }
      int in = openat(journal, v, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (in < 0) {
        rc = -1;
        if (!rc && fsync(journal))
          rc = -1;
        break;
      }
      char temp[80];
      snprintf(temp, sizeof(temp), ".sql-apply.%u", ent.slot);
      unlinkat(journal, temp, 0);
      int out =
          openat(journal, temp,
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
      if (out < 0) {
        close(in);
        rc = -1;
        if (!rc && fsync(journal))
          rc = -1;
        break;
      }
      char buf[65536];
      ssize_t n;
      while ((n = read(in, buf, sizeof(buf))) > 0)
        if (writeall(out, buf, n)) {
          rc = -1;
          if (!rc && fsync(journal))
            rc = -1;
          break;
        }
      if (n < 0 || fsync(out))
        rc = -1;
      close(in);
      close(out);
      if (!rc && renameat(journal, temp, parent, base))
        rc = -1;
      if (!rc && fsync(journal))
        rc = -1;
      break;
    }
    case 'L': {
      char temp[80];
      snprintf(temp, sizeof(temp), ".sql-apply.%u", ent.slot);
      unlinkat(journal, temp, 0);
      if (symlinkat(v, journal, temp) || renameat(journal, temp, parent, base))
        rc = -1;
      if (!rc && fsync(journal))
        rc = -1;
      break;
    }
    default:
      rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid journal operation");
      break;
    }
    if (!rc && fsync(parent))
      rc = -1;
    close(parent);
    if (rc) {
      if (!e->status)
        SQLi_fail(e, SQL_IO, "apply %s: %s", a, strerror(errno));
      break;
    }
  }
  close(fd);
  if (rc)
    return -1;
  if (!operations)
    return 0;
  return sql_event_publish(e, root, journal, name);
}
int sql_batch_preview(Env *e, Batch *b, int root) {
  return apply(e, root, b->name, b->fd);
}
int sql_batch_prepare(Env *e, Batch *b) {
  if (b->count && !b->schema_changed) {
    SQL_Map map;
    if (SQLi_map_read(e, b->root, ".table", &map))
      return -1;
    if (map.generation == UINT64_MAX)
      return SQLi_fail(e, SQL_CONSTRAINT, "table generation exhausted");
    map.generation++;
    if (SQLi_batch_put(e, b, ".table", &map, sizeof(map)))
      return -1;
  }

  if (b->count && sql_fanout_plan(e, b))
    return -1;
  if (b->count && sql_event_prepare(e, b))
    return -1;
  if (b->count && sql_permission_preflight(e, b))
    return -1;
  int mf = openat(b->fd, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (mf < 0 || fsync(mf) || fsync(b->fd) || fsync(b->root)) {
    if (mf >= 0)
      close(mf);
    return SQLi_fail(e, SQL_IO, "persist transaction preparation");
  }
  close(mf);
  return 0;
}
int sql_batch_decide(Env *e, Batch *b) {
  int decision =
      openat(b->fd, "COMMIT",
             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (decision < 0) {
    if (errno == EEXIST) {
      int old = sql_regular_open(e, b->fd, "COMMIT", 0, NULL);
      if (old < 0)
        return -1;
      int rc = fsync(old);
      close(old);
      return rc || fsync(b->fd)
                 ? SQLi_fail(e, SQL_COMMITTED_PENDING,
                             "participant decision persistence uncertain")
                 : 0;
    }
    return SQLi_fail(e, SQL_IO, "commit decision create");
  }
  int rc = fsync(decision);
  close(decision);
  if (rc || fsync(b->fd))
    return SQLi_fail(e, SQL_COMMITTED_PENDING,
                     "commit durability uncertain; recover before retry");
  return 0;
}
int sql_batch_apply(Env *e, Batch *b, int keep) {
  if (apply(e, b->root, b->name, b->fd))
    return -1;
  if (!keep) {
    int rc = cleanbatch(e, b->root, b->name, b->fd);
    b->fd = -1;
    if (rc)
      return -1;
  }
  return 0;
}
int sql_batch_cleanup(Env *e, Batch *b) {
  if (b->fd < 0)
    return 0;
  int rc = cleanbatch(e, b->root, b->name, b->fd);
  b->fd = -1;
  return rc;
}
int sql_batch_reclaim(Env *e, int root, const char *id) {
  char name[80];
  snprintf(name, sizeof(name), ".sql-clean.%s", id);
  struct stat st;
  if (fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW))
    return errno == ENOENT
               ? 0
               : SQLi_fail(e, SQL_IO, "inspect retired participant journal");
  return recover_garbage(e, root, name, 1);
}
int sql_batch_begin_id(Env *e, int root, Batch *b, const char *id) {
  if (!id || strlen(id) != 32)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid coordinated batch identity");
  for (const char *p = id; *p; p++)
    if (!isxdigit((unsigned char)*p))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid coordinated batch identity");
  if (SQLi_batch_begin(e, root, b))
    return -1;
  char name[80];
  snprintf(name, sizeof(name), ".sql-txn.%s", id);
  if (renameat2(root, b->name, root, name, RENAME_NOREPLACE)) {
    SQLi_batch_abort(b);
    return SQLi_fail(e, SQL_IO, "name coordinated journal");
  }
  strcpy(b->name, name);
  return 0;
}
int sql_batch_existing(Env *e, int root, const char *id, Batch *b) {
  memset(b, 0, sizeof(*b));
  b->fd = -1;
  b->root = root;
  snprintf(b->name, sizeof(b->name), ".sql-txn.%s", id);
  b->fd =
      openat(root, b->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (b->fd < 0)
    return SQLi_fail(e, SQL_IO, "open prepared participant journal");
  return 0;
}
int sql_batch_put_file(Env *e, Batch *b, const char *path, int source) {
  char name[32], proc[64];
  snprintf(name, sizeof(name), "data.%d", b->count);
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", source);
  struct stat payload, journal;
  if (fstat(source, &payload) || !S_ISREG(payload.st_mode) ||
      fstat(b->fd, &journal) || payload.st_dev != journal.st_dev)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "cross-device payload adoption refused before decision");
  if (linkat(AT_FDCWD, proc, b->fd, name, AT_SYMLINK_FOLLOW))
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "same-filesystem staged inode adoption failed before decision: %s",
        strerror(errno));
  if (fsync(source) || fsync(b->fd))
    return SQLi_fail(e, SQL_IO, "sync adopted replay payload");
  return SQLi_batch_op(e, b, 'H', path, name);
}
int SQLi_batch_commit(Env *e, Batch *b) {
  if (!b->count) {
    SQLi_batch_abort(b);
    return 0;
  }
  if (sql_batch_prepare(e, b) || sql_preflight(e, b) || sql_batch_decide(e, b))
    return -1;
  if (sql_command_decided(e)) {
    e->status = SQL_COMMITTED_PENDING;
    return -1;
  }
  if (getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "after-decision"))
    _exit(86);
  if (sql_batch_apply(e, b, 0)) {
    e->status = SQL_COMMITTED_PENDING;
    snprintf(e->out->diagnostic, sizeof(e->out->diagnostic),
             "committed, recovery required: %s", b->name + 9);
    close(b->fd);
    b->fd = -1;
    return -1;
  }
  return 0;
}
int SQLi_pending(Env *e, int root) {
  DIR *d = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan pending journals");
  struct dirent *ent;
  int rc = 0;
  while ((ent = readdir(d)))
    if (!strncmp(ent->d_name, ".sql-txn.", 9)) {
      if (!valid_journal_name(ent->d_name)) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid journal name; preserved");
        break;
      }
      int fd = openat(root, ent->d_name,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      struct stat st;
      if (fd < 0) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid journal directory");
        break;
      }
      int coordinated = sql_coord_pending(e, fd);
      if (coordinated < 0) {
        close(fd);
        rc = -1;
        break;
      }
      if (coordinated == 2) {
        close(fd);
        continue;
      }
      int yes = coordinated || !fstatat(fd, "COMMIT", &st, AT_SYMLINK_NOFOLLOW);
      close(fd);
      if (yes) {
        rc = SQLi_fail(
            e, SQL_COMMITTED_PENDING,
            "pending committed journal %s; run sql recover TABLE . ALL APPLY",
            ent->d_name + 9);
        break;
      }
    }
  closedir(d);
  return rc;
}
int SQLi_recover(Env *e, int root, int change) {
  DIR *d = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan recovery");
  struct dirent *ent;
  int rc = 0;
  while ((ent = readdir(d)))
    if (!strncmp(ent->d_name, ".sql-clean.", 11)) {
      if (recover_garbage(e, root, ent->d_name, change)) {
        rc = -1;
        break;
      }
    } else if (!strncmp(ent->d_name, ".sql-txn.", 9)) {
      if (!valid_journal_name(ent->d_name)) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid journal name; preserved");
        break;
      }
      int fd = openat(root, ent->d_name,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (fd < 0) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid journal directory");
        break;
      }
      SQL_CoordRef ref;
      int coordinated = sql_coord_ref(e, fd, &ref);
      if (coordinated < 0) {
        close(fd);
        rc = -1;
        break;
      }
      if (coordinated) {
        fprintf(e->stream, "coordinated %s ROOT %s: use RECOVER DATABASE\n",
                ref.Txid, ref.Root);
        close(fd);
        if (change) {
          rc = SQLi_fail(
              e, SQL_CONSTRAINT,
              "participant recovery requires its coordinator DATABASE scope");
          break;
        }
        continue;
      }
      int mf = openat(fd, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      JHeader h;
      int valid = mf >= 0 && !readall(mf, &h, sizeof(h)) && h.magic == MAGIC &&
                  (h.version == 1 || h.version == 2) && h.owner == getuid();
      if (mf >= 0)
        close(mf);
      if (!valid) {
        close(fd);
        rc = SQLi_fail(e, SQL_CONSTRAINT, "refusing invalid/foreign journal");
        break;
      }
      struct stat st;
      int committed = !fstatat(fd, "COMMIT", &st, AT_SYMLINK_NOFOLLOW);
      if (!e->quiet_recovery)
        fprintf(e->stream, "%s %s\n", ent->d_name + 9,
                committed ? "finish committed" : "discard undecided");
      if (change) {
        if (committed && apply(e, root, ent->d_name, fd)) {
          close(fd);
          rc = -1;
          break;
        }
        if (cleanbatch(e, root, ent->d_name, fd)) {
          rc = -1;
          break;
        }
      } else
        close(fd);
    }
  closedir(d);
  return rc;
}
