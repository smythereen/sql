/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Cross-table shared-value event fanout.
 *
 * A committed write to an owner anchor (.sql/shared/<id>) is visible through
 * absolute symlinks in other (consumer) tables. Consumers get their own durable
 * logical UPDATE events:
 *  1. plan: the owner batch that writes anchors also writes the intention
 *     .sql/fanout/<txn> (anchor ids, one per line), atomically with the data;
 *  2. drain (after the command, with no table locks held): for each intention,
 *     each registered "link" consumer receives one notice batch of 'N' ops (one
 *     per member linking an affected anchor) plus .sql/fanin/<dev>-<ino>-<txn>,
 *     so a re-drive after a crash never duplicates; then the intention and the
 *     fanin markers are removed. Intentions left by a crash are re-driven by
 *     the next anchor write on the owner, by RECOVER, and by WATCH/TRIGGER on
 *     the owner. Delivery to consumers is at-least-once-per-intention and
 *     exactly-once per consumer. */
#include "sql_local.h"
typedef struct {
  uint32_t magic, version;
  uint64_t owner;
} Header;
typedef struct {
  uint32_t type, a, b, slot;
} Entry;
static char drains[16][PATH_MAX];
static int ndrains;
static int anchor_name(const char *a) {
  if (strncmp(a, ".sql/shared/", 12) || strlen(a) != 44)
    return 0;
  for (int i = 12; i < 44; i++)
    if (!isxdigit((unsigned char)a[i]))
      return 0;
  return 1;
}
static void remember(const char *path) {
  for (int i = 0; i < ndrains; i++)
    if (!strcmp(drains[i], path))
      return;
  if (ndrains < 16)
    snprintf(drains[ndrains++], PATH_MAX, "%s", path);
}
static int root_path(int fd, char *out) {
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, out, PATH_MAX - 1);
  if (n <= 0)
    return -1;
  out[n] = 0;
  return 0;
}
int sql_fanout_plan(Env *e, Batch *b) {
  if (sql_context_active(e) || !b->count)
    return 0; /* staged writes: the coordinator plans at COMMIT */
  int mf = openat(b->fd, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (mf < 0)
    return SQLi_fail(e, SQL_IO, "fanout manifest");
  Header h;
  char *ids = NULL;
  size_t len = 0;
  FILE *list = open_memstream(&ids, &len);
  int rc = -1, found = 0;
  if (!list || sql_read_all(mf, &h, sizeof(h))) {
    SQLi_fail(e, SQL_IO, "fanout manifest header");
    goto done;
  }
  for (;;) {
    Entry ent;
    ssize_t n = read(mf, &ent, sizeof(ent));
    if (!n)
      break;
    char a[PATH_MAX], v[PATH_MAX];
    if (n != sizeof(ent) || ent.a >= PATH_MAX || ent.b >= PATH_MAX ||
        sql_read_all(mf, a, ent.a) || sql_read_all(mf, v, ent.b)) {
      SQLi_fail(e, SQL_IO, "fanout manifest entry");
      goto done;
    }
    a[ent.a] = 0;
    if ((ent.type == 'P' || ent.type == 'H') && anchor_name(a)) {
      fprintf(list, "%s\n", a + 12);
      found = 1;
    }
  }
  if (fclose(list)) {
    list = NULL;
    SQLi_fail(e, SQL_IO, "fanout list");
    goto done;
  }
  list = NULL;
  if (!found) {
    rc = 0;
    goto done;
  }
  char **paths = NULL;
  int np = 0;
  if (sql_dep_paths_live(e, b->root, "link", &paths, &np))
    goto done;
  for (int i = 0; i < np; i++)
    free(paths[i]);
  free(paths);
  if (!np) {
    rc = 0;
    goto done;
  }
  char marker[PATH_MAX], owner[PATH_MAX];
  snprintf(marker, sizeof(marker), ".sql/fanout/%s", b->name + 9);
  if (SQLi_batch_op(e, b, 'M', ".sql", NULL) ||
      SQLi_batch_op(e, b, 'M', ".sql/fanout", NULL) ||
      SQLi_batch_put(e, b, marker, ids, len))
    goto done;
  if (!root_path(b->root, owner))
    remember(owner);
  rc = 0;
done:
  if (list)
    fclose(list);
  free(ids);
  close(mf);
  return rc;
}
static int target_of(const char *table, Member *m, char *out) {
  char path[PATH_MAX];
  if (snprintf(path, sizeof(path), "%s/%s", table, m->path) >= PATH_MAX)
    return -1;
  ssize_t n = readlink(path, out, PATH_MAX - 1);
  if (n <= 0)
    return -1;
  out[n] = 0;
  return 0;
}
/* One consumer: 0 delivered/nothing to deliver, -1 failure (retry later). */
static int notify(Env *e, const char *consumer, const char *owner,
                  const char *fanin, const char *txn, char **anchors, int na) {
  Table t;
  memset(&t, 0, sizeof(t));
  if (SQLi_table_open(e, &t, consumer, 1))
    return -1;
  if (!t.nr && SQLi_scan_table(e, &t, 0)) {
    SQLi_table_close(&t);
    return -1;
  }
  char rel[PATH_MAX];
  snprintf(rel, sizeof(rel), ".sql/fanin/%s", fanin);
  struct stat st;
  if (!fstatat(t.fd, rel, &st, AT_SYMLINK_NOFOLLOW)) {
    SQLi_table_close(&t);
    return 0;
  }
  Batch b;
  int rc = -1, ops = 0;
  if (SQLi_batch_begin(e, t.fd, &b))
    goto done;
  for (int i = 0; i < t.nr; i++)
    for (int j = 0; j < t.r[i].nm; j++) {
      Member *m = &t.r[i].m[j];
      char target[PATH_MAX];
      if (!S_ISLNK(m->st.st_mode) || target_of(t.path, m, target))
        continue;
      for (int k = 0; k < na; k++) {
        char want[PATH_MAX];
        snprintf(want, sizeof(want), "%s/.sql/shared/%s", owner, anchors[k]);
        if (!strcmp(target, want)) {
          if (SQLi_batch_op(e, &b, 'N', m->path, txn)) {
            SQLi_batch_abort(&b);
            goto done;
          }
          ops++;
          break;
        }
      }
    }
  if (!ops) {
    SQLi_batch_abort(&b);
    rc = 0;
    goto done;
  }
  if (SQLi_batch_op(e, &b, 'M', ".sql", NULL) ||
      SQLi_batch_op(e, &b, 'M', ".sql/fanin", NULL) ||
      SQLi_batch_put(e, &b, rel, txn, strlen(txn))) {
    SQLi_batch_abort(&b);
    goto done;
  }
  rc = SQLi_batch_commit(e, &b);
done:
  SQLi_table_close(&t);
  return rc;
}
int sql_fanout_drain_root(Env *e, const char *owner) {
  int root = open(owner, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root < 0)
    return 0;
  struct stat identity;
  int dir = openat(root, ".sql/fanout", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir < 0 || fstat(root, &identity)) {
    if (dir >= 0)
      close(dir);
    close(root);
    return 0;
  }
  DIR *d = fdopendir(dup(dir));
  int rc = 0;
  struct dirent *de;
  while (d && (de = readdir(d))) {
    if (strlen(de->d_name) != 32 || strspn(de->d_name, "0123456789abcdef") != 32)
      continue;
    int marker = openat(dir, de->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat ms;
    if (marker < 0)
      continue;
    /* Serialize drainers; a removed (nlink 0) intention is already done. */
    if (flock(marker, LOCK_EX | LOCK_NB) || fstat(marker, &ms) || !ms.st_nlink ||
        !S_ISREG(ms.st_mode) || ms.st_size > 65536) {
      close(marker);
      continue;
    }
    char body[65537];
    ssize_t n = pread(marker, body, ms.st_size, 0);
    if (n != ms.st_size) {
      close(marker);
      rc = -1;
      continue;
    }
    body[n] = 0;
    char *anchors[2048], *save = NULL;
    int na = 0;
    for (char *line = strtok_r(body, "\n", &save); line && na < 2048;
         line = strtok_r(NULL, "\n", &save))
      if (strlen(line) == 32)
        anchors[na++] = line;
    char **paths = NULL, fanin[512];
    int np = 0, bad = 0;
    snprintf(fanin, sizeof(fanin), "%llu-%llu-%s",
             (unsigned long long)identity.st_dev,
             (unsigned long long)identity.st_ino, de->d_name);
    if (sql_dep_paths_live(e, root, "link", &paths, &np))
      bad = 1;
    for (int i = 0; !bad && i < np; i++)
      if (notify(e, paths[i], owner, fanin, de->d_name, anchors, na))
        bad = 1;
      else if (getenv("SQL_TEST_CRASH") &&
               !strcmp(getenv("SQL_TEST_CRASH"), "fanout-after-notice"))
        _exit(97);
    if (!bad) {
      if (unlinkat(dir, de->d_name, 0) || fsync(dir))
        bad = 1;
      for (int i = 0; !bad && i < np; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/.sql/fanin/%s", paths[i], fanin);
        unlink(path); /* done: the intention no longer exists */
      }
    }
    for (int i = 0; i < np; i++)
      free(paths[i]);
    free(paths);
    close(marker);
    if (bad)
      rc = -1;
  }
  if (d)
    closedir(d);
  close(dir);
  close(root);
  return rc;
}
/* After a command: drain owners whose anchors this command changed. Failures
 * never change the committed command's status; intentions stay for re-drive. */
void sql_fanout_drain(Env *e) {
  const char *fault = getenv("SQL_TEST_CRASH");
  if (ndrains && fault && !strcmp(fault, "fanout-before-drain"))
    _exit(96);
  for (int i = 0; i < ndrains; i++) {
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    probe.session = NULL;
    probe.no_context = 1;
    probe.stream = NULL;
    if (sql_fanout_drain_root(&probe, drains[i])) {
      Trace(SQL_TRACE, "SQL fanout for %s deferred: %s", drains[i],
            ignored.diagnostic);
      if (getenv("SQL_FANOUT_DEBUG"))
        fprintf(stderr, "sql: fanout for %s deferred: %s\n", drains[i],
                ignored.diagnostic);
    }
  }
  ndrains = 0;
}
