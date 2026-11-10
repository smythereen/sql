/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
static int exists(int fd, const char *name) {
  struct stat st;
  return !fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode) &&
         st.st_size == 0;
}
static int mark(Env *e, int fd, const char *name) {
  int out = openat(fd, name,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (out < 0) {
    if (errno == EEXIST && exists(fd, name)) {
      int old = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (old < 0)
        return SQLi_fail(e, SQL_IO, "open existing decision");
      int rc = fsync(old);
      close(old);
      return rc || fsync(fd) ? SQLi_fail(e, SQL_COMMITTED_PENDING,
                                         "decision persistence uncertain")
                             : 0;
    }
    return SQLi_fail(e, SQL_IO, "create coordinator decision %s", name);
  }
  int rc = fsync(out);
  close(out);
  return rc || fsync(fd)
             ? SQLi_fail(e, SQL_COMMITTED_PENDING,
                         "coordinator decision durability uncertain")
             : 0;
}
static int same_root(int a, int b) {
  struct stat x, y;
  return !fstat(a, &x) && !fstat(b, &y) && x.st_dev == y.st_dev &&
         x.st_ino == y.st_ino;
}
static int participant_open(Env *e, int root, const char *path) {
  int fd = SQLi_open_dir(e, path);
  if (fd < 0)
    return -1;
  if (same_root(root, fd)) {
    close(fd);
    return dup(root);
  }
  if (SQLi_lockdir(e, fd, 1)) {
    close(fd);
    return -1;
  }
  return fd;
}
static int manifest_read(Env *e, int dir, SQL_CoordManifest *m) {
  struct stat st;
  int fd = sql_regular_open(e, dir, "manifest", 0, &st);
  if (fd < 0)
    return -1;
  int rc = st.st_size != sizeof(*m) || sql_read_all(fd, m, sizeof(*m));
  close(fd);
  if (rc || m->magic != SQL_COORD_MAGIC || m->version != 2 ||
      m->bytes != sizeof(*m) || m->UID != getuid() ||
      m->Count > SQL_TX_TABLES || !memchr(m->Root, 0, PATH_MAX) ||
      !memchr(m->Txid, 0, 33) || strlen(m->Txid) != 32)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid coordinator manifest");
  for (int i = 0; i < 32; i++)
    if (!isxdigit((unsigned char)m->Txid[i]))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid coordinator transaction ID");
  size_t n = strlen(m->Root);
  for (unsigned i = 0; i < m->Count; i++) {
    const char *p = m->Table[i].Path;
    if (!memchr(p, 0, PATH_MAX) || *p != '/' ||
        (strcmp(p, m->Root) && (strncmp(p, m->Root, n) || p[n] != '/')) ||
        (i && strcmp(m->Table[i - 1].Path, p) >= 0))
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "invalid/out-of-scope/unsorted participant path");
  }
  return 0;
}
int sql_coord_outcome(Env *e, int root, const char *id) {
  char name[80];
  snprintf(name, sizeof(name), ".sql-coord.%s", id);
  int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT
               ? 0
               : SQLi_fail(e, SQL_IO, "inspect coordinator outcome");
  SQL_CoordManifest *m = calloc(1, sizeof(*m));
  if (!m) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  int rc = manifest_read(e, fd, m);
  char proc[64], actual[PATH_MAX];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", root);
  ssize_t n = readlink(proc, actual, sizeof(actual) - 1);
  if (n >= 0)
    actual[n] = 0;
  if (!rc && (n < 0 || strcmp(id, m->Txid) || strcmp(actual, m->Root)))
    rc = SQLi_fail(e, SQL_CONSTRAINT, "coordinator outcome identity mismatch");
  int committed = exists(fd, "COMMIT"), done = exists(fd, "DONE"),
      aborted = exists(fd, "ABORT");
  if (!rc && ((done && !committed) || (aborted && committed)))
    rc = SQLi_fail(e, SQL_CONSTRAINT, "contradictory coordinator outcome");
  close(fd);
  free(m);
  return rc ? -1 : done ? 1 : aborted ? 2 : committed ? 3 : 0;
}
int sql_coord_ref(Env *e, int journal, SQL_CoordRef *ref) {
  struct stat st;
  if (fstatat(journal, "COORDINATOR", &st, AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT
               ? 0
               : SQLi_fail(e, SQL_IO,
                           "inspect participant coordinator reference");
  }
  int fd = sql_regular_open(e, journal, "COORDINATOR", 0, &st);
  if (fd < 0)
    return -1;
  int rc = st.st_size != sizeof(*ref) || sql_read_all(fd, ref, sizeof(*ref));
  close(fd);
  if (rc || ref->magic != SQL_COORD_MAGIC || ref->bytes != sizeof(*ref) ||
      !memchr(ref->Root, 0, PATH_MAX) || ref->Root[0] != '/' ||
      !memchr(ref->Txid, 0, 33) || strlen(ref->Txid) != 32)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid participant coordinator reference");
  for (int i = 0; i < 32; i++)
    if (!isxdigit((unsigned char)ref->Txid[i]))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid coordinator transaction ID");
  return 1;
}
int sql_coord_pending(Env *e, int journal) {
  SQL_CoordRef ref;
  int rc = sql_coord_ref(e, journal, &ref);
  if (rc <= 0)
    return rc;
  char proc[64], location[PATH_MAX];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", journal);
  ssize_t length = readlink(proc, location, sizeof(location) - 1);
  if (length < 0)
    return SQLi_fail(e, SQL_IO, "resolve participant scope");
  location[length] = 0;
  size_t scope = strlen(ref.Root);
  if (strncmp(location, ref.Root, scope) || location[scope] != '/')
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "coordinator reference is outside participant ancestry");
  int root = SQLi_open_dir(e, ref.Root);
  if (root < 0)
    return -1;
  if (sql_root_check(e, root)) {
    close(root);
    return -1;
  }
  char name[80];
  snprintf(name, sizeof(name), ".sql-coord.%s", ref.Txid);
  int dir = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  close(root);
  if (dir < 0)
    return SQLi_fail(
        e, SQL_COMMITTED_PENDING,
        "participant references missing coordinator journal; do not discard");
  int done = exists(dir, "DONE") || exists(dir, "ABORT");
  close(dir);
  return done ? 2 : 1;
}
int sql_coord_attach(Env *e, Batch *b, SQL_Session *s) {
  SQL_CoordRef ref = {.magic = SQL_COORD_MAGIC, .bytes = sizeof(ref)};
  strcpy(ref.Root, s->map.Root);
  strcpy(ref.Txid, s->map.Txid);
  int fd = openat(b->fd, "COORDINATOR",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "attach participant coordinator reference");
  int rc = sql_write_all(fd, &ref, sizeof(ref)) || fsync(fd);
  close(fd);
  return rc || fsync(b->fd)
             ? SQLi_fail(e, SQL_IO, "persist participant coordinator reference")
             : 0;
}
static int recover_one(Env *e, int root, const char *name, int change,
                       int *outcome) {
  int dir = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0)
    return SQLi_fail(e, SQL_IO, "open coordinator recovery journal");
  SQL_CoordManifest *m = calloc(1, sizeof(*m));
  if (!m) {
    close(dir);
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  int fds[SQL_TX_TABLES];
  Batch batches[SQL_TX_TABLES];
  for (int i = 0; i < SQL_TX_TABLES; i++) {
    fds[i] = -1;
    batches[i] = (Batch){.fd = -1};
  }
  int rc = -1;
  if (manifest_read(e, dir, m))
    goto done;
  char rootlink[64], actual[PATH_MAX];
  snprintf(rootlink, sizeof(rootlink), "/proc/self/fd/%d", root);
  ssize_t rootlen = readlink(rootlink, actual, sizeof(actual) - 1);
  if (rootlen < 0) {
    SQLi_fail(e, SQL_IO, "resolve recovery scope");
    goto done;
  }
  actual[rootlen] = 0;
  if (strcmp(actual, m->Root)) {
    SQLi_fail(e, SQL_CONSTRAINT, "coordinator manifest scope mismatch");
    goto done;
  }

  if (strncmp(name, ".sql-coord.", 11) || strcmp(name + 11, m->Txid)) {
    SQLi_fail(e, SQL_CONSTRAINT, "coordinator directory/transaction mismatch");
    goto done;
  }
  int committed = exists(dir, "COMMIT"), finished = exists(dir, "DONE"),
      aborted = exists(dir, "ABORT");
  if ((finished && !committed) || (aborted && (finished || committed))) {
    SQLi_fail(e, SQL_CONSTRAINT, "contradictory coordinator decisions");
    goto done;
  }
  if (outcome)
    *outcome =
        finished || committed ? SQL_OUTCOME_COMMITTED : SQL_OUTCOME_ROLLED_BACK;
  if (!e->quiet_recovery)
    fprintf(e->stream, "%s %s\n", m->Txid,
            finished    ? "committed/done"
            : committed ? "finish committed coordinator"
                        : "discard undecided coordinator");
  if (!change) {
    rc = 0;
    goto done;
  }
  for (unsigned i = 0; i < m->Count; i++) {
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    fds[i] = participant_open((finished || aborted) ? &probe : e, root,
                              m->Table[i].Path);
    if (fds[i] < 0) {
      if ((finished || aborted) && errno == ENOENT)
        continue;
      if (finished || aborted)
        SQLi_fail(e, probe.status, "%s", ignored.diagnostic);
      goto done;
    }
    struct stat identity;
    if (fstat(fds[i], &identity) || identity.st_dev != m->Table[i].Device ||
        identity.st_ino != m->Table[i].Inode) {
      if (finished || aborted) {
        close(fds[i]);
        fds[i] = -1;
        continue;
      }
      SQLi_fail(e, SQL_CONSTRAINT,
                "participant directory identity changed; refusing recovery");
      goto done;
    }
    if ((finished || aborted) && sql_batch_reclaim(e, fds[i], m->Txid))
      goto done;
    char journal[80];
    snprintf(journal, sizeof(journal), ".sql-txn.%s", m->Txid);
    struct stat st;
    if (fstatat(fds[i], journal, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno == ENOENT && (!committed || finished))
        continue;
      SQLi_fail(e, SQL_COMMITTED_PENDING,
                "committed participant journal missing; do not guess outcome");
      goto done;
    }
    if (sql_batch_existing(e, fds[i], m->Txid, &batches[i]))
      goto done;
    SQL_CoordRef ref;
    int linked = sql_coord_ref(e, batches[i].fd, &ref);
    if (linked < 0)
      goto done;
    if (linked && (strcmp(ref.Txid, m->Txid) || strcmp(ref.Root, m->Root))) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "participant transaction reference mismatch");
      goto done;
    }
    if (!committed && exists(batches[i].fd, "COMMIT")) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "undecided coordinator has a participant commit marker; manual "
                "inspection required");
      goto done;
    }
  }
  if (committed && !finished) {
    for (unsigned i = 0; i < m->Count; i++)
      if (batches[i].fd >= 0) {
        if (sql_batch_decide(e, &batches[i]) ||
            sql_batch_apply(e, &batches[i], 1))
          goto committed_error;
      }
    if (mark(e, dir, "DONE"))
      goto committed_error;
  }
  if (!committed && mark(e, dir, "ABORT"))
    goto done;
  for (unsigned i = 0; i < m->Count; i++)
    if (batches[i].fd >= 0)
      if (sql_batch_cleanup(e, &batches[i]))
        goto done;

  rc = 0;
  goto done;
committed_error:
  e->status = SQL_COMMITTED_PENDING;
  snprintf(e->out->diagnostic, sizeof(e->out->diagnostic),
           "coordinator %s is committed but needs recovery; never roll it back",
           m->Txid);
done:
  for (int i = 0; i < SQL_TX_TABLES; i++) {
    if (batches[i].fd >= 0)
      close(batches[i].fd);
    if (fds[i] >= 0)
      close(fds[i]);
  }
  if (dir >= 0)
    close(dir);
  free(m);
  return rc;
}
int sql_coord_recover(Env *e, int root, const char *path, int change,
                      const char *id, int *outcome) {
  (void)path;
  if (SQLi_lockdir(e, root, 1) || sql_root_check(e, root))
    return -1;
  if (id) {
    char name[80];
    snprintf(name, sizeof(name), ".sql-coord.%s", id);
    return recover_one(e, root, name, change, outcome);
  }
  DIR *d = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan coordinator journals");
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d)))
    if (!strncmp(de->d_name, ".sql-coord.", 11)) {
      if (recover_one(e, root, de->d_name, change, NULL)) {
        rc = -1;
        break;
      }
    }
  closedir(d);
  return rc;
}
static int entry_order(const void *a, const void *b) {
  return strcmp(((const SQL_ContextEntry *)a)->Path,
                ((const SQL_ContextEntry *)b)->Path);
}
int sql_coord_commit(Env *e, SQL_Session *s) {
  if (SQLi_lockdir(e, s->root, 1) || sql_root_check(e, s->root))
    return -1;
  char name[80];
  snprintf(name, sizeof(name), ".sql-coord.%s", s->map.Txid);
  struct stat existing;
  if (!fstatat(s->root, name, &existing, AT_SYMLINK_NOFOLLOW)) {
    int outcome = 0;
    int quiet = e->quiet_recovery;
    e->quiet_recovery = 1;
    int recovered = recover_one(e, s->root, name, 1, &outcome);
    e->quiet_recovery = quiet;
    if (recovered)
      return -1;
    if (outcome == SQL_OUTCOME_COMMITTED) {
      s->map.State = SQL_CTX_IDLE;
      s->map.Outcome = SQL_OUTCOME_COMMITTED;
      return sql_ctx_save(e, s);
    }
    s->map.State = SQL_CTX_ACTIVE;
    if (sql_ctx_save(e, s))
      return -1;
    if (sql_tree_remove(e, s->root, name) || fsync(s->root))
      return SQLi_fail(e, SQL_IO, "retire aborted commit attempt");
  }
  if (s->map.State == SQL_CTX_COMMITTING)
    return SQLi_fail(e, SQL_COMMITTED_PENDING,
                     "committing context lost its coordinator journal; do not "
                     "guess a new decision");
  SQL_CoordManifest *m = calloc(1, sizeof(*m));
  if (!m)
    return SQLi_fail(e, SQL_IO, "out of memory");
  m->magic = SQL_COORD_MAGIC;
  m->version = 2;
  m->bytes = sizeof(*m);
  m->UID = getuid();
  m->Count = s->map.Count;
  strcpy(m->Txid, s->map.Txid);
  strcpy(m->Root, s->map.Root);
  memcpy(m->Table, s->map.Table, s->map.Count * sizeof(SQL_ContextEntry));
  qsort(m->Table, m->Count, sizeof(SQL_ContextEntry), entry_order);
  int fds[SQL_TX_TABLES], stages[SQL_TX_TABLES];
  Batch batches[SQL_TX_TABLES];
  for (int i = 0; i < SQL_TX_TABLES; i++) {
    fds[i] = stages[i] = -1;
    batches[i] = (Batch){.fd = -1};
  }
  int dir = -1, stage = -1, rc = -1, decided = 0, created = 0;
  stage = sql_stage_root(e, s, 1);
  if (stage < 0)
    goto done;
  for (unsigned i = 0; i < m->Count; i++) {
    fds[i] = participant_open(e, s->root, m->Table[i].Path);
    if (fds[i] < 0)
      goto done;
    struct stat identity;
    uint64_t generation;
    if (fstat(fds[i], &identity) || identity.st_dev != m->Table[i].Device ||
        identity.st_ino != m->Table[i].Inode || SQLi_pending(e, fds[i]) ||
        sql_object_generation_or_none(e, fds[i], &generation))
      goto done;
    if (generation != m->Table[i].Generation) {
      s->map.Outcome = SQL_OUTCOME_CONFLICT;
      SQLi_fail(
          e, SQL_CONSTRAINT,
          "transaction conflict: %s generation changed; rollback and retry",
          m->Table[i].Path);
      goto done;
    }
    unsigned index = 0;
    while (index < s->map.Count &&
           strcmp(m->Table[i].Path, s->map.Table[index].Path))
      index++;
    char slot[32];
    snprintf(slot, sizeof(slot), "%u", index);
    stages[i] =
        openat(stage, slot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    e->coordinating = 1;
    int invalid =
        stages[i] < 0 || sql_snapshot_validate(e, stages[i], m->Table[i].Path);
    e->coordinating = 0;
    if (invalid)
      goto done;
  }
  if (mkdirat(s->root, name, 0700)) {
    SQLi_fail(e, SQL_IO, "create coordinator journal");
    goto done;
  }
  created = 1;
  dir = openat(s->root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0) {
    SQLi_fail(e, SQL_IO, "open coordinator journal");
    goto done;
  }
  int mf = openat(dir, "manifest",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (mf < 0) {
    SQLi_fail(e, SQL_IO, "create coordinator manifest");
    goto done;
  }
  int failed = sql_write_all(mf, m, sizeof(*m)) || fsync(mf);
  close(mf);
  if (failed || fsync(dir) || fsync(s->root)) {
    SQLi_fail(e, SQL_IO, "persist coordinator preparation");
    goto done;
  }
  s->map.State = SQL_CTX_COMMITTING;
  if (sql_ctx_save(e, s))
    goto done;
  for (unsigned i = 0; i < m->Count; i++)
    if (sql_batch_begin_id(e, fds[i], &batches[i], m->Txid) ||
        sql_tree_diff(e, fds[i], stages[i], "", &batches[i],
                      m->Table[i].Generation) ||
        sql_coord_attach(e, &batches[i], s) ||
        sql_batch_prepare(e, &batches[i]))
      goto done;
  if (getenv("SQL_TEST_FAIL") &&
      !strcmp(getenv("SQL_TEST_FAIL"), "coordinator-participant-prepare")) {
    SQLi_fail(e, SQL_IO, "injected participant preparation I/O failure");
    goto done;
  }
  const char *fault = getenv("SQL_TEST_CRASH");
  if (fault && !strcmp(fault, "coordinator-before-decision"))
    _exit(87);
  if (mark(e, dir, "COMMIT")) {
    decided = 1;
    goto done;
  }
  decided = 1;
  if (sql_command_decided(e))
    goto done;
  if (fault && !strcmp(fault, "coordinator-after-decision"))
    _exit(88);
  for (unsigned i = 0; i < m->Count; i++) {
    if (sql_batch_decide(e, &batches[i]) || sql_batch_apply(e, &batches[i], 1))
      goto done;
    if (i == 0 && fault && !strcmp(fault, "coordinator-after-first-apply"))
      _exit(89);
  }
  if (mark(e, dir, "DONE"))
    goto done;
  if (fault && !strcmp(fault, "coordinator-after-done"))
    _exit(90);
  for (unsigned i = 0; i < m->Count; i++)
    if (sql_batch_cleanup(e, &batches[i]))
      goto done;
  s->map.State = SQL_CTX_IDLE;
  s->map.Outcome = SQL_OUTCOME_COMMITTED;
  if (sql_ctx_save(e, s))
    goto done;
  rc = 0;
done:
  if (rc && decided) {
    e->status = SQL_COMMITTED_PENDING;
    snprintf(e->out->diagnostic, sizeof(e->out->diagnostic),
             "transaction %s durably decided or uncertain; recover "
             "coordinator, never assume rollback",
             s->map.Txid);
  }
  if (rc && !decided) {
    Env cleanup = *e;
    SQL_Result ignored = {0};
    cleanup.out = &ignored;
    cleanup.status = 0;
    int prepared = created && s->map.State == SQL_CTX_COMMITTING;
    int safe = !prepared || !mark(&cleanup, dir, "ABORT");
    if (safe) {
      for (unsigned i = 0; i < m->Count; i++)
        if (batches[i].fd >= 0)
          SQLi_batch_abort(&batches[i]);
      if (created && !prepared) {
        if (dir >= 0) {
          close(dir);
          dir = -1;
        }
        sql_tree_remove(&cleanup, s->root, name);
        fsync(s->root);
      }
      /* Prepared journals retain their ABORT manifest even if cleanup failed.
         Recovery can never encounter an orphan coordinator reference. */
      s->map.State = SQL_CTX_ACTIVE;
      sql_ctx_save(&cleanup, s);
    } else {
      e->status = SQL_COMMITTED_PENDING;
      snprintf(e->out->diagnostic, sizeof(e->out->diagnostic),
               "predecision preparation needs coordinator recovery; no "
               "rollback outcome was assumed");
    }
  }
  for (int i = 0; i < SQL_TX_TABLES; i++) {
    if (batches[i].fd >= 0)
      close(batches[i].fd);
    if (fds[i] >= 0)
      close(fds[i]);
    if (stages[i] >= 0)
      close(stages[i]);
  }
  if (dir >= 0)
    close(dir);
  if (stage >= 0)
    close(stage);
  free(m);
  return rc;
}
int sql_transactions_list(Env *e, Parser *p) {
  if (SQLi_need(e, p, "ON"))
    return -1;
  char *path = take(e, p);
  if (!path || SQLi_end(e, p))
    return -1;
  int root = SQLi_open_dir(e, path);
  if (root < 0)
    return -1;
  if (sql_root_check(e, root) || SQLi_lockdir(e, root, 0)) {
    close(root);
    return -1;
  }
  DIR *d = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d) {
    close(root);
    return SQLi_fail(e, SQL_IO, "scan transaction manifests");
  }
  int rc = 0;
  struct dirent *de;
  SQL_CoordManifest *m = malloc(sizeof(*m));
  if (!m) {
    closedir(d);
    close(root);
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  while ((de = readdir(d))) {
    if (strncmp(de->d_name, ".sql-coord.", 11))
      continue;
    int fd = openat(root, de->d_name,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || manifest_read(e, fd, m)) {
      if (fd >= 0)
        close(fd);
      rc = -1;
      break;
    }
    if (strcmp(de->d_name + 11, m->Txid)) {
      close(fd);
      rc = SQLi_fail(e, SQL_CONSTRAINT, "transaction manifest name mismatch");
      break;
    }
    int committed = exists(fd, "COMMIT"), done = exists(fd, "DONE"),
        aborted = exists(fd, "ABORT");
    close(fd);
    if ((done && !committed) || (aborted && committed)) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "contradictory transaction outcome");
      break;
    }
    fprintf(e->stream,
            "{\"transaction\":\"%s\",\"source\":\"coordinator\",\"state\":\"%"
            "s\",\"participants\":%u}\n",
            m->Txid,
            done        ? "applied"
            : committed ? "commit_decided"
            : aborted   ? "aborted"
                        : "prepared",
            m->Count);
  }
  closedir(d);
  free(m);
  if (!rc) {
    int registry = sql_registry(e, root, 0);
    if (registry < 0)
      rc = -1;
    else {
      DIR *contexts =
          fdopendir(openat(registry, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
      if (!contexts)
        rc = SQLi_fail(e, SQL_IO, "scan staged transactions");
      else {
        while ((de = readdir(contexts))) {
          if (de->d_name[0] == '.')
            continue;
          char rel[NAME_MAX + 32], handle[PATH_MAX];
          snprintf(rel, sizeof(rel), ".context/%s", de->d_name);
          if (SQLi_joinpath(e, handle, path, rel)) {
            rc = -1;
            break;
          }
          SQL_Session *s = malloc(sizeof(*s));
          if (!s) {
            rc = SQLi_fail(e, SQL_IO, "out of memory");
            break;
          }
          Env probe = *e;
          SQL_Result ignored = {0};
          probe.out = &ignored;
          probe.status = 0;
          if (sql_workspace_open(&probe, handle, s, 1, 1)) {
            int busy = errno == EWOULDBLOCK || errno == EAGAIN;
            sql_workspace_close(s);
            free(s);
            if (busy) {
              fputs("{\"context\":", e->stream);
              SQLi_json(e->stream, (unsigned char *)handle, strlen(handle));
              fputs(",\"busy\":true}\n", e->stream);
              continue;
            }
            rc = SQLi_fail(e, probe.status, "%s", ignored.diagnostic);
            break;
          }
          char journal[80];
          snprintf(journal, sizeof(journal), ".sql-coord.%s", s->map.Txid);
          struct stat st;
          if (s->map.State != SQL_CTX_IDLE && *s->map.Txid &&
              fstatat(root, journal, &st, AT_SYMLINK_NOFOLLOW) &&
              errno == ENOENT) {
            fprintf(e->stream,
                    "{\"transaction\":\"%s\",\"source\":\"context\",\"state\":"
                    "\"staged\",\"participants\":%u,\"context\":",
                    s->map.Txid, s->map.Count);
            SQLi_json(e->stream, (unsigned char *)s->path, strlen(s->path));
            fputs("}\n", e->stream);
          }
          sql_workspace_close(s);
          free(s);
        }
        closedir(contexts);
      }
      close(registry);
    }
  }
  close(root);
  return rc;
}
