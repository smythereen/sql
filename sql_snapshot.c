/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
/* Only engine-owned transaction/coordinator metadata and committed event logs
 * are excluded. Unmanaged ordinary data is preserved in snapshots and diffs. */
int sql_tree_excluded(const char *path, const char *name) {
  if (!strcmp(name, ".") || !strcmp(name, ".."))
    return 1;
  if (!*path &&
      (!strcmp(name, ".sql-root") || !strcmp(name, ".context") ||
       !strncmp(name, ".context_", 9) || !strncmp(name, ".sql-context.", 13) ||
       !strncmp(name, ".sql-coord.", 11) || !strncmp(name, ".sql-clean.", 11) ||
       !strncmp(name, ".sql-txn.", 9) || !strncmp(name, ".sql-map.", 9)))
    return 1;
  return !strcmp(path, ".sql") &&
         (!strcmp(name, "events") || !strcmp(name, ".triggers") ||
          !strcmp(name, "deps") || !strcmp(name, "refs") ||
          !strcmp(name, "ids") || !strcmp(name, "fanout") ||
          !strcmp(name, "fanin") ||
          (!strncmp(name, "watch.", 6) && strlen(name) == 38));
}
static int copy_stream(Env *e, int in, int out) {
  unsigned char buf[65536];
  for (;;) {
    ssize_t n = read(in, buf, sizeof(buf));
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0)
      return SQLi_fail(e, SQL_IO, "snapshot read: %s", strerror(errno));
    if (!n)
      break;
    if (sql_write_all(out, buf, n))
      return SQLi_fail(e, SQL_IO, "snapshot write: %s", strerror(errno));
  }
  return 0;
}
int sql_tree_remove(Env *e, int parent, const char *name) {
  struct stat st;
  if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT
               ? 0
               : SQLi_fail(e, SQL_IO, "inspect owned staging entry");
  }
  if (!S_ISDIR(st.st_mode))
    return unlinkat(parent, name, 0)
               ? SQLi_fail(e, SQL_IO, "remove owned staging file")
               : 0;
  int fd =
      openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open owned staging directory");
  DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY));
  if (!d) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "scan staging cleanup");
  }
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;
    if (sql_tree_remove(e, fd, de->d_name)) {
      rc = -1;
      break;
    }
  }
  closedir(d);
  close(fd);
  if (!rc && unlinkat(parent, name, AT_REMOVEDIR))
    rc = SQLi_fail(e, SQL_IO, "remove owned staging directory");
  return rc;
}
int sql_tree_copy(Env *e, int source, int dest, const char *path) {
  DIR *d = fdopendir(openat(source, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan snapshot source");
  struct dirent *de;
  int rc = 0;
  while ((de = readdir(d))) {
    char *name = de->d_name;
    if (sql_tree_excluded(path, name))
      continue;
    struct stat st;
    if (fstatat(source, name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat snapshot entry");
      break;
    }
    char rel[PATH_MAX];
    if (SQLi_joinpath(e, rel, path, name)) {
      rc = -1;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      if (mkdirat(dest, name, 0700)) {
        rc = SQLi_fail(e, SQL_IO, "create snapshot directory");
        break;
      }
      int in = openat(source, name,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
          out = openat(dest, name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (in < 0 || out < 0) {
        if (in >= 0)
          close(in);
        if (out >= 0)
          close(out);
        rc = SQLi_fail(e, SQL_IO, "open snapshot directory");
        break;
      }
      rc = sql_tree_copy(e, in, out, rel);
      close(in);
      close(out);
      if (rc)
        break;
    } else if (S_ISREG(st.st_mode)) {
      int in = sql_regular_open(e, source, name, 0, NULL),
          out = openat(dest, name,
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                       0600);
      if (in < 0 || out < 0) {
        if (in >= 0)
          close(in);
        if (out >= 0)
          close(out);
        rc = SQLi_fail(e, SQL_IO, "open snapshot file");
        break;
      }
      rc = copy_stream(e, in, out);
      struct timespec times[2] = {st.st_atim, st.st_mtim};
      if (!rc && (fchmod(out, st.st_mode & 0777) || futimens(out, times) ||
                  fsync(out)))
        rc = SQLi_fail(e, SQL_IO, "persist snapshot metadata");
      close(in);
      close(out);
      if (rc)
        break;
    } else if (S_ISLNK(st.st_mode)) {
      char target[PATH_MAX];
      ssize_t n = readlinkat(source, name, target, sizeof(target) - 1);
      if (n < 0 || n == (ssize_t)sizeof(target) - 1) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "snapshot link target too long");
        break;
      }
      target[n] = 0;
      if (symlinkat(target, dest, name)) {
        rc = SQLi_fail(e, SQL_IO, "copy symbolic snapshot entry");
        break;
      }
    } else {
      rc =
          SQLi_fail(e, SQL_CONSTRAINT,
                    "transaction snapshot refuses non-regular/special entries; "
                    "metadata-only autocommit reads remain available");
      break;
    }
  }
  closedir(d);
  if (!rc && fsync(dest))
    rc = SQLi_fail(e, SQL_IO, "persist snapshot directory");
  return rc;
}
int sql_stage_root(Env *e, SQL_Session *s, int create) {
  if (create && mkdirat(s->workspace, "tables", 0700) && errno != EEXIST)
    return SQLi_fail(e, SQL_IO, "create context-owned tables");
  int fd = openat(s->workspace, "tables",
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open context-owned tables");
  if (fstat(fd, &st) || st.st_uid != getuid() || (st.st_mode & 0077)) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "unsafe context tables");
  }
  return fd;
}
/* 1 when the active transaction already staged a .view for this path
 * (created inside the transaction), else 0. */
int sql_session_staged_view(Env *e, const char *path) {
  if (e->no_context || !e->session ||
      e->session->map.State != SQL_CTX_ACTIVE)
    return 0;
  SQL_Session *s = e->session;
  for (unsigned i = 0; i < s->map.Count; i++)
    if (!strcmp(path, s->map.Table[i].Path)) {
      int stage = sql_stage_root(e, s, 0);
      if (stage < 0) {
        e->status = 0;
        return 0;
      }
      char slot[32];
      snprintf(slot, sizeof(slot), "%u/.view", i);
      struct stat st;
      int found = !fstatat(stage, slot, &st, AT_SYMLINK_NOFOLLOW);
      close(stage);
      return found;
    }
  return 0;
}
int sql_session_route(Env *e, Table *t, int writeable) {
  if (e->no_context || !e->session)
    return 0;
  SQL_Session *s = e->session;
  if (s->map.State == SQL_CTX_COMMITTING)
    return SQLi_fail(e, SQL_COMMITTED_PENDING,
                     "context has an interrupted commit; run COMMIT again or "
                     "RECOVER DATABASE");
  if (s->map.State != SQL_CTX_ACTIVE)
    return 0;
  if (writeable && s->map.ReadOnly)
    return SQLi_fail(e, SQL_CONSTRAINT, "read-only transaction cannot write");
  size_t rootlen = strlen(s->map.Root);
  if (strcmp(t->path, s->map.Root) &&
      (strncmp(t->path, s->map.Root, rootlen) || t->path[rootlen] != '/'))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "table is outside the explicit coordinator scope");
  unsigned index = s->map.Count;
  for (unsigned i = 0; i < s->map.Count; i++)
    if (!strcmp(t->path, s->map.Table[i].Path)) {
      index = i;
      break;
    }
  int stage = sql_stage_root(e, s, 1);
  if (stage < 0)
    return -1;
  char slot[32];
  snprintf(slot, sizeof(slot), "%u", index);
  if (index == s->map.Count) {
    uint64_t generation;
    struct stat identity;
    if (SQLi_pending(e, t->fd) ||
        (e->route_new ? sql_object_generation_or_none(e, t->fd, &generation)
                      : sql_object_generation(e, t->fd, &generation)) ||
        fstat(t->fd, &identity)) {
      close(stage);
      return -1;
    }
    for (unsigned i = 0; i < s->map.Count; i++) {
      const char *other = s->map.Table[i].Path;
      size_t a = strlen(other), b = strlen(t->path);
      if ((!strncmp(other, t->path, b) && other[b] == '/') ||
          (!strncmp(t->path, other, a) && t->path[a] == '/')) {
        close(stage);
        return SQLi_fail(
            e, SQL_CONSTRAINT,
            "overlapping table roots cannot participate in one transaction");
      }
    }

    if (index >= SQL_TX_TABLES) {
      close(stage);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "maximum 16 participant tables per transaction");
    }
    char preparing[40];
    snprintf(preparing, sizeof(preparing), "%u.pending", index);
    if (sql_tree_remove(e, stage, preparing) ||
        sql_tree_remove(e, stage, slot)) {
      close(stage);
      return -1;
    }
    if (mkdirat(stage, preparing, 0700)) {
      close(stage);
      return SQLi_fail(e, SQL_IO, "create table snapshot");
    }
    int copy = openat(stage, preparing,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0) {
      close(stage);
      return SQLi_fail(e, SQL_IO, "open table snapshot");
    }
    struct stat stage_identity;
    if (fstat(copy, &stage_identity) ||
        stage_identity.st_dev != identity.st_dev) {
      close(copy);
      close(stage);
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "cross-device context tables unsupported before decision");
    }
    int rc = sql_tree_copy(e, t->fd, copy, "");
    close(copy);
    if (rc) {
      close(stage);
      return -1;
    }
    if (renameat(stage, preparing, stage, slot) || fsync(stage) ||
        fsync(s->root)) {
      close(stage);
      return SQLi_fail(e, SQL_IO, "publish durable table snapshot");
    }
    SQL_ContextEntry *entry = &s->map.Table[index];
    strcpy(entry->Path, t->path);
    entry->Generation = generation;
    entry->Device = identity.st_dev;
    entry->Inode = identity.st_ino;
    s->map.Count++;
    if (sql_ctx_save(e, s)) {
      close(stage);
      return -1;
    }
  }
  int fd = openat(stage, slot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  close(stage);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open transaction table snapshot");
  e->participant = index;
  t->live_root = t->fd;
  t->has_live_root = 1;
  t->fd = fd;
  return 1;
}
static int same_file(Env *e, int a, int b, const char *name, int *same) {
  int x = sql_regular_open(e, a, name, 0, NULL);
  if (x < 0)
    return -1;
  int y = sql_regular_open(e, b, name, 0, NULL);
  if (y < 0) {
    close(x);
    return -1;
  }
  unsigned char p[65536], q[65536];
  *same = 1;
  int rc = 0;
  for (;;) {
    ssize_t nx = read(x, p, sizeof(p)), ny = read(y, q, sizeof(q));
    if (nx < 0 || ny < 0) {
      rc = SQLi_fail(e, SQL_IO, "compare snapshot files");
      break;
    }
    if (nx != ny || (nx && memcmp(p, q, nx))) {
      *same = 0;
      break;
    }
    if (!nx)
      break;
  }
  close(x);
  close(y);
  return rc;
}
static int delete_tree(Env *e, int fd, const char *path, Batch *b) {
  DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan removed transaction directory");
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d))) {
    if (sql_tree_excluded(path, de->d_name))
      continue;
    char rel[PATH_MAX];
    struct stat st;
    if (SQLi_joinpath(e, rel, path, de->d_name) ||
        fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "inspect removed entry");
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      int sub = openat(fd, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0) {
        rc = SQLi_fail(e, SQL_IO, "open removed directory");
        break;
      }
      rc = delete_tree(e, sub, rel, b);
      close(sub);
      if (!rc)
        rc = SQLi_batch_op(e, b, 'R', rel, NULL);
    } else
      rc = SQLi_batch_op(e, b, 'D', rel, NULL);
    if (rc)
      break;
  }
  closedir(d);
  return rc;
}
int sql_tree_diff(Env *e, int original, int snapshot, const char *path,
                  Batch *batch, uint64_t generation) {
  DIR *d = fdopendir(openat(snapshot, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan final snapshot");
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d))) {
    char *name = de->d_name;
    if (sql_tree_excluded(path, name))
      continue;
    char rel[PATH_MAX];
    if (SQLi_joinpath(e, rel, path, name)) {
      rc = -1;
      break;
    }
    struct stat st, old;
    int exists =
        original >= 0 && !fstatat(original, name, &old, AT_SYMLINK_NOFOLLOW);
    if (fstatat(snapshot, name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat final snapshot");
      break;
    }
    if (exists && ((st.st_mode & S_IFMT) != (old.st_mode & S_IFMT))) {
      if (S_ISDIR(old.st_mode)) {
        int sub = openat(original, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub < 0) {
          rc = SQLi_fail(e, SQL_IO, "open replaced directory");
          break;
        }
        rc = delete_tree(e, sub, rel, batch);
        close(sub);
        if (!rc)
          rc = SQLi_batch_op(e, batch, 'R', rel, NULL);
      } else
        rc = SQLi_batch_op(e, batch, 'D', rel, NULL);
      exists = 0;
      if (rc)
        break;
    }
    if (S_ISDIR(st.st_mode)) {
      if (!exists && SQLi_batch_op(e, batch, 'M', rel, NULL)) {
        rc = -1;
        break;
      }
      int oldfd = exists
                      ? openat(original, name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                      : -1,
          sub = openat(snapshot, name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0 || (exists && oldfd < 0)) {
        if (sub >= 0)
          close(sub);
        if (oldfd >= 0)
          close(oldfd);
        rc = SQLi_fail(e, SQL_IO, "open final snapshot directory");
        break;
      }
      rc = sql_tree_diff(e, oldfd, sub, rel, batch, generation);
      if (oldfd >= 0)
        close(oldfd);
      close(sub);
      if (rc)
        break;
    } else if (S_ISREG(st.st_mode)) {
      /* Trace is live configuration, not staged logical data. Merge the
       * currently locked physical word and ignore Trace-only differences. */
      if (!*path && !strcmp(name, ".table")) {
        SQL_Map map, live;
        if (!exists) { /* transactional CREATE/DEFINE TABLE */
          if (SQLi_map_read(e, snapshot, name, &map)) {
            rc = -1;
            break;
          }
          map.generation = 1;
          rc = SQLi_batch_put(e, batch, rel, &map, sizeof(map));
          if (rc)
            break;
          continue;
        }
        if (SQLi_map_read(e, snapshot, name, &map) ||
            SQLi_map_read(e, original, name, &live)) {
          rc = -1;
          break;
        }
        map.TraceLevel = live.TraceLevel;
        if (!memcmp(&map, &live, sizeof(map)))
          continue;
        if (generation == UINT64_MAX) {
          rc = SQLi_fail(e, SQL_CONSTRAINT,
                         "table generation exhausted at coordinated commit");
          break;
        }
        map.generation = generation + 1;
        rc = SQLi_batch_put(e, batch, rel, &map, sizeof(map));
      } else if (!*path && !strcmp(name, ".view")) {
        SQL_ViewMap map, live;
        if (!exists) { /* transactional CREATE VIEW */
          if (sql_view_read(e, snapshot, &map)) {
            rc = -1;
            break;
          }
          map.generation = 1;
          rc = SQLi_batch_put(e, batch, rel, &map, sizeof(map));
          if (rc)
            break;
          continue;
        }
        if (sql_view_read(e, snapshot, &map) ||
            sql_view_read(e, original, &live)) {
          rc = -1;
          break;
        }
        map.TraceLevel = live.TraceLevel;
        if (!memcmp(&map, &live, sizeof(map)))
          continue;
        if (generation == UINT64_MAX) {
          rc = SQLi_fail(e, SQL_CONSTRAINT,
                         "view generation exhausted at coordinated commit");
          break;
        }
        map.generation = generation + 1;
        rc = SQLi_batch_put(e, batch, rel, &map, sizeof(map));
      } else {
        int equal = 0;
        if (exists && st.st_size == old.st_size &&
            same_file(e, original, snapshot, name, &equal)) {
          rc = -1;
          break;
        }
        if (equal)
          continue;
        int fd = sql_regular_open(e, snapshot, name, 0, NULL);
        if (fd < 0) {
          rc = -1;
          break;
        }
        rc = sql_batch_put_file(e, batch, rel, fd);
        close(fd);
      }
      if (rc)
        break;
    } else if (S_ISLNK(st.st_mode)) {
      char target[PATH_MAX], before[PATH_MAX];
      ssize_t n = readlinkat(snapshot, name, target, sizeof(target) - 1);
      if (n < 0 || n == (ssize_t)sizeof(target) - 1) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "final symbolic target too long");
        break;
      }
      target[n] = 0;
      int equal = 0;
      if (exists) {
        ssize_t z = readlinkat(original, name, before, sizeof(before) - 1);
        if (z >= 0) {
          before[z] = 0;
          equal = !strcmp(before, target);
        }
      }
      if (!equal && SQLi_batch_op(e, batch, 'L', rel, target)) {
        rc = -1;
        break;
      }
    } else {
      rc =
          SQLi_fail(e, SQL_CONSTRAINT, "unsupported final snapshot entry type");
      break;
    }
  }
  closedir(d);
  if (rc || original < 0)
    return rc;
  d = fdopendir(openat(original, ".", O_RDONLY | O_DIRECTORY));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan original deletions");
  while ((de = readdir(d))) {
    if (sql_tree_excluded(path, de->d_name))
      continue;
    /* The private .sql directory may appear after the snapshot (events,
     * dependency registry); its non-transactional parts are never removed
     * by a commit. */
    if (!*path && !strcmp(de->d_name, ".sql"))
      continue;
    struct stat st;
    if (!fstatat(snapshot, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
      continue;
    if (errno != ENOENT) {
      rc = SQLi_fail(e, SQL_IO, "inspect final deletion");
      break;
    }
    char rel[PATH_MAX];
    if (SQLi_joinpath(e, rel, path, de->d_name) ||
        fstatat(original, de->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = -1;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      int sub = openat(original, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0) {
        rc = SQLi_fail(e, SQL_IO, "open deleted directory");
        break;
      }
      rc = delete_tree(e, sub, rel, batch);
      close(sub);
      if (!rc)
        rc = SQLi_batch_op(e, batch, 'R', rel, NULL);
    } else
      rc = SQLi_batch_op(e, batch, 'D', rel, NULL);
    if (rc)
      break;
  }
  closedir(d);
  return rc;
}
int sql_snapshot_validate(Env *e, int fd, const char *path) {
  Table t = {.fd = dup(fd)};
  if (strlen(path) >= sizeof(t.path)) {
    SQLi_table_close(&t);
    return SQLi_fail(e, SQL_CONSTRAINT, "snapshot logical path too long");
  }
  strcpy(t.path, path);
  struct stat definition;
  if (fstatat(fd, ".table", &definition, AT_SYMLINK_NOFOLLOW) &&
      errno == ENOENT) {
    SQL_ViewMap view;
    if (fstatat(fd, ".view", &definition, AT_SYMLINK_NOFOLLOW) &&
        errno == ENOENT) { /* transactional DROP: definition removed */
      SQLi_table_close(&t);
      return 0;
    }
    int rc = sql_view_read(e, fd, &view);
    SQLi_table_close(&t);
    return rc;
  }
  int deferred = e->deferred;
  e->deferred = 0;
  int rc = SQLi_pending(e, t.fd) || SQLi_map_read(e, t.fd, ".table", &t.map) ||
           SQLi_schema_text(e, t.map.DDL, &t.schema) ||
           SQLi_scan_table(e, &t, 1);
  e->deferred = deferred;
  SQLi_table_close(&t);
  return rc ? -1 : 0;
}
