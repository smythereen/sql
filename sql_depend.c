/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Dependency registry.  Every object that reads another object's definition
 * or data (saved/LINKED views, LINKED BRANCHES roots, cross-table shared-field
 * consumers) registers itself in the source's private <source>/.sql/deps/
 * directory as "<kind>-<dev>-<ino>" holding the dependent's canonical path.
 * Entries are intentions: registration is written before the dependent is
 * published, and every reader re-verifies liveness (identity + a definition
 * that still names this source), pruning stale entries.  Hence a crash can
 * only leave conservative, self-healing stale entries, never a missing one. */
#include "sql_local.h"
static const char *kinds[] = {"view", "branch", "link", NULL};
static int fd_path(Env *e, int fd, char *out) {
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, out, PATH_MAX - 1);
  if (n < 0)
    return SQLi_fail(e, SQL_IO, "resolve object path");
  out[n] = 0;
  return 0;
}
static int durable_file(Env *e, int dir, const char *name, const char *text) {
  char temp[NAME_MAX + 1];
  snprintf(temp, sizeof(temp), ".tmp.%d.%s", getpid(), name);
  if (strlen(temp) > 200)
    temp[200] = 0;
  unlinkat(dir, temp, 0);
  int fd = openat(dir, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create dependency entry: %s", strerror(errno));
  size_t len = strlen(text);
  int bad = write(fd, text, len) != (ssize_t)len || fsync(fd);
  close(fd);
  if (bad || renameat(dir, temp, dir, name) || fsync(dir)) {
    unlinkat(dir, temp, 0);
    return SQLi_fail(e, SQL_IO, "persist dependency entry");
  }
  return 0;
}
static int private_dir(Env *e, int parent, const char *name) {
  if (mkdirat(parent, name, 0700) && errno != EEXIST)
    return SQLi_fail(e, SQL_IO, "create %s: %s", name, strerror(errno));
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return SQLi_fail(e, SQL_CONSTRAINT, "unsafe private directory %s", name);
  if (fsync(parent)) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "persist %s", name);
  }
  return fd;
}
int sql_dep_open(Env *e, int source, int create) {
  if (!create) {
    int fd = openat(source, ".sql/deps",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
      return -2;
    return fd < 0 ? SQLi_fail(e, SQL_IO, "open dependency registry") : fd;
  }
  int sql = private_dir(e, source, ".sql");
  if (sql < 0)
    return -1;
  int deps = private_dir(e, sql, "deps");
  close(sql);
  return deps;
}
static void entry_name(char *out, size_t z, const char *kind, struct stat *st) {
  snprintf(out, z, "%s-%llx-%llx", kind, (unsigned long long)st->st_dev,
           (unsigned long long)st->st_ino);
}
/* Source already open and locked by the caller. */
int sql_dep_register_fd(Env *e, int source, const char *kind, int dependent) {
  struct stat st;
  char path[PATH_MAX], name[96];
  if (fstat(dependent, &st) || fd_path(e, dependent, path))
    return SQLi_fail(e, SQL_IO, "inspect dependent identity");
  int deps = sql_dep_open(e, source, 1);
  if (deps < 0)
    return -1;
  entry_name(name, sizeof(name), kind, &st);
  strcat(path, "\n");
  int rc = durable_file(e, deps, name, path);
  close(deps);
  return rc;
}
int sql_dep_register(Env *e, const char *source_path, const char *kind,
                     int dependent) {
  struct stat st;
  char path[PATH_MAX], name[96];
  if (fstat(dependent, &st) || fd_path(e, dependent, path))
    return SQLi_fail(e, SQL_IO, "inspect dependent identity");
  int source = SQLi_open_dir(e, source_path);
  if (source < 0)
    return -1;
  struct stat def;
  int rc = -1;
  if (SQLi_lockdir(e, source, 0))
    goto done;
  if (fstatat(source, ".table", &def, AT_SYMLINK_NOFOLLOW) &&
      fstatat(source, ".view", &def, AT_SYMLINK_NOFOLLOW)) {
    SQLi_fail(e, SQL_CONSTRAINT, "dependency source has no definition");
    goto done;
  }
  int deps = sql_dep_open(e, source, 1);
  if (deps < 0)
    goto done;
  entry_name(name, sizeof(name), kind, &st);
  strcat(path, "\n");
  rc = durable_file(e, deps, name, path);
  close(deps);
done:
  close(source);
  return rc;
}
int sql_dep_unregister(Env *e, const char *source_path, const char *kind,
                       int dependent) {
  struct stat st;
  char name[96];
  if (fstat(dependent, &st))
    return 0;
  int source = SQLi_open_dir(e, source_path);
  if (source < 0) {
    e->status = 0;
    return 0; /* source gone: nothing to unregister */
  }
  int deps = sql_dep_open(e, source, 0);
  if (deps >= 0) {
    entry_name(name, sizeof(name), kind, &st);
    if (!unlinkat(deps, name, 0))
      fsync(deps);
    close(deps);
  }
  e->status = 0;
  close(source);
  return 0;
}
/* Raw, lock-free scan for symlinks naming <source>/.sql/shared/. */
static int links_into(int dir, const char *prefix, int depth) {
  if (depth > 32)
    return 0;
  DIR *d = fdopendir(openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d)
    return 0;
  struct dirent *de;
  int found = 0;
  while (!found && (de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;
    struct stat st;
    if (fstatat(dir, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
      continue;
    if (S_ISLNK(st.st_mode)) {
      char target[PATH_MAX];
      ssize_t n = readlinkat(dir, de->d_name, target, sizeof(target) - 1);
      if (n > 0) {
        target[n] = 0;
        found = !strncmp(target, prefix, strlen(prefix));
      }
    } else if (S_ISDIR(st.st_mode) && strncmp(de->d_name, ".sql", 4) &&
               strncmp(de->d_name, ".context", 8)) {
      /* Engine-private trees (.sql*, context stages) are not references. */
      int sub = openat(dir, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub >= 0) {
        found = links_into(sub, prefix, depth + 1);
        close(sub);
      }
    }
  }
  closedir(d);
  return found;
}
static int names_source(SQL_ViewMap *m, struct stat *src) {
  return m->Device == (uint64_t)src->st_dev && m->Inode == (uint64_t)src->st_ino;
}
/* 1 live, 0 stale. */
static int live(Env *e, int source, const char *kind, const char *path,
                unsigned long long dev, unsigned long long ino) {
  struct stat src, st;
  if (fstat(source, &src))
    return 1;
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return 0;
  int result = 0;
  if (fstat(fd, &st) || (unsigned long long)st.st_dev != dev ||
      (unsigned long long)st.st_ino != ino)
    goto done;
  Env quiet = {0};
  SQL_Result ignored = {0};
  quiet.out = &ignored;
  quiet.opt = e->opt;
  if (!strcmp(kind, "view")) {
    SQL_ViewMap m;
    if (!fstatat(fd, ".view", &st, AT_SYMLINK_NOFOLLOW) &&
        sql_multiview_kind(&quiet, fd) == 0 && !sql_view_read(&quiet, fd, &m))
      result = names_source(&m, &src);
  } else if (!strcmp(kind, "branch")) {
    SQL_MultiView *mv = calloc(1, sizeof(*mv));
    if (mv && sql_multiview_kind(&quiet, fd) > 0 &&
        !sql_multiview_read(&quiet, fd, mv))
      for (unsigned i = 0; i < mv->Count && !result; i++)
        result = names_source(&mv->Branch[i].View, &src);
    free(mv);
  } else if (!strcmp(kind, "link")) {
    char prefix[PATH_MAX + 16];
    char sp[PATH_MAX];
    if (!fstatat(fd, ".table", &st, AT_SYMLINK_NOFOLLOW) &&
        !fd_path(&quiet, source, sp)) {
      snprintf(prefix, sizeof(prefix), "%s/.sql/shared/", sp);
      result = links_into(fd, prefix, 0);
    }
  }
done:
  close(fd);
  return result;
}
/* Visits live dependents (pruning stale ones when prune is set).  Returns the
 * live count, or -1 on registry error.  emit, when non-NULL, receives JSON. */
static char ***collect;
static int *ncollect;
static const char *collect_kind;
int sql_dep_scan(Env *e, int source, int prune, FILE *emit,
                 const char *field) {
  int deps = sql_dep_open(e, source, 0);
  if (deps == -2)
    return 0;
  if (deps < 0)
    return -1;
  DIR *d = fdopendir(dup(deps));
  if (!d) {
    close(deps);
    return SQLi_fail(e, SQL_IO, "scan dependency registry");
  }
  struct dirent *de;
  int count = 0;
  while ((de = readdir(d))) {
    char kind[16];
    unsigned long long dev, ino;
    int matched = 0;
    for (int i = 0; kinds[i]; i++) {
      size_t z = strlen(kinds[i]);
      if (!strncmp(de->d_name, kinds[i], z) && de->d_name[z] == '-' &&
          sscanf(de->d_name + z + 1, "%llx-%llx", &dev, &ino) == 2) {
        strcpy(kind, kinds[i]);
        matched = 1;
      }
    }
    if (!matched)
      continue;
    unsigned char *text = NULL;
    size_t len = 0;
    if (SQLi_load_bytes(e, deps, de->d_name, &text, &len)) {
      e->status = 0;
      continue;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%.*s", (int)(len && text[len - 1] == '\n'
                                                    ? len - 1
                                                    : len),
             (char *)text);
    free(text);
    if (!live(e, source, kind, path, dev, ino)) {
      if (prune && !unlinkat(deps, de->d_name, 0))
        fsync(deps);
      continue;
    }
    if (field && strcmp(kind, "link")) {
      /* Field-level restriction: does the dependent query name the field? */
      int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      int uses = 0;
      if (fd >= 0) {
        Env quiet = {0};
        SQL_Result ignored = {0};
        quiet.out = &ignored;
        SQL_MultiView *mv = calloc(1, sizeof(*mv));
        int n = 0;
        SQL_ViewMap *maps[SQL_BRANCH_MAX] = {0};
        SQL_ViewMap single;
        if (!strcmp(kind, "view") && !sql_view_read(&quiet, fd, &single))
          maps[n++] = &single;
        else if (mv && !sql_multiview_read(&quiet, fd, mv))
          for (unsigned i = 0; i < mv->Count; i++)
            maps[n++] = &mv->Branch[i].View;
        for (int i = 0; i < n && !uses; i++) {
          Parser *q = calloc(1, sizeof(*q));
          if (q && !SQLi_lex(&quiet, q, maps[i]->Query))
            for (int k = 0; k < q->n && !uses; k++)
              uses = !q->t[k].quoted && (!strcmp(q->t[k].s, field) ||
                                         !strcmp(q->t[k].s, "*"));
          else
            uses = 1; /* unreadable query: be conservative */
          if (q) {
            SQLi_parser_free(q);
            free(q);
          }
        }
        free(mv);
        close(fd);
      }
      if (!uses)
        continue;
    } else if (field)
      continue; /* shared links do not name logical fields */
    count++;
    if (collect && !strcmp(kind, collect_kind)) {
      char **grown = realloc(*collect, (*ncollect + 1) * sizeof(*grown));
      if (grown) {
        *collect = grown;
        grown[*ncollect] = strdup(path);
        if (grown[*ncollect])
          (*ncollect)++;
      }
    }
    if (emit) {
      fprintf(emit, "{\"kind\":\"%s\",\"path\":", kind);
      SQLi_json(emit, (unsigned char *)path, strlen(path));
      fputs("}\n", emit);
    }
  }
  closedir(d);
  close(deps);
  return count;
}
int sql_dep_restrict(Env *e, int source, const char *what) {
  char *buf = NULL;
  size_t len = 0;
  FILE *f = open_memstream(&buf, &len);
  if (!f)
    return SQLi_fail(e, SQL_IO, "out of memory");
  int n = sql_dep_scan(e, source, 1, f, NULL);
  fclose(f);
  if (n > 0) {
    char *nl = strchr(buf, '\n');
    if (nl)
      *nl = 0;
    SQLi_fail(e, SQL_CONSTRAINT,
              "%s refused (RESTRICT): %d live dependent(s), first %s", what, n,
              buf);
  }
  free(buf);
  return n ? -1 : 0;
}
int sql_dep_show(Env *e, Parser *p) {
  char *path = NULL;
  if (SQLi_need(e, p, "OF") || !(path = take(e, p)) || SQLi_end(e, p))
    return -1;
  int fd = SQLi_open_dir(e, path);
  if (fd < 0)
    return -1;
  int rc = SQLi_lockdir(e, fd, 0) ? -1 : sql_dep_scan(e, fd, 0, e->stream, NULL);
  close(fd);
  return rc < 0 ? -1 : 0;
}
static int dep_paths(Env *e, int source, const char *kind, char ***out, int *n,
                     int prune) {
  *out = NULL;
  *n = 0;
  collect = out;
  ncollect = n;
  collect_kind = kind;
  int rc = sql_dep_scan(e, source, prune, NULL, NULL);
  collect = NULL;
  ncollect = NULL;
  return rc < 0 ? -1 : 0;
}
/* Lists without pruning: an intention may precede its consumer's link. */
int sql_dep_paths_live(Env *e, int source, const char *kind, char ***out,
                       int *n) {
  return dep_paths(e, source, kind, out, n, 0);
}
int sql_dep_paths(Env *e, int source, const char *kind, char ***out, int *n) {
  *out = NULL;
  *n = 0;
  collect = out;
  ncollect = n;
  collect_kind = kind;
  int rc = sql_dep_scan(e, source, 1, NULL, NULL);
  collect = NULL;
  ncollect = NULL;
  return rc < 0 ? -1 : 0;
}
