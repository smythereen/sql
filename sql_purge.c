/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* DROP ... INCLUDING DATA.  Only entries the unit itself manages are removed;
 * any unmanaged entry refuses the whole drop before anything changes. */
#include "sql_local.h"
typedef struct {
  char **v;
  int n;
} List;
static int add(Env *e, List *l, const char *s) {
  char **g = realloc(l->v, (l->n + 1) * sizeof(*g));
  if (!g)
    return SQLi_fail(e, SQL_IO, "out of memory");
  l->v = g;
  if (!(l->v[l->n] = strdup(s)))
    return SQLi_fail(e, SQL_IO, "out of memory");
  l->n++;
  return 0;
}
static void drop_list(List *l) {
  for (int i = 0; i < l->n; i++)
    free(l->v[i]);
  free(l->v);
  memset(l, 0, sizeof(*l));
}
static int cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}
static int has(List *l, const char *s) {
  return l->n && bsearch(&s, l->v, l->n, sizeof(char *), cmp) != NULL;
}
/* Recursive removal of a private unit subtree (.sql, .linked).  When
 * check is set nothing is removed; entries failing allow() are refused. */
typedef int (*Allow)(const char *rel, struct stat *st, int depth);
static int subtree(Env *e, int parent, const char *name, const char *rel,
                   Allow allow, int depth, int check) {
  if (depth > 64)
    return SQLi_fail(e, SQL_CONSTRAINT, "managed tree too deep: %s", rel);
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? 0 : SQLi_fail(e, SQL_IO, "open %s", rel);
  DIR *d = fdopendir(dup(fd));
  if (!d) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "scan %s", rel);
  }
  struct dirent *de;
  int rc = 0;
  while (!rc && (de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
      continue;
    char sub[PATH_MAX];
    snprintf(sub, sizeof(sub), "%s/%s", rel, de->d_name);
    struct stat st;
    if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat %s", sub);
      break;
    }
    if (!allow(sub, &st, depth + 1)) {
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "unmanaged entry %s; INCLUDING DATA refused, nothing "
                     "removed",
                     sub);
      break;
    }
    if (S_ISDIR(st.st_mode))
      rc = subtree(e, fd, de->d_name, sub, allow, depth + 1, check);
    else if (!check && unlinkat(fd, de->d_name, 0) && errno != ENOENT)
      rc = SQLi_fail(e, SQL_IO, "remove %s", sub);
  }
  closedir(d);
  if (!rc && !check && fsync(fd))
    rc = SQLi_fail(e, SQL_IO, "persist removal in %s", rel);
  close(fd);
  if (!rc && !check && unlinkat(parent, name, AT_REMOVEDIR) && errno != ENOENT)
    rc = SQLi_fail(e, SQL_IO, "remove directory %s: %s", rel, strerror(errno));
  return rc;
}
static int allow_private(const char *rel, struct stat *st, int depth) {
  (void)rel;
  (void)depth;
  return S_ISDIR(st->st_mode) || S_ISREG(st->st_mode);
}
static int allow_linked(const char *rel, struct stat *st, int depth) {
  if (S_ISDIR(st->st_mode) || S_ISLNK(st->st_mode))
    return depth > 1 || S_ISDIR(st->st_mode);
  const char *base = strrchr(rel, '/') + 1;
  size_t z = strlen(base);
  return S_ISREG(st->st_mode) && depth == 1 &&
         (!strcmp(base, "owner") || (z > 5 && !strcmp(base + z - 5, ".meta")));
}
static int lease_busy(int root) {
  int fd = openat(root, ".sql-view-watch", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return 0;
  int busy = flock(fd, LOCK_EX | LOCK_NB) != 0;
  close(fd);
  return busy;
}
/* One v1/v2 view directory: records symlink, .linked, .sql, lease, .view. */
static int view_dir(Env *e, int root, int check) {
  if (lease_busy(root))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "a WATCH VIEW process holds this view; stop it first");
  DIR *d = fdopendir(openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan view directory");
  struct dirent *de;
  int rc = 0;
  while (!rc && (de = readdir(d))) {
    const char *n = de->d_name;
    struct stat st;
    if (!strcmp(n, ".") || !strcmp(n, "..") ||
        sql_provisioned_metadata(e, root, n))
      continue;
    if (fstatat(root, n, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat view entry");
      break;
    }
    int ok = (!strcmp(n, ".view") && S_ISREG(st.st_mode)) ||
             (!strcmp(n, "records") && S_ISLNK(st.st_mode)) ||
             (!strcmp(n, ".sql-view-watch") && S_ISREG(st.st_mode) &&
              !st.st_size) ||
             ((!strcmp(n, ".linked") || !strcmp(n, ".sql")) &&
              S_ISDIR(st.st_mode));
    if (!ok)
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "unmanaged view entry %s; INCLUDING DATA refused", n);
  }
  closedir(d);
  if (rc)
    return rc;
  if (subtree(e, root, ".linked", ".linked", allow_linked, 0, 1) ||
      subtree(e, root, ".sql", ".sql", allow_private, 0, 1))
    return -1;
  if (check)
    return 0;
  if ((unlinkat(root, "records", 0) && errno != ENOENT) ||
      subtree(e, root, ".linked", ".linked", allow_linked, 0, 0) ||
      subtree(e, root, ".sql", ".sql", allow_private, 0, 0) ||
      (unlinkat(root, ".sql-view-watch", 0) && errno != ENOENT) ||
      fsync(root) || unlinkat(root, ".view", 0) || fsync(root))
    return e->status ? -1 : SQLi_fail(e, SQL_IO, "remove view data");
  return 0;
}
int sql_purge_view(Env *e, int root) {
  return view_dir(e, root, 1) || view_dir(e, root, 0) ? -1 : 0;
}
int sql_purge_multiview(Env *e, int root, SQL_MultiView *m) {
  if (lease_busy(root))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "a WATCH VIEW process holds this view; stop it first");
  for (int pass = 1; pass >= 0; pass--) {
    for (unsigned i = 0; i < m->Count; i++) {
      int fd = openat(root, m->Branch[i].Name,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (fd < 0) {
        if (errno == ENOENT)
          continue;
        return SQLi_fail(e, SQL_IO, "open branch %s", m->Branch[i].Name);
      }
      struct stat st;
      int bad = fstat(fd, &st) || st.st_dev != m->Branch[i].Device ||
                st.st_ino != m->Branch[i].Inode;
      if (bad) {
        close(fd);
        return SQLi_fail(e, SQL_CONSTRAINT,
                         "branch %s identity changed; preserved",
                         m->Branch[i].Name);
      }
      SQL_ViewMap v;
      int had = !fstatat(fd, ".view", &st, AT_SYMLINK_NOFOLLOW);
      if (had && sql_view_read(e, fd, &v)) {
        close(fd);
        return -1;
      }
      int rc = view_dir(e, fd, pass);
      if (!rc && !pass && had)
        sql_dep_unregister(e, v.Source, "view", fd);
      close(fd);
      if (rc)
        return -1;
      if (!pass && (unlinkat(root, m->Branch[i].Name, AT_REMOVEDIR) ||
                    fsync(root)))
        return SQLi_fail(e, SQL_IO, "remove branch directory");
    }
  }
  if (subtree(e, root, ".sql", ".sql", allow_private, 0, 0) ||
      (unlinkat(root, ".sql-view-watch", 0) && errno != ENOENT) ||
      unlinkat(root, ".view", 0) || fsync(root))
    return e->status ? -1 : SQLi_fail(e, SQL_IO, "remove multi-view root");
  return 0;
}
static int root_meta(const char *name) {
  return !strcmp(name, ".sql-root") || !strcmp(name, ".context") ||
         !strncmp(name, ".context_", 9) || !strncmp(name, ".sql-context.", 13) ||
         !strncmp(name, ".sql-coord.", 11) || !strncmp(name, ".sql-clean.", 11) ||
         !strcmp(name, ".table") || !strcmp(name, ".sql") ||
         !strncmp(name, ".sql-map.", 9);
}
static int raw(Env *e, Table *t, int fd, const char *rel, List *files,
               List *dirs, List *found, int depth) {
  if (depth > 64)
    return SQLi_fail(e, SQL_CONSTRAINT, "table tree too deep");
  DIR *d = fdopendir(dup(fd));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan %s", *rel ? rel : ".");
  struct dirent *de;
  int rc = 0;
  while (!rc && (de = readdir(d))) {
    const char *n = de->d_name;
    if (!strcmp(n, ".") || !strcmp(n, ".."))
      continue;
    if (!depth && !strncmp(n, ".sql-txn.", 9)) {
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "pending journal %s; RECOVER first, nothing removed", n);
      break;
    }
    if (!depth && (root_meta(n) || sql_provisioned_metadata(e, t->fd, n)))
      continue;
    char sub[PATH_MAX];
    if (SQLi_joinpath(e, sub, rel, n)) {
      rc = -1;
      break;
    }
    struct stat st;
    if (fstatat(fd, n, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat %s", sub);
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      if (!has(dirs, sub) && SQLi_schema_dir_path(&t->schema, sub) < 0) {
        rc = SQLi_fail(e, SQL_CONSTRAINT,
                       "unmanaged directory %s; INCLUDING DATA refused, "
                       "nothing removed",
                       sub);
        break;
      }
      int child = openat(fd, n, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0) {
        rc = SQLi_fail(e, SQL_IO, "open %s: %s", sub, strerror(errno));
        break;
      }
      rc = raw(e, t, child, sub, files, dirs, found, depth + 1);
      close(child);
      if (!rc)
        rc = add(e, found, sub); /* post-order: children first */
    } else if (!has(files, sub))
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "unmanaged entry %s; INCLUDING DATA refused, nothing "
                     "removed",
                     sub);
  }
  closedir(d);
  return rc;
}
/* t is locked exclusively and scanned. */
int sql_purge_table(Env *e, Table *t) {
  List files = {0}, records = {0}, found = {0}, anchors = {0};
  Batch b = {.fd = -1};
  int rc = -1;
  for (int i = 0; i < t->nr; i++) {
    Record *r = &t->r[i];
    char p[PATH_MAX];
    if (add(e, &records, r->path) || SQLi_joinpath(e, p, r->path, ".sql-id") ||
        add(e, &files, p))
      goto done;
    for (int j = 0; j < r->nm; j++) {
      Member *m = &r->m[j];
      if (add(e, &files, m->path))
        goto done;
      if (m->isnull) {
        const char *slash = strrchr(m->path, '/');
        snprintf(p, sizeof(p), "%.*s/.sql-null.%s", (int)(slash - m->path),
                 m->path, slash + 1);
        if (add(e, &files, p))
          goto done;
      }
    }
  }
  if (files.n)
    qsort(files.v, files.n, sizeof(char *), cmp);
  if (records.n)
    qsort(records.v, records.n, sizeof(char *), cmp);
  if (raw(e, t, t->fd, "", &files, &records, &found, 0))
    goto done;
  /* Shared anchors owned by this table. */
  int shared =
      openat(t->fd, ".sql/shared", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (shared >= 0) {
    DIR *d = fdopendir(shared);
    struct dirent *de;
    while (d && (de = readdir(d))) {
      char p[PATH_MAX];
      if (de->d_name[0] == '.')
        continue;
      snprintf(p, sizeof(p), ".sql/shared/%s", de->d_name);
      if (add(e, &anchors, p)) {
        closedir(d);
        goto done;
      }
    }
    if (d)
      closedir(d);
  }
  if (SQLi_batch_begin(e, t->fd, &b))
    goto done;
  for (int i = 0; i < files.n; i++) {
    struct stat st;
    if (!fstatat(t->fd, files.v[i], &st, AT_SYMLINK_NOFOLLOW) &&
        SQLi_batch_op(e, &b, 'D', files.v[i], NULL))
      goto done;
  }
  for (int i = 0; i < found.n; i++)
    if (SQLi_batch_op(e, &b, 'R', found.v[i], NULL))
      goto done;
  for (int i = 0; i < anchors.n; i++)
    if (SQLi_batch_op(e, &b, 'D', anchors.v[i], NULL))
      goto done;
  if (SQLi_batch_op(e, &b, 'D', ".table", NULL))
    goto done;
  rc = SQLi_batch_commit(e, &b);
  /* Private bookkeeping (.sql: deps, events, refs, ids) goes last; a crash
   * here leaves only private metadata in an undefined directory. */
  if (!rc && !t->has_live_root &&
      subtree(e, t->fd, ".sql", ".sql", allow_private, 0, 0))
    rc = SQLi_fail(e, SQL_IO, "table data removed; private .sql cleanup "
                              "incomplete");
done:
  SQLi_batch_abort(&b);
  drop_list(&files);
  drop_list(&records);
  drop_list(&found);
  drop_list(&anchors);
  return rc;
}
