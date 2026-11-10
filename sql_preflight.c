/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
/* Structural preview, not a payload snapshot: regular members are represented
 * by private empty files, links by literal links, directories by real private
 * directories. Only .table is copied. Never hardlink originals (ctime changes)
 * and never open a pipe, device or socket. Staged puts supply their real bytes.
 * Type/content checks for changed values already ran before journal creation.
 */
static int skeleton(Env *e, int source, int dest, const char *path) {
  DIR *d = fdopendir(openat(source, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan structural preview");
  int rc = 0;
  struct dirent *de;
  while ((de = readdir(d))) {
    const char *name = de->d_name;
    if (sql_tree_excluded(path, name))
      continue;
    struct stat st;
    char rel[PATH_MAX];
    if (fstatat(source, name, &st, AT_SYMLINK_NOFOLLOW) ||
        SQLi_joinpath(e, rel, path, name)) {
      rc = SQLi_fail(e, SQL_IO, "inspect structural preview entry");
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      if (mkdirat(dest, name, 0700)) {
        rc = SQLi_fail(e, SQL_IO, "create preview directory");
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
        rc = SQLi_fail(e, SQL_IO, "open structural preview directories");
        break;
      }
      rc = skeleton(e, in, out, rel);
      close(in);
      close(out);
      if (rc)
        break;
    } else if (S_ISLNK(st.st_mode)) {
      char target[PATH_MAX];
      ssize_t n = readlinkat(source, name, target, sizeof(target) - 1);
      if (n < 0 || n == (ssize_t)sizeof(target) - 1) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "preview link length");
        break;
      }
      target[n] = 0;
      if (symlinkat(target, dest, name)) {
        rc = SQLi_fail(e, SQL_IO, "create preview link");
        break;
      }
    } else {
      int out =
          openat(dest, name,
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
      if (out < 0) {
        rc = SQLi_fail(e, SQL_IO, "create structural preview file");
        break;
      }
      if (!*path && !strcmp(name, ".table")) {
        SQL_Map map;
        if (SQLi_map_read(e, source, name, &map) ||
            sql_write_all(out, &map, sizeof(map)))
          rc = SQLi_fail(e, SQL_IO, "copy preview schema");
      }
      close(out);
      if (rc)
        break;
    }
  }
  closedir(d);
  return rc;
}
int sql_preflight(Env *e, Batch *b) {
  if (e->deferred)
    return 0; /* Full staged tree validation occurs at COMMIT. */
  if (mkdirat(b->fd, "preview", 0700))
    return SQLi_fail(e, SQL_IO, "create structural preflight");
  int fd =
      openat(b->fd, "preview", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open structural preflight");
  Table t = {.fd = -1};
  int rc = -1;
  if (skeleton(e, b->root, fd, "") || sql_batch_preview(e, b, fd))
    goto done;
  struct stat st;
  if (fstatat(fd, ".table", &st, AT_SYMLINK_NOFOLLOW)) {
    if (errno == ENOENT)
      rc = 0;
    else
      SQLi_fail(e, SQL_IO, "inspect preflight definition");
    goto done; /* Explicit definition-only DROP is allowed. */
  }
  t.fd = dup(fd);
  if (t.fd < 0 || SQLi_map_read(e, t.fd, ".table", &t.map) ||
      SQLi_schema_text(e, t.map.DDL, &t.schema) || SQLi_scan_table(e, &t, 0))
    goto done;
  rc = 0;
done:
  SQLi_table_close(&t);
  close(fd);
  Env cleanup = *e;
  SQL_Result ignored = {0};
  cleanup.out = &ignored;
  cleanup.status = 0;
  if (sql_tree_remove(&cleanup, b->fd, "preview") || fsync(b->fd)) {
    if (!rc)
      rc = SQLi_fail(e, SQL_IO, "cleanup structural preflight");
  }
  return rc;
}
/* Permission preflight (before any decision): every directory an operation
 * changes must be writable and searchable, so EACCES/EPERM/EROFS refuse the
 * command with nothing committed instead of leaving a decided journal that
 * cannot apply. Parents created by earlier operations are checked at their
 * nearest existing ancestor. */
typedef struct {
  uint32_t magic, version;
  uint64_t owner;
} PHeader;
typedef struct {
  uint32_t type, a, b, slot;
} PEntry;
static int writable_parent(Env *e, int root, const char *path) {
  char copy[PATH_MAX];
  snprintf(copy, sizeof(copy), "%s", path);
  char *slash = strrchr(copy, '/');
  int fd = dup(root);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "permission preflight descriptor");
  if (slash) {
    *slash = 0;
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
      int next =
          openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next < 0) {
        if (errno == ENOENT)
          break; /* created by an earlier operation: ancestor decides */
        int saved = errno;
        close(fd);
        return SQLi_fail(e, SQL_IO, "permission preflight: %s: %s", path,
                         strerror(saved));
      }
      close(fd);
      fd = next;
    }
  }
  int bad = faccessat(fd, ".", W_OK | X_OK, 0);
  int saved = errno;
  close(fd);
  return bad ? SQLi_fail(e, SQL_IO,
                         "permission preflight: directory of %s is not "
                         "writable: %s; nothing committed",
                         path, strerror(saved))
             : 0;
}
int sql_permission_preflight(Env *e, Batch *b) {
  int mf = openat(b->fd, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  PHeader h;
  if (mf < 0 || sql_read_all(mf, &h, sizeof(h))) {
    if (mf >= 0)
      close(mf);
    return SQLi_fail(e, SQL_IO, "permission preflight manifest");
  }
  /* Publication renames the durable event into .sql/events after apply. */
  int rc = writable_parent(e, b->root, ".sql/events/event");
  for (; !rc;) {
    PEntry ent;
    ssize_t n = read(mf, &ent, sizeof(ent));
    if (!n)
      break;
    char a[PATH_MAX], v[PATH_MAX];
    if (n != sizeof(ent) || ent.a >= PATH_MAX || ent.b >= PATH_MAX ||
        sql_read_all(mf, a, ent.a) || sql_read_all(mf, v, ent.b)) {
      rc = SQLi_fail(e, SQL_IO, "permission preflight entry");
      break;
    }
    a[ent.a] = 0;
    v[ent.b] = 0;
    if (ent.type == 'N')
      continue;
    if (writable_parent(e, b->root, a) ||
        (ent.type == 'T' && writable_parent(e, b->root, v))) {
      rc = -1;
      break;
    }
  }
  close(mf);
  return rc;
}
