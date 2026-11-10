/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Autocommit redo remains table-gated, while these owned hardlinks and
 * operation manifests retain every new byte under the persistent context. */
#include "sql_local.h"
static int directories(Env *e, int root, const char *path) {
  char *copy = strdup(path);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "context data path allocation");
  int fd = dup(root);
  if (fd < 0) {
    free(copy);
    return SQLi_fail(e, SQL_IO, "context data descriptor");
  }
  char *save = NULL;
  for (char *part = strtok_r(copy, "/", &save); part;
       part = strtok_r(NULL, "/", &save)) {
    if (mkdirat(fd, part, 0700) && errno != EEXIST) {
      close(fd);
      free(copy);
      return SQLi_fail(e, SQL_IO, "create owned pending directory");
    }
    int child =
        openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0 || fsync(fd)) {
      if (child >= 0)
        close(child);
      close(fd);
      free(copy);
      return SQLi_fail(e, SQL_IO, "sync owned pending directory");
    }
    close(fd);
    fd = child;
  }
  free(copy);
  return fd;
}
int sql_command_data(Env *e, Batch *b, char op, const char *path,
                     const char *value) {
  SQL_Session *s = e->session;
  if (!s || !s->recording || s->map.State != SQL_CTX_IDLE ||
      e->participant != UINT32_MAX)
    return 0;
  char slot[96];
  snprintf(slot, sizeof(slot), "tables/autocommit-%llu",
           (unsigned long long)s->map.Command.Sequence);
  int data = directories(e, s->workspace, slot);
  if (data < 0)
    return -1;
  char meta_path[96];
  snprintf(meta_path, sizeof(meta_path), "commands/%llu",
           (unsigned long long)s->map.Command.Sequence);
  int meta = directories(e, s->workspace, meta_path);
  if (meta < 0) {
    close(data);
    return -1;
  }
  int rc = -1;
  struct stat root, staged;
  if (fstat(b->root, &root) || fstat(data, &staged))
    goto io;
  if (root.st_dev != staged.st_dev) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "autocommit workspace/target cross-device data refused before "
              "decision");
    goto done;
  }
  int source =
      openat(meta, ".source",
             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (source >= 0) {
    char identity[256];
    int n = snprintf(
        identity, sizeof(identity),
        "SQL_AUTOCOMMIT 1\nuid=%u\ndevice=%llu\ninode=%llu\ntransaction=%s\n",
        getuid(), (unsigned long long)root.st_dev,
        (unsigned long long)root.st_ino, b->name + 9);
    int bad = sql_write_all(source, identity, n) || fsync(source);
    close(source);
    if (bad)
      goto io;
  } else if (errno != EEXIST)
    goto io;
  if (op == 'P' || op == 'H' || op == 'L' || op == 'M') {
    char *copy = strdup(path);
    if (!copy)
      goto io;
    char *slash = strrchr(copy, '/'), *base = slash ? slash + 1 : copy;
    int parent;
    if (slash) {
      *slash = 0;
      parent = directories(e, data, copy);
    } else
      parent = dup(data);
    if (parent < 0) {
      free(copy);
      goto done;
    }
    int bad = 0;
    if (op == 'P' || op == 'H' || op == 'L') {
      char id[33], temporary[64];
      if (sql_uuid(e, id)) {
        close(parent);
        free(copy);
        goto done;
      }
      snprintf(temporary, sizeof(temporary), ".sql-pending-%s", id);
      bad = op == 'L' ? symlinkat(value, parent, temporary)
                      : linkat(b->fd, value, parent, temporary, 0);
      if (!bad)
        bad = renameat(parent, temporary, parent, base);
      if (bad)
        unlinkat(parent, temporary, 0);
    } else
      bad = mkdirat(parent, base, 0700) && errno != EEXIST;
    if (!bad)
      bad = fsync(parent);
    close(parent);
    free(copy);
    if (bad)
      goto io;
  }
  int changes =
      openat(meta, ".changes",
             O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (changes < 0)
    goto io;
  uint32_t lengths[3] = {(unsigned char)op, strlen(path),
                         value ? strlen(value) : 0};
  int bad = sql_write_all(changes, lengths, sizeof(lengths)) ||
            sql_write_all(changes, path, lengths[1]) ||
            (lengths[2] && sql_write_all(changes, value, lengths[2])) ||
            fsync(changes);
  close(changes);
  if (bad || fsync(meta) || fsync(data) || fsync(s->workspace))
    goto io;
  rc = 0;
  goto done;
io:
  SQLi_fail(e, SQL_IO, "persist context-owned autocommit data: %s",
            strerror(errno));
done:
  close(meta);
  close(data);
  return rc;
}
