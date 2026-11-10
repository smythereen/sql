/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Cross-table shared fields.  A source table owns the payload anchor
 * <source>/.sql/shared/<id>; consumer members in other tables are symlinks
 * with that absolute target.  Each consumer table is registered as a "link"
 * dependent in the source's dependency registry (the reverse reference), so
 * the source cannot be dropped while consumers exist, every update through
 * any consumer is validated against every consumer's field type, and
 * SHOW REFERENCES OF lists them.  Inside a transaction the source and
 * consumers are ordinary participants, so updates commit atomically. */
#include "sql_local.h"
int sql_xshare_split(const char *target, char *root, char *anchor) {
  const char *tail = strstr(target, "/.sql/shared/");
  if (target[0] != '/' || !tail || strlen(tail + 13) != 32)
    return 0;
  for (const char *s = tail + 13; *s; s++)
    if (!isxdigit((unsigned char)*s))
      return 0;
  if (strstr(target, "/./") || strstr(target, "/../") || strstr(target, "//") ||
      tail == target)
    return 0;
  if (tail - target >= PATH_MAX)
    return 0;
  memcpy(root, target, tail - target);
  root[tail - target] = 0;
  snprintf(anchor, 80, ".sql/shared/%s", tail + 13);
  return 1;
}
static int open_source(Env *e, const char *root, Table *s, int write) {
  if (SQLi_table_open(e, s, root, write) || SQLi_scan_table(e, s, 0))
    return -1;
  if (!s->schema.links)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "shared source %s is not LINKS INTERNAL", root);
  return 0;
}
int sql_xshare_load(Env *e, const char *abs, unsigned char **buf,
                    size_t *len) {
  char root[PATH_MAX], anchor[80];
  if (!sql_xshare_split(abs, root, anchor))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid cross-table anchor");
  Table s = {.fd = -1};
  /* Opening routes the source into an active transaction's snapshot. */
  struct stat st;
  int rc = -1;
  if (e->coordinating) {
    /* COMMIT validation: this process may hold the owner's exclusive lock as
     * a participant; the committed anchor is stable, read it lock-free. */
    s.fd = SQLi_open_dir(e, root);
    if (s.fd < 0)
      return -1;
    snprintf(s.path, sizeof(s.path), "%s", root);
    /* Route (no lock) so an anchor staged by this transaction is visible. */
    if (sql_session_route(e, &s, 0) < 0)
      goto done;
    if (fstatat(s.fd, anchor, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode))
      SQLi_fail(e, SQL_CONSTRAINT, "broken/nonregular cross-table anchor %s",
                abs);
    else
      rc = SQLi_load_bytes(e, s.fd, anchor, buf, len) ? -1 : 0;
    goto done;
  }
  if (SQLi_table_open(e, &s, root, 0))
    goto done;
  if (fstatat(s.fd, anchor, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode)) {
    SQLi_fail(e, SQL_CONSTRAINT, "broken/nonregular cross-table anchor %s",
              abs);
    goto done;
  }
  rc = SQLi_load_bytes(e, s.fd, anchor, buf, len) ? -1 : 0;
done:
  SQLi_table_close(&s);
  return rc;
}
int sql_xshare_stat(Env *e, const char *abs, struct stat *st) {
  char root[PATH_MAX], anchor[80];
  if (!sql_xshare_split(abs, root, anchor))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid cross-table anchor");
  Table s = {.fd = -1};
  int rc = SQLi_table_open(e, &s, root, 0);
  if (!rc && (fstatat(s.fd, anchor, st, AT_SYMLINK_NOFOLLOW) ||
              !S_ISREG(st->st_mode)))
    rc = SQLi_fail(e, SQL_CONSTRAINT, "broken/nonregular cross-table anchor");
  SQLi_table_close(&s);
  return rc ? -1 : 0;
}
static int same(struct stat *a, const struct stat *b) {
  return b && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
/* s: opened source.  Validates the value against the source's own members
 * sharing the anchor and every registered consumer table (except skip). */
int sql_xshare_validate(Env *e, Table *s, const char *anchor,
                        const struct stat *skip, const unsigned char *data,
                        size_t len) {
  char abs[PATH_MAX];
  if (snprintf(abs, sizeof(abs), "%s/%s", s->path, anchor) >= PATH_MAX)
    return SQLi_fail(e, SQL_CONSTRAINT, "anchor path too long");
  for (int i = 0; i < s->nr; i++)
    for (int j = 0; j < s->r[i].nm; j++) {
      Member *m = &s->r[i].m[j];
      char target[PATH_MAX];
      if (!S_ISLNK(m->st.st_mode))
        continue;
      if (SQLi_member_target(e, s, m, target))
        return -1;
      if (!strcmp(target, anchor) &&
          SQLi_value_check(e, &s->schema.node[m->field], data, len))
        return -1;
    }
  char **paths = NULL;
  int n = 0, rc = 0;
  if (sql_dep_paths(e, s->has_live_root ? s->live_root : s->fd, "link", &paths,
                    &n))
    return -1;
  for (int k = 0; k < n && !rc; k++) {
    int fd = open(paths[k], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat id;
    if (fd < 0 || fstat(fd, &id) || same(&id, skip)) {
      if (fd >= 0)
        close(fd);
      continue;
    }
    close(fd);
    Table c = {.fd = -1};
    if (SQLi_table_open(e, &c, paths[k], 0) || SQLi_scan_table(e, &c, 0))
      rc = -1;
    for (int i = 0; !rc && i < c.nr; i++)
      for (int j = 0; !rc && j < c.r[i].nm; j++) {
        Member *m = &c.r[i].m[j];
        char target[PATH_MAX];
        if (!S_ISLNK(m->st.st_mode))
          continue;
        if (SQLi_member_target(e, &c, m, target))
          rc = -1;
        else if (!strcmp(target, abs) &&
                 SQLi_value_check(e, &c.schema.node[m->field], data, len))
          rc = -1;
      }
    SQLi_table_close(&c);
  }
  for (int k = 0; k < n; k++)
    free(paths[k]);
  free(paths);
  return rc;
}
int sql_xshare_write(Env *e, const char *abs, const struct stat *skip,
                     const unsigned char *data, size_t len) {
  char root[PATH_MAX], anchor[80];
  if (!sql_xshare_split(abs, root, anchor))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid cross-table anchor");
  Table s = {.fd = -1};
  Batch b = {.fd = -1};
  int rc = -1;
  if (open_source(e, root, &s, 1) ||
      sql_xshare_validate(e, &s, anchor, skip, data, len) ||
      SQLi_batch_begin(e, s.fd, &b) ||
      SQLi_batch_put(e, &b, anchor, data, len))
    goto done;
  rc = SQLi_batch_commit(e, &b);
done:
  SQLi_batch_abort(&b);
  SQLi_table_close(&s);
  return rc;
}
static int randomid(Env *e, char *out) {
  unsigned char x[16];
  if (getrandom(x, 16, 0) != 16)
    return SQLi_fail(e, SQL_IO, "random ID unavailable");
  for (int i = 0; i < 16; i++)
    sprintf(out + 2 * i, "%02x", x[i]);
  return 0;
}
/* Prepares the source side of LINK ... FROM SOURCE <other table>: promotes
 * the source member to an anchor (its own journaled batch) and records the
 * reverse reference before any consumer symlink exists.  Returns the
 * absolute anchor and its value. */
int sql_xshare_link_source(Env *e, Table *dest, const char *source_table,
                           const char *member, char *abs,
                           unsigned char **data, size_t *len, Table *keep) {
  /* keep receives the still-locked owner so a concurrent DROP cannot prune
   * the reverse reference before the consumer's symlinks are committed. */
  Table s = {.fd = -1};
  Batch b = {.fd = -1};
  int rc = -1;
  if (open_source(e, source_table, &s, 1))
    goto done;
  if (!strcmp(s.path, dest->path)) {
    SQLi_fail(e, SQL_CONSTRAINT, "same table; use same-table LINK");
    goto done;
  }
  Member *src = NULL;
  for (int i = 0; i < s.nr; i++)
    for (int j = 0; j < s.r[i].nm; j++)
      if (!strcmp(s.r[i].m[j].path, member))
        src = &s.r[i].m[j];
  if (!src || src->isnull) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "source must identify exactly one non-NULL managed member");
    goto done;
  }
  int promote = !S_ISLNK(src->st.st_mode);
  char anchor[PATH_MAX];
  if (!promote && SQLi_member_target(e, &s, src, anchor))
    goto done;
  if (!promote && anchor[0] == '/') {
    char root[PATH_MAX], rel[80];
    /* Checked before loading: the owner may be the (locked) destination. */
    if (!sql_xshare_split(anchor, root, rel) || !strcmp(root, dest->path)) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "source member is shared from the destination table; link "
                "within that table instead");
      goto done;
    }
  }
  if (SQLi_member_load(e, &s, src, data, len))
    goto done;
  if (!promote) {
    if (anchor[0] == '/') {
      /* Chain to the ultimate owner; never a cycle back into dest. */
      char root[PATH_MAX], rel[80];
      sql_xshare_split(anchor, root, rel);
      strcpy(abs, anchor);
      SQLi_table_close(&s);
      if (open_source(e, root, &s, 1) ||
          sql_dep_register_fd(e, s.has_live_root ? s.live_root : s.fd, "link",
                              dest->has_live_root ? dest->live_root : dest->fd))
        goto done;
      rc = 0;
      goto done;
    }
  } else {
    char id[33];
    if (randomid(e, id))
      goto done;
    snprintf(anchor, sizeof(anchor), ".sql/shared/%s", id);
  }
  if (snprintf(abs, PATH_MAX, "%s/%s", s.path, anchor) >= PATH_MAX) {
    SQLi_fail(e, SQL_CONSTRAINT, "anchor path too long");
    goto done;
  }
  /* Reverse reference first: a crash leaves only a self-pruning entry. */
  if (sql_dep_register_fd(e, s.has_live_root ? s.live_root : s.fd, "link",
                          dest->has_live_root ? dest->live_root : dest->fd))
    goto done;
  if (promote) {
    char target[PATH_MAX] = "";
    for (char *c = src->path; *c; c++)
      if (*c == '/')
        strcat(target, "../");
    strcat(target, anchor);
    if (SQLi_batch_begin(e, s.fd, &b) ||
        SQLi_batch_op(e, &b, 'M', ".sql", NULL) ||
        SQLi_batch_op(e, &b, 'M', ".sql/shared", NULL) ||
        SQLi_batch_put(e, &b, anchor, *data, *len) ||
        SQLi_batch_op(e, &b, 'L', src->path, target) ||
        SQLi_batch_commit(e, &b))
      goto done;
  }
  rc = 0;
done:
  SQLi_batch_abort(&b);
  if (!rc && keep) {
    *keep = s;
    memset(&s, 0, sizeof(s));
    s.fd = -1;
  }
  SQLi_table_close(&s);
  if (rc) {
    free(*data);
    *data = NULL;
  }
  return rc;
}
/* CHECK LINKS: is t registered in the anchor owner's reverse references? */
int sql_xshare_registered(Env *e, Table *t, const char *abs) {
  char root[PATH_MAX], anchor[80];
  if (!sql_xshare_split(abs, root, anchor))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid cross-table anchor");
  int fd = SQLi_open_dir(e, root);
  if (fd < 0)
    return -1;
  struct stat me;
  char name[96];
  int self = t->has_live_root ? t->live_root : t->fd;
  fstat(self, &me);
  snprintf(name, sizeof(name), ".sql/deps/link-%llx-%llx",
           (unsigned long long)me.st_dev, (unsigned long long)me.st_ino);
  struct stat st;
  int ok = !fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode);
  close(fd);
  return ok ? 0
            : SQLi_fail(e, SQL_CONSTRAINT,
                        "cross-table reference to %s is not registered in its "
                        "owner's reverse references",
                        root);
}
static void reference(FILE *f, const char *anchor, Table *c, Member *m) {
  fprintf(f, "{\"anchor\":\"%s\",\"table\":", strrchr(anchor, '/') + 1);
  SQLi_json(f, (unsigned char *)c->path, strlen(c->path));
  const char *slash = strrchr(m->path, '/');
  fputs(",\"record\":", f);
  SQLi_json(f, (unsigned char *)m->path, slash - m->path);
  fputs(",\"field\":", f);
  SQLi_json(f, (unsigned char *)c->schema.node[m->field].name,
            strlen(c->schema.node[m->field].name));
  fputs(",\"member\":", f);
  SQLi_json(f, (unsigned char *)m->path, strlen(m->path));
  fputs("}\n", f);
}
/* SHOW REFERENCES OF table: every member (here and in registered consumer
 * tables) that shares one of this table's anchors. */
int sql_xshare_show(Env *e, Parser *p) {
  char *path = NULL;
  if (SQLi_need(e, p, "OF") || !(path = take(e, p)) || SQLi_end(e, p))
    return -1;
  Table s = {.fd = -1};
  char **paths = NULL;
  int n = 0, rc = -1;
  if (SQLi_table_open(e, &s, path, 0) || SQLi_scan_table(e, &s, 0))
    goto done;
  for (int i = 0; i < s.nr; i++)
    for (int j = 0; j < s.r[i].nm; j++) {
      Member *m = &s.r[i].m[j];
      char target[PATH_MAX];
      if (!S_ISLNK(m->st.st_mode))
        continue;
      if (SQLi_member_target(e, &s, m, target))
        goto done;
      if (target[0] != '/')
        reference(e->stream, target, &s, m);
    }
  if (sql_dep_paths(e, s.has_live_root ? s.live_root : s.fd, "link", &paths,
                    &n))
    goto done;
  char prefix[PATH_MAX + 16];
  snprintf(prefix, sizeof(prefix), "%s/.sql/shared/", s.path);
  for (int k = 0; k < n; k++) {
    Table c = {.fd = -1};
    if (SQLi_table_open(e, &c, paths[k], 0) || SQLi_scan_table(e, &c, 0)) {
      SQLi_table_close(&c);
      goto done;
    }
    for (int i = 0; i < c.nr; i++)
      for (int j = 0; j < c.r[i].nm; j++) {
        Member *m = &c.r[i].m[j];
        char target[PATH_MAX];
        if (S_ISLNK(m->st.st_mode) && !SQLi_member_target(e, &c, m, target) &&
            !strncmp(target, prefix, strlen(prefix)))
          reference(e->stream, target, &c, m);
      }
    SQLi_table_close(&c);
  }
  rc = 0;
done:
  for (int k = 0; k < n; k++)
    free(paths[k]);
  free(paths);
  SQLi_table_close(&s);
  return rc;
}
