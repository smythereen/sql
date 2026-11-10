/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int sql_view_validate(Env *e, SQL_ViewMap *m) {
  if (m->magic != SQL_VIEW_MAGIC ||
      !((m->version == 1 && !m->reserved) ||
        (m->version == 2 && m->reserved == 1)) ||
      m->bytes != sizeof(*m) || m->endian != 0x01020304 || !m->generation ||
      !m->Inode || !memchr(m->Source, 0, sizeof(m->Source)) ||
      m->Source[0] != '/' || !memchr(m->Query, 0, sizeof(m->Query)))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid .view identity/version/length/source/query");
  Parser *p = calloc(1, sizeof(*p));
  if (!p)
    return SQLi_fail(e, SQL_IO, "out of memory");
  int rc = SQLi_lex(e, p, m->Query), depth = 0, found = 0;
  for (int i = 0; !rc && i < p->n; i++)
    if (!p->t[i].quoted) {
      if (!strcmp(p->t[i].s, "("))
        depth++;
      else if (!strcmp(p->t[i].s, ")"))
        depth--;
      else if (!depth && !strcasecmp(p->t[i].s, "FROM")) {
        if (found++ || i + 1 >= p->n || strcmp(p->t[i + 1].s, m->Source))
          rc = SQLi_fail(e, SQL_CONSTRAINT, "view query/source pin mismatch");
      }
    }
  if (!rc && found != 1)
    rc = SQLi_fail(e, SQL_CONSTRAINT,
                   "view must have exactly one persisted source scope");
  SQLi_parser_free(p);
  free(p);
  return rc;
}
int sql_view_read(Env *e, int root, SQL_ViewMap *m) {
  struct stat st;
  int fd = sql_regular_open(e, root, ".view", 0, &st);
  if (fd < 0)
    return -1;
  if (st.st_size != sizeof(*m)) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid .view map size");
  }
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  void *p = sql_mapping(e, fd, sizeof(*m), 0);
  if (!p) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "Map .view failed");
  }
  memcpy(m, p, sizeof(*m));
  sql_unmapping(p);
  close(fd);
  return sql_view_validate(e, m);
}
int sql_view_write(Env *e, int root, SQL_ViewMap *m, int replace) {
  if (sql_view_validate(e, m))
    return -1;
  char id[33], name[80];
  if (sql_uuid(e, id))
    return -1;
  snprintf(name, sizeof(name), ".sql-map.%s.view", id);
  int fd = openat(root, name,
                  O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create private .view");
  int rc = -1, published = 0;
  void *p = NULL;
  char proc[64];
  if (ftruncate(fd, sizeof(*m)))
    goto done;
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  p = sql_mapping(e, fd, sizeof(*m), PROT_WRITE);
  if (!p)
    goto done;
  memcpy(p, m, sizeof(*m));
  UpdateMap(p, sizeof(*m));
  int sync = msync(p, sizeof(*m), MS_SYNC);
  sql_unmapping(p);
  p = NULL;
  if (sync || fsync(fd))
    goto done;
  if (replace) {
    if (renameat(root, name, root, ".view"))
      goto done;
  } else if (renameat2(root, name, root, ".view", RENAME_NOREPLACE))
    goto done;
  published = 1;
  if (fsync(root))
    goto done;
  rc = 0;
done:
  if (p)
    sql_unmapping(p);
  close(fd);
  unlinkat(root, name, 0);
  return rc ? SQLi_fail(e, published ? SQL_COMMITTED_PENDING : SQL_IO,
                        "view write %s",
                        published ? "published; durability uncertain"
                                  : "failed before publication")
            : 0;
}
/* Transactional DDL: a participant that had no definition at BEGIN records
 * generation 0, which no published definition can have. */
int sql_object_generation_or_none(Env *e, int fd, uint64_t *generation) {
  struct stat st;
  if (fstatat(fd, ".table", &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT &&
      fstatat(fd, ".view", &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) {
    *generation = 0;
    return 0;
  }
  return sql_object_generation(e, fd, generation);
}
int sql_object_generation(Env *e, int fd, uint64_t *generation) {
  struct stat st;
  if (!fstatat(fd, ".table", &st, AT_SYMLINK_NOFOLLOW)) {
    SQL_Map m;
    if (SQLi_map_read(e, fd, ".table", &m))
      return -1;
    *generation = m.generation;
    return 0;
  }
  if (errno != ENOENT)
    return SQLi_fail(e, SQL_IO, "inspect definition kind");
  int multi = sql_multiview_kind(e, fd);
  if (multi < 0)
    return -1;
  if (multi) { /* LINKED BRANCHES root: version-3 manifest */
    SQL_MultiView *mv = malloc(sizeof(*mv));
    if (!mv)
      return SQLi_fail(e, SQL_IO, "out of memory");
    int bad = sql_multiview_read(e, fd, mv);
    if (!bad)
      *generation = mv->generation;
    free(mv);
    return bad ? -1 : 0;
  }
  SQL_ViewMap m;
  if (sql_view_read(e, fd, &m))
    return -1;
  *generation = m.generation;
  return 0;
}
static int canonical(Env *e, int fd, char *path) {
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, path, PATH_MAX - 1);
  if (n < 0 || n == PATH_MAX - 1)
    return SQLi_fail(e, SQL_CONSTRAINT, "definition canonical path bound");
  path[n] = 0;
  return 0;
}
static int pinned_source(Env *e, SQL_ViewMap *m) {
  if (sql_context_active(e))
    for (unsigned i = 0; i < e->session->map.Count; i++)
      if (!strcmp(m->Source, e->session->map.Table[i].Path))
        return m->Device == e->session->map.Table[i].Device &&
                       m->Inode == e->session->map.Table[i].Inode
                   ? 0
                   : SQLi_fail(e, SQL_CONSTRAINT,
                               "view source identity changed");
  int fd = SQLi_open_dir(e, m->Source);
  if (fd < 0)
    return -1;
  struct stat st;
  int rc = fstat(fd, &st);
  close(fd);
  return rc || st.st_dev != m->Device || st.st_ino != m->Inode
             ? SQLi_fail(
                   e, SQL_CONSTRAINT,
                   "view source directory identity changed; no retargeting")
             : 0;
}
int sql_relation_open(Env *e, Table *t, const char *path) {
  if (sql_session_load(e, NULL, NULL, 0))
    return -1;
  int fd = e->pinned_view_fd ? openat(e->pinned_view_fd - 1, ".",
                                      O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                             : SQLi_open_dir(e, path);
  e->pinned_view_fd = 0;
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open relation directory");
  struct stat st;
  int staged_only = 0;
  if (fstatat(fd, ".view", &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT &&
      sql_context_active(e)) {
    char where[PATH_MAX];
    staged_only = !canonical(e, fd, where) && sql_session_staged_view(e, where);
  }
  if (!staged_only && fstatat(fd, ".view", &st, AT_SYMLINK_NOFOLLOW)) {
    int absent = errno == ENOENT;
    close(fd);
    return absent ? (SQLi_table_open(e, t, path, 0) || SQLi_scan_table(e, t, 0)
                         ? -1
                         : 0)
                  : SQLi_fail(e, SQL_IO, "inspect view definition");
  }
  t->fd = fd;
  if (!fstatat(fd, ".table", &st, AT_SYMLINK_NOFOLLOW))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "ambiguous TABLE and VIEW definitions in one directory");
  if (errno != ENOENT)
    return SQLi_fail(e, SQL_IO, "inspect table/view ambiguity");
  if (canonical(e, fd, t->path))
    return -1;
  for (int i = 0; i < e->view_depth; i++)
    if (!strcmp(t->path, e->view_stack[i]))
      return SQLi_fail(e, SQL_CONSTRAINT, "cyclic view dependency");
  if (e->view_depth >= 16)
    return SQLi_fail(e, SQL_CONSTRAINT, "view nesting exceeds 16");
  int multi = staged_only ? 0 : sql_multiview_kind(e, fd);
  if (multi < 0)
    return -1;
  if (multi)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "multi-view root has independent schemas: SELECT BRANCH "
                     "name ... from root CWD, or query exact branch directory");
  SQL_ViewMap initial = {.version = 1};
  if (!staged_only && sql_view_read(e, fd, &initial))
    return -1;
  /* Inside a transaction a LINKED view is evaluated against the staged
   * source like a saved view; its physical tree is not republished until a
   * read outside the transaction (after COMMIT). */
  int publish = initial.version == 2 && !sql_context_active(e);
  if (SQLi_lockdir(e, fd, publish) ||
      sql_session_route(e, t, 0) < 0 || SQLi_pending(e, t->fd))
    return -1;
  SQL_ViewMap map;
  if (sql_view_read(e, t->fd, &map) || pinned_source(e, &map))
    return -1;
  int definition = sql_regular_open(
      e, t->has_live_root && !staged_only ? t->live_root : t->fd, ".view", 0,
      NULL);
  if (definition < 0)
    return -1;
  int binding = sql_trace_map(e, definition, sizeof(map),
                              offsetof(SQL_ViewMap, TraceLevel), 0, &t->trace);
  close(definition);
  if (binding)
    return -1;
  Trace(SQL_TRACE, "SQL view %s generation %llu", t->path,
        (unsigned long long)map.generation);
  strcpy(e->view_stack[e->view_depth++], t->path);
  Parser *p = calloc(1, sizeof(*p));
  SQL_QueryResult *result = calloc(1, sizeof(*result));
  int rc = -1;
  if (!p || !result) {
    SQLi_fail(e, SQL_IO, "out of memory");
    goto done;
  }
  if (map.version == 2 && publish)
    result->linked_fd = t->fd + 1;
  if (SQLi_lex(e, p, map.Query) || sql_query(e, p, result))
    goto done;
  if (strcmp(result->source, map.Source) || result->device != map.Device ||
      result->inode != map.Inode) {
    SQLi_fail(e, SQL_CONSTRAINT, "view source changed during evaluation");
    goto done;
  }
  t->schema.virtualrel = 1;
  t->schema.n = result->np;
  for (int i = 0; i < result->np; i++) {
    Node *n = &t->schema.node[i];
    strcpy(n->name, result->names[i]);
    strcpy(n->type, "VIRTUAL");
    n->min = n->max = 1;
  }
  t->r = calloc(result->nr ? result->nr : 1, sizeof(Record));
  if (!t->r) {
    SQLi_fail(e, SQL_IO, "out of memory");
    goto done;
  }
  t->nr = result->nr;
  for (int i = 0; i < result->nr; i++) {
    Record *r = &t->r[i];
    r->values = result->rows[i];
    result->rows[i] = NULL;
    size_t count = 0;
    for (int j = 0; j < result->np; j++)
      count += r->values[j].collection ? r->values[j].count : 1;
    if (count > INT_MAX) {
      SQLi_fail(e, SQL_CONSTRAINT, "view member bound");
      goto done;
    }
    r->m = calloc(count ? count : 1, sizeof(Member));
    if (!r->m) {
      SQLi_fail(e, SQL_IO, "out of memory");
      goto done;
    }
    for (int j = 0; j < result->np; j++) {
      Value *v = &r->values[j];
      size_t n = v->collection ? v->count : 1;
      for (size_t k = 0; k < n; k++)
        r->m[r->nm++] =
            (Member){.field = j, .value = v->collection ? &v->items[k] : v};
    }
  }
  rc = 0;
done:
  if (p) {
    SQLi_parser_free(p);
    free(p);
  }
  if (result) {
    sql_query_free(result);
    free(result);
  }
  e->view_depth--;
  return rc;
}
int sql_view_directory(Env *e, const char *path, int create) {
  if (create && path) {
    char full[PATH_MAX];
    if (*path == '/') {
      if (strlen(path) >= sizeof(full))
        return SQLi_fail(e, SQL_CONSTRAINT, "view path bound");
      strcpy(full, path);
    } else if (SQLi_joinpath(e, full, e->cwd, path))
      return -1;
    char *last = strrchr(full, '/');
    if (!last || !SQLi_component(last + 1))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid view basename");
    char name[NAME_MAX + 1];
    strcpy(name, last + 1);
    *last = 0;
    int parent = SQLi_open_dir(e, *full ? full : "/");
    if (parent < 0)
      return -1;
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) &&
        (errno != ENOENT || mkdirat(parent, name, 0700) || fsync(parent))) {
      close(parent);
      return SQLi_fail(e, SQL_IO, "create view directory");
    }
    close(parent);
  }
  return SQLi_open_dir(e, path);
}
/* ALTER VIEW [path] PRUNE GENERATIONS [KEEP n]: explicit linked GC for a
 * LINKED view, or for every linked branch under a LINKED BRANCHES root. */
static int prune_one(Env *e, int view, unsigned keep, unsigned *removed,
                     unsigned *kept) {
  unsigned r = 0, k = 0;
  if (SQLi_lockdir(e, view, 1) || sql_linked_prune(e, view, keep, 0, &r, &k))
    return -1;
  flock(view, LOCK_UN);
  *removed += r;
  *kept += k;
  return 0;
}
static int view_prune(Env *e, Parser *p, const char *path) {
  unsigned keep = 0;
  if (SQLi_need(e, p, "PRUNE") || SQLi_need(e, p, "GENERATIONS"))
    return -1;
  if (SQLi_eat(p, "KEEP")) {
    char *n = take(e, p), *end = NULL;
    unsigned long v = n ? strtoul(n, &end, 10) : 0;
    if (!n || !*n || *end || v > 1000000)
      return SQLi_fail(e, SQL_SYNTAX, "KEEP requires 0..1000000");
    keep = v;
  }
  if (SQLi_end(e, p))
    return -1;
  if (sql_session_load(e, NULL, NULL, 0))
    return -1;
  if (sql_context_active(e))
    return SQLi_fail(e, SQL_UNSUPPORTED,
                     "PRUNE GENERATIONS is not transactional; nothing removed");
  int root = SQLi_open_dir(e, path);
  if (root < 0)
    return -1;
  unsigned removed = 0, kept = 0, views = 0;
  int rc = 0;
  struct stat st;
  if (!fstatat(root, ".linked", &st, AT_SYMLINK_NOFOLLOW)) {
    views++;
    rc = prune_one(e, root, keep, &removed, &kept);
  } else {
    DIR *d = fdopendir(dup(root));
    struct dirent *de;
    while (!rc && d && (de = readdir(d))) {
      if (de->d_name[0] == '.')
        continue;
      int sub = openat(root, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0)
        continue;
      if (!fstatat(sub, ".linked", &st, AT_SYMLINK_NOFOLLOW)) {
        views++;
        rc = prune_one(e, sub, keep, &removed, &kept);
      }
      close(sub);
    }
    if (d)
      closedir(d);
  }
  close(root);
  if (rc)
    return -1;
  if (!views)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "not a LINKED view or LINKED BRANCHES root");
  fprintf(e->stream, "{\"views\":%u,\"removed\":%u,\"kept\":%u}\n", views,
          removed, kept);
  return 0;
}
int sql_view_cmd(Env *e, const char *cmd, Parser *p, const char *path) {
  if (!strcasecmp(cmd, "alter"))
    return view_prune(e, p, path);
  int create = !strcasecmp(cmd, "create") || !strcasecmp(cmd, "define"),
      describe = !strcasecmp(cmd, "describe"), drop = !strcasecmp(cmd, "drop"),
      check = !strcasecmp(cmd, "check");
  if (!create && !describe && !drop && !check)
    return SQLi_fail(e, SQL_SYNTAX, "unsupported view administration");
  if (sql_session_load(e, NULL, NULL, 0))
    return -1;
  int txn = !describe && !check && sql_context_active(e);
  int live = -1;
  if (!create) {
    int root = SQLi_open_dir(e, path);
    if (root < 0)
      return -1;
    int kind = sql_multiview_kind(e, root);
    if (kind > 0 && txn) {
      close(root);
      return SQLi_fail(e, SQL_UNSUPPORTED,
                       "LINKED BRANCHES administration inside a transaction "
                       "is not provided; no definition changed");
    }
    if (kind) {
      int result = kind < 0 ? -1 : sql_multiview_admin(e, root, cmd, p);
      close(root);
      return result;
    }
    close(root);
  }
  SQL_QueryResult *query = calloc(1, sizeof(*query));
  if (!query)
    return SQLi_fail(e, SQL_IO, "out of memory");
  SQL_ViewMap map;
  int fd = -1, rc = -1;
  int linked = create && SQLi_eat(p, "LINKED");
  if (linked && txn) {
    free(query);
    return SQLi_fail(e, SQL_UNSUPPORTED,
                     "LINKED views publish a physical tree and cannot be "
                     "created inside a transaction; no definition changed");
  }
  if (linked && SQLi_eat(p, "BRANCHES")) {
    free(query);
    return sql_multiview_create(e, p, path);
  }

  if (create) {
    query->linked_fd = linked ? -1 : 0;
    if (SQLi_need(e, p, "AS") || SQLi_need(e, p, "SELECT") ||
        sql_query(e, p, query))
      goto done;
    map = (SQL_ViewMap){.magic = SQL_VIEW_MAGIC,
                        .version = linked ? 2 : 1,
                        .reserved = linked ? 1 : 0,
                        .bytes = sizeof(map),
                        .endian = 0x01020304,
                        .generation = 1,
                        .Device = query->device,
                        .Inode = query->inode};
    strcpy(map.Source, query->source);
    strcpy(map.Query, query->query);
  }
  fd = sql_view_directory(e, path, create);
  if (fd < 0 || SQLi_lockdir(e, fd, !describe && !check))
    goto done;
  if (txn) {
    /* Transactional view DDL: stage the view directory as a participant;
     * COMMIT publishes the .view change, ROLLBACK discards it. */
    Table vt = {.fd = fd};
    if (canonical(e, fd, vt.path))
      goto done;
    e->route_new = create;
    int routed = sql_session_route(e, &vt, 1);
    e->route_new = 0;
    if (routed < 0)
      goto done;
    live = vt.live_root;
    fd = vt.fd;
  }
  if (create) {
    DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY));
    if (!d) {
      SQLi_fail(e, SQL_IO, "inspect new view");
      goto done;
    }
    struct dirent *de;
    int nonempty = 0;
    while ((de = readdir(d)))
      if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") &&
          !sql_provisioned_metadata(e, fd, de->d_name))
        nonempty = 1;
    closedir(d);
    if (nonempty) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "CREATE/DEFINE VIEW requires an empty directory; no overwrite");
      goto done;
    }
    if (sql_dep_register(e, map.Source, "view", live >= 0 ? live : fd))
      goto done;
    rc = sql_view_write(e, fd, &map, 0);
    if (!rc && linked) {
      Parser *refresh = calloc(1, sizeof(*refresh));
      sql_query_free(query);
      query->linked_fd = fd + 1;
      if (!refresh || SQLi_lex(e, refresh, map.Query) ||
          sql_query(e, refresh, query))
        rc = SQLi_fail(e, SQL_COMMITTED_PENDING,
                       "LINKED definition published; initial tree refresh "
                       "incomplete; retry SELECT");
      if (refresh) {
        SQLi_parser_free(refresh);
        free(refresh);
      }
    }
    goto done;
  }
  if (sql_view_read(e, fd, &map))
    goto done;
  if (check) {
    if (SQLi_end(e, p) || pinned_source(e, &map))
      goto done;
    if (map.version == 2) {
      if (SQLi_lockdir(e, fd, 1))
        goto done;
      query->linked_fd = fd + 1;
    }
    char canonical_view[PATH_MAX];
    if (canonical(e, fd, canonical_view))
      goto done;
    strcpy(e->view_stack[e->view_depth++], canonical_view);
    Parser *checkquery = calloc(1, sizeof(*checkquery));
    if (!checkquery) {
      e->view_depth--;
      SQLi_fail(e, SQL_IO, "out of memory");
      goto done;
    }
    rc = SQLi_lex(e, checkquery, map.Query) || sql_query(e, checkquery, query)
             ? -1
             : 0;
    SQLi_parser_free(checkquery);
    free(checkquery);
    e->view_depth--;
    goto done;
  }
  if (describe) {
    int ddl = SQLi_eat(p, "AS");
    if ((ddl && SQLi_need(e, p, "DDL")) || SQLi_end(e, p))
      goto done;
    fprintf(
        e->stream, "%s%s\n",
        ddl ? (map.version == 2 ? "VIEW LINKED AS SELECT " : "VIEW AS SELECT ")
            : "SELECT ",
        map.Query);
    rc = 0;
  } else {
    int purge = 0;
    if (SQLi_eat(p, "INCLUDING")) {
      if (SQLi_need(e, p, "DATA"))
        goto done;
      purge = 1;
    }
    if (SQLi_eat(p, "CASCADE")) {
      SQLi_fail(e, SQL_UNSUPPORTED,
                "CASCADE is deliberately not provided; nothing changed");
      goto done;
    }
    SQLi_eat(p, "RESTRICT");
    int validate = SQLi_eat(p, "VALIDATE");
    if ((validate && SQLi_need(e, p, "ONLY")) || SQLi_end(e, p))
      goto done;
    if (map.version == 2 && txn) {
      SQLi_fail(e, SQL_UNSUPPORTED,
                "LINKED view DROP inside a transaction is not provided");
      goto done;
    }
    if (sql_dep_restrict(e, live >= 0 ? live : fd, "DROP VIEW"))
      goto done;
    if (validate)
      rc = 0;
    else if (purge)
      rc = sql_purge_view(e, fd);
    else
      rc = unlinkat(fd, ".view", 0) || fsync(fd)
               ? SQLi_fail(e, SQL_IO, "drop view definition")
               : 0;
    if (!rc && !validate && !txn)
      sql_dep_unregister(e, map.Source, "view", fd);
  }
done:
  if (fd >= 0)
    close(fd);
  if (live >= 0)
    close(live);
  sql_query_free(query);
  free(query);
  return rc;
}
