/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
typedef struct {
  char *field, *name;
  unsigned char *data;
  size_t len;
  int isnull;
  int stream_fd1; /* fd+1 of a FILE input above 64 MiB, copied in chunks */
} Assignment;
static void assignment_free(Assignment *a) {
  free(a->data);
  a->data = NULL;
  if (a->stream_fd1)
    close(a->stream_fd1 - 1);
  a->stream_fd1 = 0;
}
static int input_value(Env *e, Parser *p, Assignment *a) {
  memset(a, 0, sizeof(*a));
  if (SQLi_eat(p, "NAMED")) {
    a->name = take(e, p);
    if (!a->name)
      return -1;
  }
  if (SQLi_eat(p, "FILE")) {
    if (SQLi_need(e, p, "("))
      return -1;
    char *path = take(e, p);
    if (!path || SQLi_need(e, p, ")"))
      return -1;
    char abs[PATH_MAX];
    if (*path == '/') {
      if (strlen(path) >= PATH_MAX)
        return SQLi_fail(e, SQL_CONSTRAINT, "import path too long");
      strcpy(abs, path);
    } else if (SQLi_joinpath(e, abs, e->cwd, path))
      return -1;
    char *last = strrchr(abs, '/');
    char base[NAME_MAX + 1];
    if (!last || !SQLi_component(last + 1))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid import basename");
    strcpy(base, last + 1);
    *last = 0;
    int dir = SQLi_open_dir(e, *abs ? abs : "/");
    if (dir < 0)
      return -1;
    int fd;
    size_t size;
    if (SQLi_open_payload(e, dir, base, &fd, &size, STREAMMAX)) {
      close(dir);
      return -1;
    }
    if (size > VALMAX) {
      close(dir);
      if (e->returning_active) {
        close(fd);
        return SQLi_fail(e, SQL_UNSUPPORTED,
                         "RETURNING cannot be combined with streamed (>64 MiB) "
                         "FILE values; no changes made");
      }
      a->stream_fd1 = fd + 1;
      a->len = size;
      return 0;
    }
    close(fd);
    int rc = SQLi_load_bytes(e, dir, base, &a->data, &a->len);
    close(dir);
    return rc;
  }
  if (p->p >= p->n)
    return SQLi_fail(e, SQL_SYNTAX, "value required");
  a->isnull = SQLi_is(p, "NULL");
  int boolean = SQLi_is(p, "TRUE") || SQLi_is(p, "FALSE");
  char *s = take(e, p);
  if (boolean)
    s = !strcasecmp(s, "TRUE") ? "true" : "false";
  a->data = (unsigned char *)strdup(a->isnull ? "" : s);
  a->len = a->isnull ? 0 : strlen(s);
  return a->data ? 0 : SQLi_fail(e, SQL_IO, "out of memory");
}
static int normalize_value(Env *e, Node *n, Assignment *a) {
  if (a->isnull)
    return n->notnull && !e->deferred
               ? SQLi_fail(e, SQL_CONSTRAINT, "NOT NULL assignment")
               : 0;
  if (a->stream_fd1)
    return SQLi_value_check_fd(e, n, a->stream_fd1 - 1, a->len);
  if (SQLi_value_check(e, n, a->data, a->len))
    return -1;
  char text[64];
  if (!strcmp(n->type, "INT64"))
    snprintf(text, sizeof(text), "%lld", strtoll((char *)a->data, NULL, 10));
  else if (!strcmp(n->type, "UINT64"))
    snprintf(text, sizeof(text), "%llu", strtoull((char *)a->data, NULL, 10));
  else
    return 0;
  unsigned char *data = (unsigned char *)strdup(text);
  if (!data)
    return SQLi_fail(e, SQL_IO, "out of memory");
  free(a->data);
  a->data = data;
  a->len = strlen(text);
  return 0;
}
static int nullpath(Env *e, const char *path, char *out) {
  const char *slash = strrchr(path, '/');
  if (!slash)
    return SQLi_fail(e, SQL_CONSTRAINT, "field outside record");
  int prefix = slash - path;
  return snprintf(out, PATH_MAX, "%.*s/.sql-null.%s", prefix, path,
                  slash + 1) >= PATH_MAX
             ? SQLi_fail(e, SQL_CONSTRAINT, "NULL metadata path too long")
             : 0;
}
static int assign_put(Env *e, Batch *b, const char *path, Assignment *a,
                      int oldnull) {
  if (a->stream_fd1 ? SQLi_batch_put_fd(e, b, path, a->stream_fd1 - 1, a->len)
                    : SQLi_batch_put(e, b, path, a->data, a->len))
    return -1;
  char marker[PATH_MAX];
  if (nullpath(e, path, marker))
    return -1;
  if (a->isnull)
    return SQLi_batch_put(e, b, marker, "", 0);
  if (oldnull)
    return SQLi_batch_op(e, b, 'D', marker, NULL);
  return 0;
}
static int sharedpath(Env *e, Table *t, Member *m, char *out) {
  if (!S_ISLNK(m->st.st_mode)) {
    strcpy(out, m->path);
    return 0;
  }
  return SQLi_member_target(e, t, m, out);
}
static int compatible(Env *e, Table *t, Member *m, Assignment *a) {
  Node *n = &t->schema.node[m->field];
  if (a->isnull) {
    if (n->notnull && !e->deferred)
      return SQLi_fail(e, SQL_CONSTRAINT, "NOT NULL %s", n->name);
    if (S_ISLNK(m->st.st_mode))
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "detach sharing before assigning NULL");
    return 0;
  }
  if (a->stream_fd1) {
    if (S_ISLNK(m->st.st_mode))
      return SQLi_fail(e, SQL_UNSUPPORTED,
                       "streamed (>64 MiB) values cannot update shared fields; "
                       "UNLINK first");
    return SQLi_value_check_fd(e, n, a->stream_fd1 - 1, a->len);
  }
  return SQLi_value_check(e, n, a->data, a->len);
}
static int randomid(Env *e, char *out) {
  unsigned char x[16];
  if (getrandom(x, 16, 0) != 16)
    return SQLi_fail(e, SQL_IO, "random ID unavailable");
  for (int i = 0; i < 16; i++)
    sprintf(out + 2 * i, "%02x", x[i]);
  return 0;
}
static int target_clause(Env *e, Parser *p, Expr **where, int *all,
                         int members) {
  if (SQLi_eat(p, "WHERE")) {
    *where = SQLi_expr_parse(e, p);
    if (!*where)
      return -1;
  }
  if (SQLi_eat(p, "ALL")) {
    if (SQLi_need(e, p, members ? "MEMBERS" : "RECORDS"))
      return -1;
    *all = 1;
  }
  if (!*where && !*all)
    return SQLi_fail(e, SQL_SYNTAX,
                     "mutation requires WHERE or explicit ALL scope");
  return 0;
}
typedef struct {
  char **p;
  int n;
} Affected;
static int affected_add(Env *e, Affected *a, const char *path) {
  if (!a)
    return 0;
  for (int i = 0; i < a->n; i++)
    if (!strcmp(a->p[i], path))
      return 0;
  char **grown = realloc(a->p, (a->n + 1) * sizeof(*grown));
  if (!grown || !(grown[a->n] = strdup(path))) {
    if (grown)
      a->p = grown;
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  a->p = grown;
  a->n++;
  return 0;
}
static void affected_free(Affected *a) {
  for (int i = 0; i < a->n; i++)
    free(a->p[i]);
  free(a->p);
  memset(a, 0, sizeof(*a));
}
static int create_record(Env *e, Table *t, Parser *p, Affected *aff) {
  char *record = NULL;
  static char generated[PATH_MAX];
  if (SQLi_eat(p, "RECORD")) {
    if (SQLi_eat(p, "GENERATED")) {
      char *under = NULL;
      unsigned long long use[4 * CAPMAX];
      int nuse = 0;
      if (SQLi_eat(p, "UNDER") && !(under = take(e, p)))
        return -1;
      if (SQLi_eat(p, "USING")) {
        if (SQLi_need(e, p, "("))
          return -1;
        do {
          char *v = take(e, p), *end;
          errno = 0;
          unsigned long long x = v && isdigit((unsigned char)*v)
                                     ? strtoull(v, &end, 10)
                                     : 0;
          if (!v || !isdigit((unsigned char)*v) || errno || *end ||
              nuse == 4 * CAPMAX)
            return SQLi_fail(e, SQL_SYNTAX,
                             "USING takes up to 32 unsigned integers");
          use[nuse++] = x;
        } while (SQLi_eat(p, ","));
        if (SQLi_need(e, p, ")"))
          return -1;
      }
      if (SQLi_generate_record(e, t, under, use, nuse, generated,
                               sizeof(generated)))
        return -1;
      record = generated;
    } else
      record = take(e, p);
  }
  if (!record)
    return SQLi_fail(e, SQL_SYNTAX, "INSERT requires RECORD path");
  int parent = SQLi_schema_record_path(e, &t->schema, record);
  if (parent < 0)
    return -1;
  struct stat st;
  if (!fstatat(t->fd, record, &st, AT_SYMLINK_NOFOLLOW))
    return SQLi_fail(e, SQL_CONSTRAINT, "record already exists");
  char *fields[NODES];
  int nf = 0;
  Assignment a[NODES] = {{0}};
  Batch b = {.fd = -1};
  int rc = -1;
  if (SQLi_need(e, p, "("))
    goto done;
  if (!SQLi_is(p, ")"))
    do {
      if (nf == NODES) {
        SQLi_fail(e, SQL_CONSTRAINT, "maximum 64 assigned members per insert");
        goto done;
      }
      fields[nf++] = take(e, p);
      if (!fields[nf - 1])
        goto done;
    } while (SQLi_eat(p, ","));
  if (SQLi_need(e, p, ")") || SQLi_need(e, p, "VALUES") || SQLi_need(e, p, "("))
    goto done;
  for (int i = 0; i < nf; i++) {
    if (input_value(e, p, &a[i]))
      goto done;
    a[i].field = fields[i];
    if (i < nf - 1 && SQLi_need(e, p, ","))
      goto done;
  }
  if (SQLi_need(e, p, ")") || SQLi_end(e, p))
    goto done;
  int counts[NODES] = {0};
  for (int j = 0; j < nf; j++) {
    int id = SQLi_field_id(&t->schema, fields[j]);
    if (id < 0 || t->schema.node[id].parent != parent) {
      SQLi_fail(e, SQL_CONSTRAINT, "field not in record: %s", fields[j]);
      goto done;
    }
    Node *n = &t->schema.node[id];
    counts[id]++;
    if (a[j].isnull) {
      if (n->notnull && !e->deferred) {
        SQLi_fail(e, SQL_CONSTRAINT, "NOT NULL %s", n->name);
        goto done;
      }
    } else if (normalize_value(e, n, &a[j]))
      goto done;
  }
  for (int i = 0; i < t->schema.n; i++) {
    Node *n = &t->schema.node[i];
    if (n->parent != parent)
      continue;
    if (!counts[i] && n->hasdefault) {
      if (nf == NODES) {
        SQLi_fail(e, SQL_CONSTRAINT, "too many defaults");
        goto done;
      }
      a[nf].field = n->name;
      a[nf].data = (unsigned char *)strdup(n->defnull ? "" : n->def);
      a[nf].len = strlen((char *)a[nf].data);
      a[nf].isnull = n->defnull;
      fields[nf++] = n->name;
      counts[i] = 1;
      if (n->defnull && n->notnull) {
        SQLi_fail(e, SQL_CONSTRAINT, "NULL default disallowed");
        goto done;
      }
      if (!n->defnull && normalize_value(e, n, &a[nf - 1]))
        goto done;
    }
    if (!e->deferred &&
        (counts[i] < n->min || (n->max >= 0 && counts[i] > n->max))) {
      SQLi_fail(e, SQL_CONSTRAINT, "insert count for %s violates [%d-%d]",
                n->name, n->min, n->max);
      goto done;
    }
  }
  if (SQLi_batch_begin(e, t->fd, &b))
    goto done;
  char path[PATH_MAX] = "", *copy = strdup(record), *save = NULL;
  int dir = dup(t->fd);
  for (char *x = strtok_r(copy, "/", &save); x;
       x = strtok_r(NULL, "/", &save)) {
    char next[PATH_MAX];
    if (SQLi_joinpath(e, next, path, x)) {
      free(copy);
      close(dir);
      goto done;
    }
    strcpy(path, next);
    if (fstatat(t->fd, path, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno != ENOENT) {
        free(copy);
        close(dir);
        SQLi_fail(e, SQL_IO, "inspect insertion path");
        goto done;
      }
      if (SQLi_batch_op(e, &b, 'M', path, NULL)) {
        free(copy);
        close(dir);
        goto done;
      }
    } else if (!S_ISDIR(st.st_mode)) {
      free(copy);
      close(dir);
      SQLi_fail(e, SQL_CONSTRAINT, "insertion parent is not a directory");
      goto done;
    }
  }
  free(copy);
  close(dir);
  if (affected_add(e, aff, record))
    goto done;
  char id[33];
  if (randomid(e, id))
    goto done;
  char idpath[PATH_MAX];
  if (SQLi_joinpath(e, idpath, record, ".sql-id") ||
      SQLi_batch_put(e, &b, idpath, id, 32))
    goto done;
  memset(counts, 0, sizeof(counts));
  char planned[NODES][NAME_MAX + 1] = {{0}};
  for (int j = 0; j < nf; j++) {
    int i = SQLi_field_id(&t->schema, fields[j]);
    char name[NAME_MAX + 1], dest[PATH_MAX];
    ++counts[i];
    int name_error = 0;
    if (a[j].name) {
      name_error = SQLi_field_name_check(e, &t->schema.node[i], a[j].name);
      if (!name_error)
        snprintf(name, sizeof(name), "%s", a[j].name);
    } else
      name_error = SQLi_field_filename_at(e, &t->schema, &t->schema.node[i],
                                          record, counts[i], name,
                                       sizeof(name));
    if (!name_error) {
      if (SQLi_field_name_unique(e, &t->schema, i, name))
        goto done;
      for (int k = 0; k < j; k++)
        if (!strcmp(planned[k], name)) {
          SQLi_fail(e, SQL_CONSTRAINT, "duplicate member filename");
          goto done;
        }
      strcpy(planned[j], name);
    }
    if (name_error || SQLi_joinpath(e, dest, record, name) ||
        assign_put(e, &b, dest, &a[j], 0))
      goto done;
  }
  rc = SQLi_batch_commit(e, &b);
done:
  SQLi_batch_abort(&b);
  for (int i = 0; i < nf; i++)
    assignment_free(&a[i]);
  return rc;
}

static int add_members(Env *e, Table *t, Parser *p, Affected *aff) {
  if (SQLi_need(e, p, "ADD") || SQLi_need(e, p, "TO"))
    return -1;
  char *field = take(e, p);
  if (!field)
    return -1;
  int id = SQLi_field_id(&t->schema, field);
  if (id < 0 || !strcmp(t->schema.node[id].type, "DIRECTORY"))
    return SQLi_fail(e, SQL_SYNTAX, "unknown collection");
  Assignment a[NODES] = {{0}};
  int na = 0, all = 0, rc = -1;
  Expr *where = NULL;
  Batch b = {.fd = -1};
  if (SQLi_need(e, p, "VALUES") || SQLi_need(e, p, "("))
    goto done;
  do {
    if (na == NODES) {
      SQLi_fail(e, SQL_CONSTRAINT, "at most 64 additions per statement");
      goto done;
    }
    if (input_value(e, p, &a[na]))
      goto done;
    na++;
  } while (SQLi_eat(p, ","));
  if (SQLi_need(e, p, ")") || target_clause(e, p, &where, &all, 0) ||
      SQLi_end(e, p))
    goto done;
  if (SQLi_expr_validate(e, where, &t->schema, 0))
    goto done;
  Node *n = &t->schema.node[id];
  for (int i = 0; i < na; i++) {
    if (a[i].isnull) {
      if (n->notnull && !e->deferred) {
        SQLi_fail(e, SQL_CONSTRAINT, "NOT NULL collection");
        goto done;
      }
    } else if (normalize_value(e, n, &a[i]))
      goto done;
  }
  if (SQLi_batch_begin(e, t->fd, &b))
    goto done;
  for (int i = 0; i < t->nr; i++) {
    Record *r = &t->r[i];
    int yes = SQLi_predicate(e, where, t, r, NULL);
    if (yes < 0)
      goto done;
    if (!yes)
      continue;
    int count = 0;
    for (int j = 0; j < r->nm; j++)
      count += r->m[j].field == id;
    if (affected_add(e, aff, r->path))
      goto done;
    if (!e->deferred && n->max >= 0 && count + na > n->max) {
      SQLi_fail(e, SQL_CONSTRAINT, "addition exceeds maximum cardinality");
      goto done;
    }
    char used[NODES][NAME_MAX + 1] = {{0}};
    unsigned index = 1;
    for (int j = 0; j < na; j++) {
      char path[PATH_MAX], name[NAME_MAX + 1];
      if (a[j].name) {
        if (SQLi_field_name_check(e, n, a[j].name))
          goto done;
        strcpy(name, a[j].name);
        if (SQLi_joinpath(e, path, r->path, name))
          goto done;
        struct stat st;
        if (!fstatat(t->fd, path, &st, AT_SYMLINK_NOFOLLOW)) {
          SQLi_fail(e, SQL_CONSTRAINT, "member already exists");
          goto done;
        }
      } else {
        for (;;) {
          if (index > 1000000) {
            SQLi_fail(e, SQL_CONSTRAINT, "member ID space exhausted");
            goto done;
          }
          if (SQLi_field_filename_at(e, &t->schema, n, r->path, index++, name,
                                     sizeof(name)) ||
              SQLi_joinpath(e, path, r->path, name))
            goto done;
          struct stat st;
          if (fstatat(t->fd, path, &st, AT_SYMLINK_NOFOLLOW)) {
            if (errno == ENOENT)
              break;
            SQLi_fail(e, SQL_IO, "inspect member name");
            goto done;
          }
          if (n->max == 1) {
            SQLi_fail(e, SQL_CONSTRAINT, "scalar member already exists");
            goto done;
          }
        }
      }
      for (int k = 0; k < j; k++)
        if (!strcmp(used[k], name)) {
          SQLi_fail(e, SQL_CONSTRAINT, "duplicate named member in statement");
          goto done;
        }
      strcpy(used[j], name);
      if (SQLi_field_name_unique(e, &t->schema, id, name))
        goto done;
      if (assign_put(e, &b, path, &a[j], 0))
        goto done;
    }
  }
  rc = SQLi_batch_commit(e, &b);
done:
  SQLi_batch_abort(&b);
  SQLi_expr_free(where);
  for (int i = 0; i < na; i++)
    assignment_free(&a[i]);
  return rc;
}
static int record_delete_safe(Env *e, Table *t, Record *r) {
  int fd =
      openat(t->fd, r->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open record for deletion validation");
  DIR *d = fdopendir(fd);
  if (!d) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "scan record deletion");
  }
  struct dirent *de;
  int rc = 0;
  while ((de = readdir(d))) {
    const char *name = de->d_name;
    if (!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, ".sql-id"))
      continue;
    int known = 0;
    for (int i = 0; i < r->nm; i++) {
      const char *base = strrchr(r->m[i].path, '/') + 1;
      if (!strcmp(base, name) || (!strncmp(name, ".sql-null.", 10) &&
                                  r->m[i].isnull && !strcmp(base, name + 10))) {
        known = 1;
        break;
      }
    }
    if (!known) {
      rc = SQLi_fail(e, SQL_CONSTRAINT,
                     "record contains unmanaged data; deleting it would not "
                     "complete safely");
      break;
    }
  }
  closedir(d);
  return rc;
}
int sql_mutate_cmd(Env *e, const char *cmd, Parser *p) {
  Table owner = {.fd = -1}; /* cross-table LINK: owner held until commit */
  Table t = {.fd = -1};
  Batch batch = {.fd = -1};
  Expr *where = NULL;
  Assignment assignments[NODES] = {{0}};
  int na = 0, rc = -1, all = 0, membermode = 0;
  char *path = NULL, *field = NULL, *source = NULL, *source_table = NULL;
  Parser *rp = NULL;
  SQL_Returning ret = {0};
  Affected aff = {0};
  char *preimage = NULL, canonical[PATH_MAX] = "";
  size_t preimage_len = 0;
  if (sql_returning_split(e, p, &rp))
    goto done;
  e->returning_active = rp != NULL;
  int insert = !strcasecmp(cmd, "insert"), update = !strcasecmp(cmd, "update"),
      del = !strcasecmp(cmd, "delete"), link = !strcasecmp(cmd, "link"),
      unlink = !strcasecmp(cmd, "unlink");
  if (insert) {
    if (SQLi_eat(p, "INTO"))
      path = take(e, p);
  } else if (update) {
    if (!SQLi_is(p, "SET"))
      path = take(e, p);
  } else if (SQLi_eat(p, "FROM"))
    path = take(e, p);
  if (update) {
    if (SQLi_need(e, p, "SET"))
      goto done;
    do {
      if (na == NODES) {
        SQLi_fail(e, SQL_CONSTRAINT, "too many assignments");
        goto done;
      }
      char *name = take(e, p);
      if (!name || SQLi_need(e, p, "="))
        goto done;
      if (input_value(e, p, &assignments[na]))
        goto done;
      assignments[na++].field = name;
    } while (SQLi_eat(p, ","));
  } else if (del && SQLi_eat(p, "MEMBERS")) {
    membermode = 1;
    field = take(e, p);
    if (!field)
      goto done;
  } else if (link || unlink) {
    if (SQLi_need(e, p, "FIELD"))
      goto done;
    field = take(e, p);
    if (!field)
      goto done;
    if (link) {
      if (SQLi_need(e, p, "TO"))
        goto done;
      source = take(e, p);
      if (!source || SQLi_need(e, p, "FROM") || SQLi_need(e, p, "SOURCE"))
        goto done;
      source_table = take(e, p);
      if (!source_table)
        goto done;
    }
  }
  if (!insert) {
    if (update) {
      if (SQLi_eat(p, "WHERE")) {
        where = SQLi_expr_parse(e, p);
        if (!where)
          goto done;
      }
      if (SQLi_eat(p, "ALL")) {
        if (SQLi_eat(p, "MEMBERS"))
          membermode = 1;
        else if (SQLi_need(e, p, "RECORDS"))
          goto done;
        all = 1;
      }
      if (!where && !all) {
        SQLi_fail(e, SQL_SYNTAX, "UPDATE requires WHERE or ALL scope");
        goto done;
      }
      if (membermode && na != 1) {
        SQLi_fail(e, SQL_SYNTAX, "ALL MEMBERS requires one assignment field");
        goto done;
      }
      if (SQLi_end(e, p))
        goto done;
    } else if (target_clause(e, p, &where, &all, membermode) || SQLi_end(e, p))
      goto done;
  }
  if (SQLi_table_open(e, &t, path, 1) || SQLi_scan_table(e, &t, 1))
    goto done;
  snprintf(canonical, sizeof(canonical), "%s", t.path);
  if (rp && sql_returning_prepare(e, rp, &t.schema, &ret))
    goto done;
  if (insert) {
    rc = SQLi_is(p, "ADD") ? add_members(e, &t, p, &aff)
                           : create_record(e, &t, p, &aff);
    goto done;
  }
  if (SQLi_expr_validate(e, where, &t.schema, membermode))
    goto done;
  int fid = -1;
  if (field) {
    fid = SQLi_field_id(&t.schema, field);
    if (fid < 0 || !strcmp(t.schema.node[fid].type, "DIRECTORY")) {
      SQLi_fail(e, SQL_SYNTAX, "unknown field %s", field);
      goto done;
    }
  }
  for (int a = 0; a < na; a++) {
    int id = SQLi_field_id(&t.schema, assignments[a].field);
    if (id < 0 || !strcmp(t.schema.node[id].type, "DIRECTORY")) {
      SQLi_fail(e, SQL_SYNTAX, "unknown assignment field");
      goto done;
    }
    Node *n = &t.schema.node[id];
    if (update && n->max != 1 && !membermode) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "collection UPDATE requires explicit ALL MEMBERS");
      goto done;
    }
    if (assignments[a].isnull) {
      if (n->notnull && !e->deferred) {
        SQLi_fail(e, SQL_CONSTRAINT, "NOT NULL assignment");
        goto done;
      }
    } else if (normalize_value(e, n, &assignments[a]))
      goto done;
  }
  Member *src = NULL;
  char anchor[PATH_MAX] = "";
  Assignment shared = {0};
  int cross = 0, nforeign = 0;
  char **foreign = NULL;      /* absolute anchors written through consumers */
  Assignment **foreign_value = NULL;
  struct stat self_identity;
  if (fstat(t.has_live_root ? t.live_root : t.fd, &self_identity)) {
    SQLi_fail(e, SQL_IO, "inspect table identity");
    goto done;
  }
  if (link) {
    if (!t.schema.links) {
      SQLi_fail(e, SQL_CONSTRAINT, "LINK requires schema LINKS INTERNAL");
      goto done;
    }
    int sd = SQLi_open_dir(e, source_table);
    if (sd < 0)
      goto done;
    struct stat a, b;
    if (fstat(sd, &a) || fstat(t.fd, &b)) {
      close(sd);
      SQLi_fail(e, SQL_IO, "inspect LINK source identity");
      goto done;
    }
    close(sd);
    if (sql_context_active(e))
      for (unsigned i = 0; i < e->session->map.Count; i++)
        if (!strcmp(t.path, e->session->map.Table[i].Path)) {
          b.st_dev = e->session->map.Table[i].Device;
          b.st_ino = e->session->map.Table[i].Inode;
          break;
        }
    if (a.st_ino != b.st_ino || a.st_dev != b.st_dev) {
      cross = 1;
      if (sql_xshare_link_source(e, &t, source_table, source, anchor,
                                 &shared.data, &shared.len, &owner))
        goto done;
    }
    for (int i = 0; !cross && i < t.nr; i++)
      for (int j = 0; j < t.r[i].nm; j++)
        if (!strcmp(t.r[i].m[j].path, source))
          src = &t.r[i].m[j];
    if (!cross && (!src || src->isnull)) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "source must identify exactly one non-NULL managed member");
      goto done;
    }
    if (cross) {
    } else if (SQLi_member_load(e, &t, src, &shared.data, &shared.len))
      goto done;
    else if (S_ISLNK(src->st.st_mode)) {
      if (sharedpath(e, &t, src, anchor))
        goto shared_done;
    } else {
      char id[33];
      if (randomid(e, id))
        goto shared_done;
      snprintf(anchor, sizeof(anchor), ".sql/shared/%s", id);
    }
  }
  if (link) {
    int destinations = 0;
    for (int i = 0; i < t.nr; i++) {
      int yes = SQLi_predicate(e, where, &t, &t.r[i], NULL);
      if (yes < 0)
        goto shared_done;
      if (!yes)
        continue;
      for (int j = 0; j < t.r[i].nm; j++)
        destinations += t.r[i].m[j].field == fid;
    }
    if (!destinations) {
      rc = 0;
      goto shared_done;
    }
  }
  if (SQLi_batch_begin(e, t.fd, &batch))
    goto shared_done;
  if (link && !cross && !S_ISLNK(src->st.st_mode)) {
    if (SQLi_batch_op(e, &batch, 'M', ".sql", NULL) ||
        SQLi_batch_op(e, &batch, 'M', ".sql/shared", NULL) ||
        SQLi_batch_put(e, &batch, anchor, shared.data, shared.len))
      goto shared_done;
    char target[PATH_MAX] = "";
    for (char *s = src->path; *s; s++)
      if (*s == '/')
        strcat(target, "../");
    strcat(target, anchor);
    if (SQLi_batch_op(e, &batch, 'L', src->path, target))
      goto shared_done;
  }
  for (int i = 0; i < t.nr; i++) {
    Record *r = &t.r[i];
    if (!membermode) {
      int yes = SQLi_predicate(e, where, &t, r, NULL);
      if (yes < 0)
        goto shared_done;
      if (!yes)
        continue;
      if (affected_add(e, &aff, r->path))
        goto shared_done;
    }
    if (update) {
      for (int a = 0; a < na; a++) {
        int id = SQLi_field_id(&t.schema, assignments[a].field);
        if (id < 0) {
          SQLi_fail(e, SQL_SYNTAX, "unknown assignment field");
          goto shared_done;
        }
        int seen = 0;
        for (int j = 0; j < r->nm; j++) {
          Member *m = &r->m[j];
          if (m->field != id)
            continue;
          seen++;
          if (t.schema.node[id].max != 1 && !membermode) {
            SQLi_fail(e, SQL_CONSTRAINT,
                      "collection UPDATE requires explicit ALL MEMBERS");
            goto shared_done;
          }
          if (membermode) {
            int yes = SQLi_predicate(e, where, &t, r, m);
            if (yes < 0)
              goto shared_done;
            if (!yes)
              continue;
            if (affected_add(e, &aff, r->path))
              goto shared_done;
          }
          if (compatible(e, &t, m, &assignments[a]))
            goto shared_done;
          char dest[PATH_MAX];
          if (sharedpath(e, &t, m, dest))
            goto shared_done;
          if (S_ISLNK(m->st.st_mode)) {
            for (int ri = 0; ri < t.nr; ri++)
              for (int mi = 0; mi < t.r[ri].nm; mi++) {
                Member *other = &t.r[ri].m[mi];
                if (!S_ISLNK(other->st.st_mode))
                  continue;
                char otherpath[PATH_MAX];
                if (sharedpath(e, &t, other, otherpath))
                  goto shared_done;
                if (!strcmp(dest, otherpath) &&
                    compatible(e, &t, other, &assignments[a]))
                  goto shared_done;
              }
            if (dest[0] == '/') {
              /* Consumer of another table's anchor: written in the owner. */
              int seen_anchor = 0;
              for (int k = 0; k < nforeign; k++)
                seen_anchor |= !strcmp(foreign[k], dest);
              if (!seen_anchor) {
                char **g = realloc(foreign, (nforeign + 1) * sizeof(*g));
                Assignment **v =
                    realloc(foreign_value, (nforeign + 1) * sizeof(*v));
                if (g)
                  foreign = g;
                if (v)
                  foreign_value = v;
                if (!g || !v || !(foreign[nforeign] = strdup(dest))) {
                  SQLi_fail(e, SQL_IO, "out of memory");
                  goto shared_done;
                }
                foreign_value[nforeign++] = &assignments[a];
              }
              continue;
            }
            if (sql_xshare_validate(e, &t, dest, &self_identity,
                                    assignments[a].data, assignments[a].len))
              goto shared_done;
            if (SQLi_batch_put(e, &batch, dest, assignments[a].data,
                               assignments[a].len))
              goto shared_done;
          } else if (assign_put(e, &batch, dest, &assignments[a], m->isnull))
            goto shared_done;
        }
        if (!seen && !membermode) {
          SQLi_fail(
              e, SQL_CONSTRAINT,
              "UPDATE cannot implicitly invent an absent member; INSERT ADD "
              "TO is required");
          goto shared_done;
        }
      }
    } else if (del) {
      if (!membermode && record_delete_safe(e, &t, r))
        goto shared_done;
      int removed[NODES] = {0};
      for (int j = 0; j < r->nm; j++) {
        Member *m = &r->m[j];
        if (membermode) {
          if (m->field != fid)
            continue;
          int yes = SQLi_predicate(e, where, &t, r, m);
          if (yes < 0)
            goto shared_done;
          if (!yes)
            continue;
          if (affected_add(e, &aff, r->path))
            goto shared_done;
        }
        removed[m->field]++;
        if (SQLi_batch_op(e, &batch, 'D', m->path, NULL))
          goto shared_done;
        if (m->isnull) {
          char null[PATH_MAX];
          if (nullpath(e, m->path, null) ||
              SQLi_batch_op(e, &batch, 'D', null, NULL))
            goto shared_done;
        }
      }
      if (membermode) {
        int count = 0;
        for (int j = 0; j < r->nm; j++)
          count += r->m[j].field == fid;
        if (!e->deferred && count - removed[fid] < t.schema.node[fid].min) {
          SQLi_fail(e, SQL_CONSTRAINT,
                    "deleting members violates minimum cardinality");
          goto shared_done;
        }
      } else {
        char id[PATH_MAX];
        if (SQLi_joinpath(e, id, r->path, ".sql-id") ||
            SQLi_batch_op(e, &batch, 'D', id, NULL) ||
            SQLi_batch_op(e, &batch, 'R', r->path, NULL))
          goto shared_done;
      }
    } else if (link || unlink) {
      for (int j = 0; j < r->nm; j++) {
        Member *m = &r->m[j];
        if (m->field != fid)
          continue;
        if (link) {
          if (compatible(e, &t, m, &shared))
            goto shared_done;
          char target[PATH_MAX] = "";
          if (anchor[0] == '/')
            strcpy(target, anchor); /* cross-table: absolute anchor */
          else {
            for (char *s = m->path; *s; s++)
              if (*s == '/')
                strcat(target, "../");
            strcat(target, anchor);
          }
          if (SQLi_batch_op(e, &batch, 'L', m->path, target))
            goto shared_done;
          if (m->isnull) {
            char np[PATH_MAX];
            if (nullpath(e, m->path, np) ||
                SQLi_batch_op(e, &batch, 'D', np, NULL))
              goto shared_done;
          }
        } else if (S_ISLNK(m->st.st_mode)) {
          unsigned char *b;
          size_t z;
          if (SQLi_member_load(e, &t, m, &b, &z))
            goto shared_done;
          int err = SQLi_batch_put(e, &batch, m->path, b, z);
          free(b);
          if (err)
            goto shared_done;
        }
      }
    }
  }
  if (rp && del) {
    FILE *mem = open_memstream(&preimage, &preimage_len);
    if (!mem) {
      SQLi_fail(e, SQL_IO, "RETURNING buffer");
      goto shared_done;
    }
    int failed = sql_returning_emit(e, &ret, &t, aff.p, aff.n, mem);
    if (fclose(mem) || failed) {
      if (!failed)
        SQLi_fail(e, SQL_IO, "RETURNING buffer");
      goto shared_done;
    }
  }
  /* Owner tables first; inside a transaction these are staged too and the
   * coordinator commits every participant atomically. */
  for (int k = 0; k < nforeign; k++)
    if (sql_xshare_write(e, foreign[k], &self_identity, foreign_value[k]->data,
                         foreign_value[k]->len))
      goto shared_done;
  rc = SQLi_batch_commit(e, &batch);
shared_done:
  for (int k = 0; k < nforeign; k++)
    free(foreign[k]);
  free(foreign);
  free(foreign_value);
  free(shared.data);
done:
  SQLi_batch_abort(&batch);
  for (int i = 0; i < na; i++)
    assignment_free(&assignments[i]);
  SQLi_expr_free(where);
  e->returning_active = 0;
  SQLi_table_close(&owner); /* LIFO: trace scopes nest */
  SQLi_table_close(&t);
  if (!rc && rp) {
    if (preimage)
      fwrite(preimage, 1, preimage_len, e->stream);
    else {
      Table post = {.fd = -1};
      if (SQLi_table_open(e, &post, canonical, 0) ||
          SQLi_scan_table(e, &post, 1) ||
          sql_returning_emit(e, &ret, &post, aff.p, aff.n, e->stream))
        rc = SQLi_fail(e, SQL_IO, "mutation committed, but its RETURNING "
                                  "post-image could not be read");
      SQLi_table_close(&post);
    }
  }
  free(preimage);
  sql_returning_free(&ret);
  affected_free(&aff);
  if (rp) {
    SQLi_parser_free(rp);
    free(rp);
  }
  return rc;
}
