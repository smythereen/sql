/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
static pthread_mutex_t api_mutex = PTHREAD_MUTEX_INITIALIZER;
int SQLi_fail(Env *e, SQL_Status s, const char *fmt, ...) {
  if (!e->status) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->out->diagnostic, sizeof(e->out->diagnostic), fmt, ap);
    va_end(ap);
    e->status = s;
  }
  return -1;
}
void SQL_Free(SQL_Result *r) {
  if (r) {
    free(r->data);
    memset(r, 0, sizeof(*r));
  }
}
int SQLi_lex(Env *e, Parser *p, const char *s) {
  memset(p, 0, sizeof(*p));
  if (!s)
    return SQLi_fail(e, SQL_SYNTAX, "missing statement");
  while (*s) {
    while (isspace((unsigned char)*s))
      s++;
    if (!*s)
      break;
    if (p->n >= TOKMAX)
      return SQLi_fail(e, SQL_SYNTAX, "too many tokens");
    char *v;
    size_t n = 0;
    int q = 0;
    if (*s == '\'' || *s == '"') {
      int delim = *s++;
      int closed = 0;
      q = 1;
      size_t cap = strlen(s) + 1;
      v = malloc(cap);
      if (!v)
        return SQLi_fail(e, SQL_IO, "out of memory");
      while (*s) {
        if (*s == delim) {
          s++;
          if (*s == delim) {
            v[n++] = *s++;
            continue;
          }
          closed = 1;
          break;
        }
        v[n++] = *s++;
      }
      if (!closed) {
        free(v);
        return SQLi_fail(e, SQL_SYNTAX, "unterminated quoted string");
      }
      v[n] = 0;
    } else {
      const char *a = s;
      if (strchr("(),[]=<>!;", *s)) {
        s++;
        if (strchr("<>=!", *a) && *s == '=')
          s++;
        else if (*a == '<' && *s == '>')
          s++;
      } else {
        while (*s && !isspace((unsigned char)*s) && !strchr("(),[]=<>!;", *s))
          s++;
      }
      v = strndup(a, s - a);
    }
    if (!v)
      return SQLi_fail(e, SQL_IO, "out of memory");
    if (!q && v[0] == ':') {
      const SQL_Binding *binding = NULL;
      for (size_t i = 0; i < e->opt.binding_count; i++)
        if (e->opt.bindings[i].name &&
            !strcmp(e->opt.bindings[i].name, v + 1)) {
          if (binding) {
            free(v);
            return SQLi_fail(e, SQL_SYNTAX, "duplicate parameter binding");
          }
          binding = &e->opt.bindings[i];
        }
      if (!binding) {
        free(v);
        return SQLi_fail(e, SQL_SYNTAX, "unbound SQL parameter");
      }
      free(v);
      v = NULL;
      if (binding->type == SQL_BIND_NULL) {
        v = strdup("NULL");
        q = 0;
      } else {
        if (!binding->data || binding->size > VALMAX ||
            memchr(binding->data, 0, binding->size))
          return SQLi_fail(e, SQL_CONSTRAINT, "invalid parameter bytes");
        v = strndup(binding->data, binding->size);
        if (!v)
          return SQLi_fail(e, SQL_IO, "out of memory");
        Node check = {0};
        strcpy(check.name, "parameter");
        const char *type = binding->type == SQL_BIND_TEXT     ? "TEXT"
                           : binding->type == SQL_BIND_INT64  ? "INT64"
                           : binding->type == SQL_BIND_UINT64 ? "UINT64"
                           : binding->type == SQL_BIND_BOOL   ? "BOOL"
                                                              : NULL;
        if (!type) {
          free(v);
          return SQLi_fail(e, SQL_SYNTAX, "unknown binding type");
        }
        strcpy(check.type, type);
        if (SQLi_value_check(e, &check, (unsigned char *)v, strlen(v))) {
          free(v);
          return -1;
        }
        q = binding->type == SQL_BIND_TEXT;
      }
    }
    p->t[p->n++] = (Tok){v, q};
  }
  return 0;
}
void SQLi_parser_free(Parser *p) {
  for (int i = 0; i < p->n; i++)
    free(p->t[i].s);
  memset(p, 0, sizeof(*p));
}
int SQLi_is(Parser *p, const char *s) {
  return p->p < p->n && !p->t[p->p].quoted && !strcasecmp(p->t[p->p].s, s);
}
int SQLi_eat(Parser *p, const char *s) {
  if (SQLi_is(p, s)) {
    p->p++;
    return 1;
  }
  return 0;
}
int SQLi_need(Env *e, Parser *p, const char *s) {
  return SQLi_eat(p, s) ? 0
                        : SQLi_fail(e, SQL_SYNTAX, "expected %s near token %d",
                                    s, p->p + 1);
}
char *take(Env *e, Parser *p) {
  if (p->p >= p->n) {
    SQLi_fail(e, SQL_SYNTAX, "missing operand");
    return NULL;
  }
  return p->t[p->p++].s;
}
int SQLi_end(Env *e, Parser *p) {
  SQLi_eat(p, ";");
  return p->p == p->n
             ? 0
             : SQLi_fail(e, SQL_SYNTAX, "unexpected token: %s", p->t[p->p].s);
}
int SQLi_component(const char *s) {
  return s && *s && strcmp(s, ".") && strcmp(s, "..") && !strchr(s, '/') &&
         s[0] != '.' && strlen(s) <= NAME_MAX;
}
int SQLi_joinpath(Env *e, char *out, const char *a, const char *b) {
  return snprintf(out, PATH_MAX, "%s%s%s", a, *a ? "/" : "", b) >= PATH_MAX
             ? SQLi_fail(e, SQL_CONSTRAINT, "path too long")
             : 0;
}
int SQLi_open_dir(Env *e, const char *path) {
  char abs[PATH_MAX];
  if (!path)
    path = e->cwd;
  if (*path == '/') {
    if (strlen(path) >= sizeof(abs))
      return SQLi_fail(e, SQL_CONSTRAINT, "path too long");
    strcpy(abs, path);
  } else if (SQLi_joinpath(e, abs, e->cwd, path))
    return -1;
  /* Walk components without following any symlink. Pinned fds survive rename.
   */
  int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  char *copy = strdup(abs), *save = NULL;
  if (fd < 0 || !copy) {
    if (fd >= 0)
      close(fd);
    free(copy);
    return SQLi_fail(e, SQL_IO, "open root: %s", strerror(errno));
  }
  for (char *x = strtok_r(copy, "/", &save); x;
       x = strtok_r(NULL, "/", &save)) {
    if (!strcmp(x, "..")) {
      close(fd);
      free(copy);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "parent path components are not accepted");
    }
    int next = openat(fd, x, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    fd = next;
    if (fd < 0) {
      free(copy);
      return SQLi_fail(e, SQL_IO, "open directory %s: %s", path,
                       strerror(errno));
    }
  }
  free(copy);
  return fd;
}
int SQLi_lockdir(Env *e, int fd, int write) {
  unsigned timeout = e->opt.lock_timeout_ms ? e->opt.lock_timeout_ms : 5000;
  struct timespec t = {0, 10000000};
  for (unsigned n = 0;; n += 10) {
    if (!flock(fd, (write ? LOCK_EX : LOCK_SH) | LOCK_NB))
      return 0;
    if (errno != EWOULDBLOCK || n >= timeout)
      return SQLi_fail(e, SQL_IO, "table lock: %s", strerror(errno));
    nanosleep(&t, NULL);
  }
}
int SQLi_map_valid(Env *e, SQL_Map *m) {
  if (m->magic != MAGIC || m->version != SQL_VERSION ||
      m->bytes != sizeof(*m) || m->endian != 0x01020304 || m->kind > 1 ||
      !m->generation || !memchr(m->DDL, 0, sizeof(m->DDL)))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid map magic, version, length, endian, kind or "
                     "unterminated schema");
  return 0;
}
int SQLi_map_read(Env *e, int dir, const char *name, SQL_Map *m) {
  int fd = openat(dir, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open %s: %s", name, strerror(errno));
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != sizeof(*m)) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid %s map size/type", name);
  }
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  void *p = sql_mapping(e, fd, sizeof(*m), 0);
  if (!p) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "Map failed for %s", name);
  }
  memcpy(m, p, sizeof(*m));
  sql_unmapping(p);
  close(fd);
  if (SQLi_map_valid(e, m))
    return -1;
  if (!strcmp(name, ".table") && m->kind != 0)
    return SQLi_fail(e, SQL_CONSTRAINT, ".table has non-table map kind");
  return 0;
}
int SQLi_map_write(Env *e, int dir, const char *name, SQL_Map *m, int replace) {
  if (SQLi_map_valid(e, m) || (!strcmp(name, ".table") && m->kind != 0))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid map write kind/format");
  char temp[80];
  unsigned char id[16];
  if (getrandom(id, sizeof(id), 0) != sizeof(id))
    return SQLi_fail(e, SQL_IO, "random ID unavailable");
  snprintf(temp, sizeof(temp), ".sql-map.%02x%02x%02x%02x.%ld", id[0], id[1],
           id[2], id[3], (long)getpid());
  int fd = openat(dir, temp, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create map: %s", strerror(errno));
  int rc = -1, published = 0;
  if (ftruncate(fd, sizeof(*m)))
    goto io;
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  SQL_Map *p = sql_mapping(e, fd, sizeof(*m), PROT_WRITE);
  if (!p)
    goto io;
  memcpy(p, m, sizeof(*m));
  UpdateMap(p, sizeof(*m));
  int synced = msync(p, sizeof(*m), MS_SYNC);
  sql_unmapping(p);
  if (synced || fsync(fd))
    goto io;
  if (replace) {
    if (renameat(dir, temp, dir, name))
      goto io;
    published = 1;
  } else {
    if (linkat(dir, temp, dir, name, 0))
      goto io;
    published = 1;
    if (unlinkat(dir, temp, 0))
      goto io;
  }
  if (fsync(dir))
    goto io;
  rc = 0;
  goto done;
io:
  SQLi_fail(e, published ? SQL_COMMITTED_PENDING : SQL_IO,
            "durable map write %s: %s%s", name, strerror(errno),
            published ? "; metadata may be installed: inspect the map, do not "
                        "assume rollback"
                      : "");
done:
  close(fd);
  unlinkat(dir, temp, 0);
  return rc;
}
int SQLi_table_open(Env *e, Table *t, const char *path, int write) {
  memset(t, 0, sizeof(*t));
  t->fd = -1;
  if (sql_session_load(e, NULL, NULL, 0))
    return -1;
  t->fd = SQLi_open_dir(e, path);
  if (t->fd < 0)
    return -1;
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", t->fd);
  ssize_t n = readlink(proc, t->path, sizeof(t->path) - 1);
  if (n < 0)
    return SQLi_fail(e, SQL_IO, "resolve pinned table");
  t->path[n] = 0;
  if (SQLi_lockdir(e, t->fd, write))
    return -1;
  if (sql_session_route(e, t, write) < 0)
    return -1;
  struct stat view_definition;
  if (!fstatat(t->fd, ".view", &view_definition, AT_SYMLINK_NOFOLLOW))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "a VIEW or ambiguous definition is not a writable TABLE");
  if (errno != ENOENT)
    return SQLi_fail(e, SQL_IO, "inspect table/view definition kind");
  if (SQLi_pending(e, t->fd) || SQLi_map_read(e, t->fd, ".table", &t->map) ||
      SQLi_schema_text(e, t->map.DDL, &t->schema))
    return -1;
  struct stat live_definition;
  int staged_only = t->has_live_root &&
                    fstatat(t->live_root, ".table", &live_definition,
                            AT_SYMLINK_NOFOLLOW) &&
                    errno == ENOENT;
  /* A table created inside the transaction has no live word yet; Trace
   * binds to the staged definition until COMMIT publishes it. */
  int definition = sql_regular_open(
      e, t->has_live_root && !staged_only ? t->live_root : t->fd, ".table", 0,
      NULL);
  if (definition < 0)
    return -1;
  int binding = sql_trace_map(e, definition, sizeof(SQL_Map),
                              offsetof(SQL_Map, TraceLevel), 0, &t->trace);
  close(definition);
  if (binding)
    return -1;
  Trace(SQL_TRACE, "SQL table %s generation %llu", t->path,
        (unsigned long long)t->map.generation);
  return 0;
}
void SQLi_table_close(Table *t) {
  sql_trace_unmap(&t->trace);
  if (t->has_live_root)
    close(t->live_root);
  for (int i = 0; i < t->nr; i++) {
    Record *r = &t->r[i];
    free(r->path);
    for (int k = 0; k < r->nc; k++) {
      free(r->cap[k].name);
      free(r->cap[k].value);
    }
    for (int j = 0; j < r->nm; j++) {
      free(r->m[j].path);
      for (int k = 0; k < r->m[j].nc; k++) {
        free(r->m[j].cap[k].name);
        free(r->m[j].cap[k].value);
      }
    }
    free(r->m);
    if (r->values) {
      for (int j = 0; j < t->schema.n; j++)
        SQLi_value_free(&r->values[j]);
      free(r->values);
    }
  }
  free(t->r);
  SQLi_schema_free(&t->schema);
  if (t->fd >= 0)
    close(t->fd);
  memset(t, 0, sizeof(*t));
  t->fd = -1;
}
/* Secure relative regular-file read: never opens a pipe/device or follows a
 * link. */
int SQLi_open_payload(Env *e, int dir, const char *path, int *out,
                      size_t *len, unsigned long long limit) {
  *out = -1;
  *len = 0;
  char *copy = strdup(path);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "out of memory");
  int fd = dup(dir);
  char *save = NULL, *part = strtok_r(copy, "/", &save);
  if (!part || path[0] == '/') {
    free(copy);
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid relative payload path");
  }
  while (part) {
    if (!strcmp(part, "..") || !strcmp(part, ".")) {
      free(copy);
      close(fd);
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid payload path component");
    }
    char *next = strtok_r(NULL, "/", &save);
    int n = openat(fd, part,
                   O_PATH | O_NOFOLLOW | O_CLOEXEC | (next ? O_DIRECTORY : 0));
    close(fd);
    fd = n;
    if (fd < 0) {
      free(copy);
      return SQLi_fail(e, SQL_IO, "read %s: %s", path, strerror(errno));
    }
    part = next;
  }
  free(copy);
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (unsigned long long)st.st_size > limit) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "payload must be a regular file <=%s: %s",
                     limit == VALMAX ? "64 MiB" : "the streaming limit", path);
  }
  char pinned[64];
  snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
  int readable = open(pinned, O_RDONLY | O_CLOEXEC);
  close(fd);
  fd = readable;
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open pinned regular payload: %s",
                     strerror(errno));
  *out = fd;
  *len = st.st_size;
  return 0;
}
int SQLi_load_bytes(Env *e, int dir, const char *path, unsigned char **buf,
                    size_t *len) {
  *buf = NULL;
  *len = 0;
  int fd;
  size_t n;
  if (SQLi_open_payload(e, dir, path, &fd, &n, VALMAX))
    return -1;
  unsigned char *b = malloc(n + 1);
  if (!b) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  size_t off = 0;
  while (off < n) {
    int r = File_Read(fd, b + off, n - off);
    if (r <= 0) {
      free(b);
      close(fd);
      return SQLi_fail(e, SQL_IO, "short/error payload read");
    }
    off += r;
  }
  b[n] = 0;
  close(fd);
  *buf = b;
  *len = n;
  return 0;
}
void SQLi_json(FILE *f, const unsigned char *s, size_t n) {
  fputc('"', f);
  for (size_t i = 0; i < n; i++) {
    unsigned c = s[i];
    if (c == '"' || c == '\\')
      fprintf(f, "\\%c", c);
    else if (c < 32)
      fprintf(f, "\\u%04x", c);
    else
      fputc(c, f);
  }
  fputc('"', f);
}
void SQLi_shellquote(FILE *f, const char *s) {
  fputc('\'', f);
  for (; *s; s++) {
    if (*s == '\'')
      fputs("'\\''", f);
    else
      fputc(*s, f);
  }
  fputc('\'', f);
}
SQL_Status sql_run(const char *verb, int (*operation)(Env *, Parser *),
                   const char *statement, const SQL_Options *opt,
                   SQL_Result *out) {
  if (!out)
    return SQL_SYNTAX;
  memset(out, 0, sizeof(*out));
  Env e = {.out = out,
           .verb = verb,
           .statement = statement,
           .participant = UINT32_MAX};
  Parser p = {0};
  e.parser = &p;
  if (opt)
    e.opt = *opt;
  if (e.opt.binding_count > 64 || (e.opt.binding_count && !e.opt.bindings) ||
      e.opt.lock_timeout_ms > 3600000) {
    snprintf(out->diagnostic, sizeof(out->diagnostic),
             "invalid execution option bounds or binding array");
    return SQL_SYNTAX;
  }

  pthread_mutex_lock(&api_mutex);
  u32 oldtrace = TraceLevel;
  u32 *oldptr = TracePointer;
  if (opt && opt->cwd) {
    if (!realpath(opt->cwd, e.cwd)) {
      SQLi_fail(&e, SQL_IO, "cwd: %s", strerror(errno));
      goto done;
    }
  } else if (!getcwd(e.cwd, sizeof(e.cwd))) {
    SQLi_fail(&e, SQL_IO, "getcwd: %s", strerror(errno));
    goto done;
  }
  e.stream = open_memstream(&e.buf, &e.len);
  if (!e.stream) {
    SQLi_fail(&e, SQL_IO, "output spool unavailable");
    goto done;
  }
  if (SQLi_lex(&e, &p, statement))
    goto done;
  /* Resolve a supplied/session context before input_value can read FILE()
   * operands. Captured input tokens must drive this execution, not only replay.
   */
  int administration = verb && !strcmp(verb, "watch");
  administration |=
      verb && !strcmp(verb, "context") && p.n &&
      (!strcasecmp(p.t[0].s, "CREATE") || !strcasecmp(p.t[0].s, "RESUME") ||
       !strcasecmp(p.t[0].s, "MIGRATE") || !strcasecmp(p.t[0].s, "CLEAN") ||
       !strcasecmp(p.t[0].s, "INSPECT"));
  if (!administration) {
    const char *handle = NULL, *hint = NULL;
    if (verb && (!strcmp(verb, "begin") || !strcmp(verb, "commit") ||
                 !strcmp(verb, "rollback")))
      for (int i = 0; i + 1 < p.n; i++)
        if (!p.t[i].quoted) {
          if (!strcasecmp(p.t[i].s, "CONTEXT"))
            handle = p.t[i + 1].s;
          else if (!strcasecmp(p.t[i].s, "ON"))
            hint = p.t[i + 1].s;
        }
    if (sql_session_load(&e, handle, hint, 0))
      goto done;
  }
  if (sql_autocontext(&e, &p))
    goto done;
  operation(&e, &p);
done:
  if (e.session && !e.status && verb && !strcmp(verb, "recover")) {
    int apply = 0;
    for (int i = 0; i < p.n; i++)
      if (!p.t[i].quoted && !strcasecmp(p.t[i].s, "APPLY"))
        apply = 1;
    if (apply)
      sql_command_reconcile(&e);
  }
  sql_command_finish(&e);
  SQLi_parser_free(&p);
  if (e.stream && fclose(e.stream))
    SQLi_fail(&e, SQL_IO, "output spool close failed");
  if (!e.status) {
    out->data = (unsigned char *)e.buf;
    out->size = e.len;
  } else
    free(e.buf);
  sql_session_close(&e);
  /* After the command and its context are closed: no locks are held. */
  sql_fanout_drain(&e);
  TracePointer = oldptr;
  TraceLevel = oldtrace;
  pthread_mutex_unlock(&api_mutex);
  return e.status;
}
