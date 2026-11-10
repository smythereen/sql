/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
enum { LITERAL = 1, IDENT, FUNCTION, BINARY, UNARY };
struct Expr {
  int kind, quoted;
  char *text;
  Expr *a, *b;
};
static Expr *node(Env *e, int kind, const char *text, Expr *a, Expr *b) {
  Expr *x = calloc(1, sizeof(*x));
  if (!x) {
    SQLi_fail(e, SQL_IO, "out of memory");
    return NULL;
  }
  x->kind = kind;
  x->text = strdup(text);
  x->a = a;
  x->b = b;
  return x;
}
void SQLi_expr_free(Expr *x) {
  if (x) {
    SQLi_expr_free(x->a);
    SQLi_expr_free(x->b);
    free(x->text);
    free(x);
  }
}
static Expr *parse_or(Env *, Parser *, int);

static int parse_timestamp(Env *e, const char *s, char *out, size_t size) {
  size_t n = strlen(s);
  if (n != 20 && n != 25)
    return SQLi_fail(
        e, SQL_SYNTAX,
        "TIMESTAMP requires YYYY-MM-DDTHH:MM:SSZ or explicit +/-HH:MM");
  if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
      s[16] != ':')
    return SQLi_fail(e, SQL_SYNTAX, "invalid TIMESTAMP syntax");
  for (int i = 0; i < 19; i++)
    if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 &&
        !isdigit((unsigned char)s[i]))
      return SQLi_fail(e, SQL_SYNTAX, "invalid TIMESTAMP digit");
  struct tm tm = {0};
  char *z = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
  if (!z || tm.tm_sec > 59)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid date/time");
  struct tm original = tm;
  time_t stamp = timegm(&tm);
  if (original.tm_year != tm.tm_year || original.tm_mon != tm.tm_mon ||
      original.tm_mday != tm.tm_mday || original.tm_hour != tm.tm_hour ||
      original.tm_min != tm.tm_min || original.tm_sec != tm.tm_sec)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid calendar date/time");
  int offset = 0;
  if (n == 20) {
    if (s[19] != 'Z')
      return SQLi_fail(e, SQL_SYNTAX, "TIMESTAMP requires zone");
  } else {
    if ((s[19] != '+' && s[19] != '-') || s[22] != ':' ||
        !isdigit((unsigned char)s[20]) || !isdigit((unsigned char)s[21]) ||
        !isdigit((unsigned char)s[23]) || !isdigit((unsigned char)s[24]))
      return SQLi_fail(e, SQL_SYNTAX, "invalid TIMESTAMP offset");
    int h = (s[20] - '0') * 10 + s[21] - '0',
        m = (s[23] - '0') * 10 + s[24] - '0';
    if (h > 23 || m > 59)
      return SQLi_fail(e, SQL_CONSTRAINT, "TIMESTAMP offset range");
    offset = (h * 60 + m) * 60;
    if (s[19] == '-')
      offset = -offset;
  }
  snprintf(out, size, "%lld", (long long)stamp - offset);
  return 0;
}
static Expr *primary(Env *e, Parser *p, int depth) {
  if (depth > 64) {
    SQLi_fail(e, SQL_SYNTAX, "expression nesting exceeds 64");
    return NULL;
  }
  if (SQLi_eat(p, "(")) {
    Expr *x = parse_or(e, p, depth + 1);
    if (SQLi_need(e, p, ")")) {
      SQLi_expr_free(x);
      return NULL;
    }
    return x;
  }
  if (p->p >= p->n) {
    SQLi_fail(e, SQL_SYNTAX, "expression operand required");
    return NULL;
  }
  Tok t = p->t[p->p++];
  if (!t.quoted && !strcasecmp(t.s, "TIMESTAMP")) {
    if (p->p >= p->n || !p->t[p->p].quoted) {
      SQLi_fail(e, SQL_SYNTAX, "TIMESTAMP requires a quoted zoned timestamp");
      return NULL;
    }
    char stamp[64];
    if (parse_timestamp(e, p->t[p->p++].s, stamp, sizeof(stamp)))
      return NULL;
    return node(e, LITERAL, stamp, NULL, NULL);
  }

  if (!t.quoted && SQLi_eat(p, "(")) {
    Expr *a = parse_or(e, p, depth + 1), *b = NULL;
    if (SQLi_eat(p, ","))
      b = parse_or(e, p, depth + 1);
    if (!a || SQLi_need(e, p, ")")) {
      SQLi_expr_free(a);
      SQLi_expr_free(b);
      return NULL;
    }
    if (strcasecmp(t.s, "PATH") && strcasecmp(t.s, "CONTENT") &&
        strcasecmp(t.s, "COUNT") && strcasecmp(t.s, "ANY") &&
        strcasecmp(t.s, "ALL")) {
      SQLi_expr_free(a);
      SQLi_expr_free(b);
      SQLi_fail(e, SQL_SYNTAX, "unknown function %s", t.s);
      return NULL;
    }
    if ((!strcasecmp(t.s, "ANY") || !strcasecmp(t.s, "ALL")) != !!b) {
      SQLi_expr_free(a);
      SQLi_expr_free(b);
      SQLi_fail(e, SQL_SYNTAX, "wrong function arity");
      return NULL;
    }
    return node(e, FUNCTION, t.s, a, b);
  }
  int literal = t.quoted || isdigit((unsigned char)t.s[0]) || t.s[0] == '-' ||
                !strcasecmp(t.s, "NULL") || !strcasecmp(t.s, "TRUE") ||
                !strcasecmp(t.s, "FALSE");
  Expr *x = node(e, literal ? LITERAL : IDENT, t.s, NULL, NULL);
  if (x)
    x->quoted = t.quoted;
  return x;
}
static Expr *comparison(Env *e, Parser *p, int depth) {
  Expr *a = primary(e, p, depth);
  if (!a)
    return NULL;
  const char *ops[] = {
      "=", "!=", "<>", "<=", ">=", "<", ">", "IS", "HAS", NULL};
  char *op = NULL;
  for (int i = 0; ops[i]; i++)
    if (SQLi_is(p, ops[i])) {
      op = p->t[p->p++].s;
      break;
    }
  if (!op)
    return a;
  int negate = !strcasecmp(op, "IS") && SQLi_eat(p, "NOT");
  Expr *b = primary(e, p, depth);
  if (!b) {
    SQLi_expr_free(a);
    return NULL;
  }
  Expr *x = node(e, BINARY, op, a, b);
  return negate ? node(e, UNARY, "NOT", x, NULL) : x;
}
static Expr *parse_not(Env *e, Parser *p, int d) {
  if (d > 64) {
    SQLi_fail(e, SQL_SYNTAX, "expression nesting exceeds 64");
    return NULL;
  }
  if (SQLi_eat(p, "NOT")) {
    Expr *x = parse_not(e, p, d + 1);
    return x ? node(e, UNARY, "NOT", x, NULL) : NULL;
  }
  return comparison(e, p, d);
}
static Expr *parse_and(Env *e, Parser *p, int d) {
  Expr *a = parse_not(e, p, d);
  while (a && SQLi_eat(p, "AND")) {
    Expr *b = parse_not(e, p, d);
    if (!b) {
      SQLi_expr_free(a);
      return NULL;
    }
    a = node(e, BINARY, "AND", a, b);
  }
  return a;
}
static Expr *parse_or(Env *e, Parser *p, int d) {
  Expr *a = parse_and(e, p, d);
  while (a && SQLi_eat(p, "OR")) {
    Expr *b = parse_and(e, p, d);
    if (!b) {
      SQLi_expr_free(a);
      return NULL;
    }
    a = node(e, BINARY, "OR", a, b);
  }
  return a;
}
Expr *SQLi_expr_parse(Env *e, Parser *p) { return parse_or(e, p, 0); }
void SQLi_value_free(Value *v) {
  for (size_t i = 0; i < v->count; i++)
    SQLi_value_free(&v->items[i]);
  free(v->items);
  free(v->s);
  if (v->stream_fd1)
    close(v->stream_fd1 - 1);
  memset(v, 0, sizeof(*v));
}
static int copy_value(Env *e, Value *out, const Value *in) {
  *out = *in;
  out->s = NULL;
  out->items = NULL;
  out->stream_fd1 = 0;
  if (in->s) {
    out->s = malloc(in->n + 1);
    if (!out->s)
      return SQLi_fail(e, SQL_IO, "out of memory");
    memcpy(out->s, in->s, in->n);
    out->s[in->n] = 0;
  }
  if (in->collection) {
    out->items = calloc(in->count ? in->count : 1, sizeof(Value));
    if (!out->items) {
      free(out->s);
      memset(out, 0, sizeof(*out));
      return SQLi_fail(e, SQL_IO, "out of memory");
    }
    for (size_t i = 0; i < in->count; i++)
      if (copy_value(e, &out->items[i], &in->items[i])) {
        SQLi_value_free(out);
        return -1;
      }
  }
  return 0;
}
static int textval(Env *e, Value *v, const char *s, int num) {
  v->s = (unsigned char *)strdup(s);
  if (!v->s)
    return SQLi_fail(e, SQL_IO, "out of memory");
  v->n = strlen(s);
  v->numeric = num;
  v->binary = !num && !sql_utf8(v->s, v->n);
  return 0;
}
static int numval(Env *e, Value *v, long long n) {
  char b[64];
  snprintf(b, sizeof(b), "%lld", n);
  return textval(e, v, b, 1);
}
static int boolval(Env *e, Value *v, long long n) {
  int rc = numval(e, v, n);
  v->boolean = 1;
  return rc;
}
static int numparse(const Value *v, __int128 *out) {
  if (!v->numeric || !v->s || !v->n)
    return -1;
  const char *s = (const char *)v->s;
  int neg = *s == '-';
  if (neg)
    s++;
  int base = 10;
  if (s[0] == '0' && (s[1] == 'o' || s[1] == 'O')) {
    base = 8;
    s += 2;
  }
  unsigned __int128 n = 0;
  int digits = 0;
  for (; *s; s++) {
    if (*s < '0' || *s >= '0' + base)
      return -1;
    n = n * base + (*s - '0');
    if (n > ((unsigned __int128)UINT64_MAX + (neg ? 1 : 0)))
      return -1;
    digits++;
  }
  if (!digits)
    return -1;
  *out = neg ? -(__int128)n : (__int128)n;
  return 0;
}
static int truth(Env *e, Value *v) {
  __int128 n;
  if (v->null)
    return -1;
  if (!numparse(v, &n))
    return !!n;
  SQLi_fail(e, SQL_CONSTRAINT, "predicate must yield Boolean, not text");
  return -2;
}
static int compareval(Env *e, Value *a, Value *b, int *cmp) {
  if (a->collection || b->collection)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "collection comparison requires ANY/ALL");
  if (a->numeric || b->numeric) {
    __int128 x, y;
    if (numparse(a, &x) || numparse(b, &y))
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "incompatible/non-integral comparison");
    *cmp = (x > y) - (x < y);
    return 0;
  }
  size_t z = a->n < b->n ? a->n : b->n;
  int c = memcmp(a->s, b->s, z);
  *cmp = c ? c : (a->n > b->n) - (a->n < b->n);
  return 0;
}
static char filetype(mode_t m) {
  if (S_ISDIR(m))
    return 'd';
  if (S_ISREG(m))
    return 'f';
  if (S_ISLNK(m))
    return 'l';
  if (S_ISSOCK(m))
    return 's';
  if (S_ISFIFO(m))
    return 'p';
  if (S_ISBLK(m))
    return 'b';
  if (S_ISCHR(m))
    return 'c';
  return '?';
}
static int metadata(Env *e, const char *name, Table *t, Member *m, Value *v) {
  if (!m)
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "fs.* requires explicit collection member scope (ANY/ALL or "
        "PATH/CONTENT projection)");
  struct stat st = m->st;
  name += 3;
  if (!strncmp(name, "target.", 7)) {
    name += 7;
    if (!S_ISLNK(st.st_mode)) {
      v->null = 1;
      return 0;
    }
    char path[PATH_MAX];
    if (SQLi_member_target(e, t, m, path))
      return -1;
    if (path[0] == '/') {
      if (sql_xshare_stat(e, path, &st))
        return -1;
      goto described;
    }
    int sqlmeta =
        openat(t->fd, ".sql", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sqlmeta < 0)
      return SQLi_fail(e, SQL_IO, "open shared metadata root");
    int shared = openat(sqlmeta, "shared",
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(sqlmeta);
    if (shared < 0)
      return SQLi_fail(e, SQL_IO, "open shared anchor root");
    int rc = fstatat(shared, strrchr(path, '/') + 1, &st, AT_SYMLINK_NOFOLLOW);
    close(shared);
    if (rc || !S_ISREG(st.st_mode))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid shared anchor inode");
  }
described:
  if (!strcmp(name, "type")) {
    char b[2] = {filetype(st.st_mode), 0};
    return textval(e, v, b, 0);
  }
  if (!strcmp(name, "mode") || !strcmp(name, "permissions"))
    return numval(e, v, st.st_mode & 07777);
  if (!strcmp(name, "uid"))
    return numval(e, v, st.st_uid);
  if (!strcmp(name, "gid"))
    return numval(e, v, st.st_gid);
  if (!strcmp(name, "owner")) {
    struct passwd *pw = getpwuid(st.st_uid);
    if (!pw) {
      v->null = 1;
      return 0;
    }
    return textval(e, v, pw->pw_name, 0);
  }
  if (!strcmp(name, "group")) {
    struct group *gr = getgrgid(st.st_gid);
    if (!gr) {
      v->null = 1;
      return 0;
    }
    return textval(e, v, gr->gr_name, 0);
  }
  if (!strcmp(name, "size_bytes"))
    return numval(e, v, st.st_size);
  if (!strcmp(name, "mtime"))
    return numval(e, v, st.st_mtim.tv_sec);
  if (!strcmp(name, "atime"))
    return numval(e, v, st.st_atim.tv_sec);
  if (!strcmp(name, "ctime"))
    return numval(e, v, st.st_ctim.tv_sec);
  return SQLi_fail(e, SQL_SYNTAX, "unknown filesystem property fs.%s", name);
}
static int permissions(Env *e, Value *a, Value *b, int exact, Value *out) {
  if (!a->numeric || b->null)
    return SQLi_fail(e, SQL_CONSTRAINT, "permission mask types invalid");
  __int128 mode;
  if (numparse(a, &mode))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid mode");
  char *s = strdup((char *)b->s), *save = NULL;
  unsigned required = 0, forbidden = 0;
  int seen = 0;
  for (char *x = strtok_r(s, ",", &save); x; x = strtok_r(NULL, ",", &save)) {
    int shift = x[0] == 'o' ? 6 : x[0] == 'g' ? 3 : x[0] == 'w' ? 0 : -1;
    if (shift < 0 || x[1] != ':' ||
        (strlen(x) != 5 && (exact || strlen(x) < 3 || strlen(x) > 5)) ||
        (seen & (1 << shift))) {
      free(s);
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "permission mask must use o:rwx,g:rwx,w:rwx; '.' is don't care");
    }
    seen |= 1 << shift;
    if (!exact && strlen(x) != 5) {
      for (char *c = x + 2; *c; c++) {
        const char *bit = strchr("rwx", *c);
        if (!bit) {
          free(s);
          return SQLi_fail(e, SQL_CONSTRAINT,
                           "invalid HAS permission shorthand");
        }
        required |= 1 << (shift + (*c == 'r' ? 2 : *c == 'w' ? 1 : 0));
      }
      continue;
    }
    for (int i = 0; i < 3; i++) {
      int bit = 1 << (shift + 2 - i);
      if (x[i + 2] == "rwx"[i])
        required |= bit;
      else if (x[i + 2] == '-') {
        if (exact)
          forbidden |= bit;
      } else if (x[i + 2] != '.') {
        free(s);
        return SQLi_fail(e, SQL_CONSTRAINT, "invalid permission symbol");
      }
    }
  }
  free(s);
  if (!seen)
    return SQLi_fail(e, SQL_CONSTRAINT, "empty permissions mask");
  return boolval(e, out,
                 ((mode & required) == required) && !(mode & forbidden));
}
int SQLi_expr_eval(Env *e, Expr *x, Table *t, Record *r, Member *m, Value *v) {
  memset(v, 0, sizeof(*v));
  if (!x)
    return numval(e, v, 1);
  if (x->kind == LITERAL) {
    if (!x->quoted && !strcasecmp(x->text, "NULL")) {
      v->null = 1;
      return 0;
    }
    if (!x->quoted && !strcasecmp(x->text, "TRUE"))
      return boolval(e, v, 1);
    if (!x->quoted && !strcasecmp(x->text, "FALSE"))
      return boolval(e, v, 0);
    return textval(e, v, x->text, !x->quoted);
  }
  if (x->kind == IDENT) {
    if (t->schema.virtualrel) {
      int id = SQLi_field_id(&t->schema, x->text);
      if (id < 0)
        return SQLi_fail(e, SQL_SYNTAX, "view does not expose column %s",
                         x->text);
      return copy_value(
          e, v, m && m->field == id && m->value ? m->value : &r->values[id]);
    }
    if (!strcmp(x->text, "record"))
      return textval(e, v, r->path, 0);
    if (e->event_scope && !strncmp(x->text, "event_", 6)) {
      const char *s = !strcmp(x->text, "event_kind")    ? e->event_kind
                      : !strcmp(x->text, "event_field") ? e->event_field
                      : !strcmp(x->text, "event_path")  ? e->event_path
                      : !strcmp(x->text, "event_record") ? e->event_record
                                                         : NULL;
      if (s)
        return textval(e, v, s, 0);
    }
    if (!strcmp(x->text, "record_id")) {
      char id[33];
      if (!sql_id_lookup(e, t, r->path, id)) {
        v->null = 1;
        return 0;
      }
      return textval(e, v, id, 0);
    }
    if (!strncmp(x->text, "fs.", 3))
      return metadata(e, x->text, t, m, v);
    for (int i = 0; i < r->nc; i++)
      if (!strcmp(r->cap[i].name, x->text))
        return textval(e, v, r->cap[i].value, r->cap[i].numeric);
    if (m)
      for (int i = 0; i < m->nc; i++)
        if (!strcmp(m->cap[i].name, x->text))
          return textval(e, v, m->cap[i].value, m->cap[i].numeric);
    int id = SQLi_field_id(&t->schema, x->text);
    if (id < 0)
      return SQLi_fail(e, SQL_SYNTAX, "unknown identifier %s", x->text);
    if (t->schema.node[id].max != 1 && (!m || m->field != id)) {
      v->collection = 1;
      for (int i = 0; i < r->nm; i++)
        if (r->m[i].field == id)
          v->count++;
      v->items = calloc(v->count ? v->count : 1, sizeof(Value));
      if (!v->items)
        return SQLi_fail(e, SQL_IO, "out of memory");
      size_t pos = 0;
      for (int i = 0; i < r->nm; i++)
        if (r->m[i].field == id) {
          if (SQLi_expr_eval(e, x, t, r, &r->m[i], &v->items[pos++])) {
            SQLi_value_free(v);
            return -1;
          }
        }
      return 0;
    }
    int mi = SQLi_record_member(r, id, 1);
    if (mi < 0) {
      v->null = 1;
      return 0;
    }
    if (m && m->field == id)
      mi = m - r->m;
    else if (SQLi_record_member(r, id, 2) >= 0)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "collection %s requires member scope or COUNT", x->text);
    Member *item = &r->m[mi];
    if (item->isnull) {
      v->null = 1;
      return 0;
    }
    Node *n = &t->schema.node[id];
    if (e->raw_stream && !S_ISLNK(item->st.st_mode) &&
        (unsigned long long)item->st.st_size > VALMAX) {
      int fd;
      size_t z;
      if (SQLi_open_payload(e, t->fd, item->path, &fd, &z, STREAMMAX))
        return -1;
      if (SQLi_value_check_fd(e, n, fd, z)) {
        close(fd);
        return -1;
      }
      v->stream_fd1 = fd + 1;
      v->n = z;
      v->binary = 1;
      return 0;
    }
    if (SQLi_member_load(e, t, item, &v->s, &v->n))
      return -1;
    if (SQLi_value_check(e, n, v->s, v->n)) {
      SQLi_value_free(v);
      return -1;
    }
    v->numeric = !strcmp(n->type, "INT64") || !strcmp(n->type, "UINT64");
    if (!strcmp(n->type, "BOOL")) {
      int b = v->n == 4 && !memcmp(v->s, "true", 4);
      free(v->s);
      v->s = NULL;
      return boolval(e, v, b);
    }

    v->binary = !strcmp(n->type, "OCTETS") || !strcmp(n->type, "JPG") ||
                !strcmp(n->type, "MP4");
    return 0;
  }
  if (x->kind == FUNCTION) {
    if (x->a->kind != IDENT)
      return SQLi_fail(e, SQL_SYNTAX,
                       "collection function requires logical field name");
    int id = SQLi_field_id(&t->schema, x->a->text);
    if (id < 0)
      return SQLi_fail(e, SQL_SYNTAX, "unknown field %s", x->a->text);
    if (t->schema.virtualrel) {
      Value *column = &r->values[id];
      if (!strcasecmp(x->text, "COUNT"))
        return numval(e, v, column->collection ? column->count : 1);
      if (!strcasecmp(x->text, "PATH"))
        return SQLi_fail(e, SQL_SYNTAX,
                         "view values have no implicit filesystem path; "
                         "project PATH in the definition");
      if (!strcasecmp(x->text, "CONTENT"))
        return copy_value(e, v,
                          m && m->field == id && m->value ? m->value : column);
      int all = !strcasecmp(x->text, "ALL"), result = all, unknown = 0;
      size_t count = column->collection ? column->count : 1;
      for (size_t i = 0; i < count; i++) {
        Member item = {.field = id,
                       .value =
                           column->collection ? &column->items[i] : column};
        Value b = {0};
        if (SQLi_expr_eval(e, x->b, t, r, &item, &b))
          return -1;
        int yes = truth(e, &b);
        SQLi_value_free(&b);
        if (yes == -2)
          return -1;
        if (yes < 0)
          unknown = 1;
        else if ((!all && yes) || (all && !yes)) {
          result = !all;
          unknown = 0;
          break;
        }
      }
      if (unknown) {
        v->null = 1;
        return 0;
      }
      return boolval(e, v, result);
    }
    if (!strcasecmp(x->text, "COUNT")) {
      int count = 0;
      for (int i = 0; i < r->nm; i++)
        count += r->m[i].field == id;
      return numval(e, v, count);
    }
    if (!strcasecmp(x->text, "ANY") || !strcasecmp(x->text, "ALL")) {
      int all = !strcasecmp(x->text, "ALL"), result = all, unknown = 0;
      for (int i = 0; i < r->nm; i++) {
        if (r->m[i].field != id)
          continue;
        Value b = {0};
        if (SQLi_expr_eval(e, x->b, t, r, &r->m[i], &b))
          return -1;
        int yes = truth(e, &b);
        SQLi_value_free(&b);
        if (yes == -2)
          return -1;
        if (yes < 0)
          unknown = 1;
        else if ((!all && yes) || (all && !yes)) {
          result = !all;
          unknown = 0;
          break;
        }
      }
      if (unknown) {
        v->null = 1;
        return 0;
      }
      return boolval(e, v, result);
    }
    int mi =
        (m && m->field == id) ? (int)(m - r->m) : SQLi_record_member(r, id, 1);
    if (mi < 0) {
      v->null = 1;
      return 0;
    }
    if (!m && SQLi_record_member(r, id, 2) >= 0)
      return SQLi_fail(e, SQL_CONSTRAINT, "collection expansion scope missing");
    if (!strcasecmp(x->text, "PATH")) {
      char path[PATH_MAX];
      if (SQLi_joinpath(e, path, t->path, r->m[mi].path))
        return -1;
      return textval(e, v, path, 0);
    }
    return SQLi_expr_eval(e, x->a, t, r, &r->m[mi], v);
  }
  if (x->kind == UNARY) {
    Value a = {0};
    if (SQLi_expr_eval(e, x->a, t, r, m, &a))
      return -1;
    int yes = truth(e, &a);
    SQLi_value_free(&a);
    if (yes == -2)
      return -1;
    if (yes < 0) {
      v->null = 1;
      return 0;
    }
    return boolval(e, v, !yes);
  }
  Value a = {0}, b = {0};
  int rc = -1;
  if (SQLi_expr_eval(e, x->a, t, r, m, &a) ||
      SQLi_expr_eval(e, x->b, t, r, m, &b))
    goto done;
  if (!strcasecmp(x->text, "AND") || !strcasecmp(x->text, "OR")) {
    int ta = truth(e, &a), tb = truth(e, &b);
    if (ta == -2 || tb == -2)
      goto done;
    int and = !strcasecmp(x->text, "AND");
    if ((and && (ta == 0 || tb == 0)) || (!and && (ta == 1 || tb == 1)))
      rc = boolval(e, v, !and);
    else if (ta < 0 || tb < 0) {
      v->null = 1;
      rc = 0;
    } else
      rc = boolval(e, v, and);
    goto done;
  }
  if (!strcasecmp(x->text, "IS") && b.null) {
    rc = boolval(e, v, a.null);
    goto done;
  }
  if (a.null || b.null) {
    v->null = 1;
    rc = 0;
    goto done;
  }
  if (!strcasecmp(x->text, "HAS") ||
      (!strcasecmp(x->text, "IS") && a.numeric && !b.numeric)) {
    rc = permissions(e, &a, &b, !strcasecmp(x->text, "IS"), v);
    goto done;
  }
  int cmp;
  if (compareval(e, &a, &b, &cmp))
    goto done;
  int yes = 0;
  if (!strcmp(x->text, "=") || !strcasecmp(x->text, "IS"))
    yes = cmp == 0;
  else if (!strcmp(x->text, "!=") || !strcmp(x->text, "<>"))
    yes = cmp != 0;
  else if (!strcmp(x->text, "<"))
    yes = cmp < 0;
  else if (!strcmp(x->text, ">"))
    yes = cmp > 0;
  else if (!strcmp(x->text, "<="))
    yes = cmp <= 0;
  else if (!strcmp(x->text, ">="))
    yes = cmp >= 0;
  else {
    SQLi_fail(e, SQL_SYNTAX, "invalid comparison");
    goto done;
  }
  rc = boolval(e, v, yes);
done:
  SQLi_value_free(&a);
  SQLi_value_free(&b);
  return rc;
}

int SQLi_expr_validate(Env *e, Expr *x, Schema *s, int member) {
  if (!x)
    return 0;
  if (x->kind == LITERAL) {
    if (!x->quoted && strcasecmp(x->text, "NULL") &&
        strcasecmp(x->text, "TRUE") && strcasecmp(x->text, "FALSE")) {
      Value v = {
          .s = (unsigned char *)x->text, .n = strlen(x->text), .numeric = 1};
      __int128 n;
      if (numparse(&v, &n))
        return SQLi_fail(e, SQL_SYNTAX, "invalid numeric literal");
    }
    return 0;
  }
  if (x->kind == IDENT) {
    if (s->virtualrel)
      return SQLi_field_id(s, x->text) >= 0
                 ? 0
                 : SQLi_fail(e, SQL_SYNTAX, "view does not expose column %s",
                             x->text);
    if (!strcmp(x->text, "record") || !strcmp(x->text, "record_id"))
      return 0;
    if (e->event_scope &&
        (!strcmp(x->text, "event_kind") || !strcmp(x->text, "event_field") ||
         !strcmp(x->text, "event_path") || !strcmp(x->text, "event_record")))
      return 0;
    if (!strncmp(x->text, "fs.", 3)) {
      if (!member)
        return SQLi_fail(e, SQL_SYNTAX, "fs.* needs explicit member scope");
      const char *property = x->text + 3;
      if (!strncmp(property, "target.", 7))
        property += 7;
      const char *known[] = {"type",  "mode",  "permissions", "uid",
                             "gid",   "owner", "group",       "size_bytes",
                             "mtime", "atime", "ctime",       NULL};
      for (int i = 0; known[i]; i++)
        if (!strcmp(property, known[i]))
          return 0;
      return SQLi_fail(e, SQL_SYNTAX, "unknown filesystem property");
    }
    int id = SQLi_field_id(s, x->text);
    if (id >= 0 && strcmp(s->node[id].type, "DIRECTORY"))
      return 0;
    for (int i = 0; i < s->n; i++)
      for (int j = 0; j < s->node[i].nc; j++)
        if (!strcmp(s->node[i].cap[j], x->text)) {
          if (strcmp(s->node[i].type, "DIRECTORY") && !member)
            return SQLi_fail(e, SQL_SYNTAX,
                             "filename capture requires member scope");
          return 0;
        }
    return SQLi_fail(e, SQL_SYNTAX, "unknown logical identifier %s", x->text);
  }
  if (x->kind == FUNCTION) {
    if (!x->a || x->a->kind != IDENT)
      return SQLi_fail(e, SQL_SYNTAX, "function needs field identifier");
    int id = SQLi_field_id(s, x->a->text);
    if (id < 0 || !strcmp(s->node[id].type, "DIRECTORY"))
      return SQLi_fail(e, SQL_SYNTAX, "unknown function field");
    if (s->virtualrel && !strcasecmp(x->text, "PATH"))
      return SQLi_fail(e, SQL_SYNTAX,
                       "PATH must be projected by the source view definition");
    return x->b ? SQLi_expr_validate(e, x->b, s, 1) : 0;
  }
  return SQLi_expr_validate(e, x->a, s, member) ||
                 SQLi_expr_validate(e, x->b, s, member)
             ? -1
             : 0;
}
int SQLi_predicate(Env *e, Expr *x, Table *t, Record *r, Member *m) {
  Value v = {0};
  if (SQLi_expr_eval(e, x, t, r, m, &v))
    return -1;
  int b = truth(e, &v);
  SQLi_value_free(&v);
  return b == -2 ? -1 : b > 0;
}
/* Returns a PATH/CONTENT field used for explicit member expansion, otherwise
 * -1. */
static int expand_field(Expr *x, Schema *s) {
  if (x->kind == FUNCTION &&
      (!strcasecmp(x->text, "PATH") || !strcasecmp(x->text, "CONTENT")) &&
      x->a->kind == IDENT)
    return SQLi_field_id(s, x->a->text);
  return -1;
}
int sql_expr_expand_field(Expr *x, Schema *s) { return expand_field(x, s); }
typedef struct {
  Value *v, order;
  Record *source;
} OutputRow;
static void outputval(FILE *f, Value *v) {
  if (v->collection) {
    fputc('[', f);
    for (size_t i = 0; i < v->count; i++) {
      if (i)
        fputc(',', f);
      outputval(f, &v->items[i]);
    }
    fputc(']', f);
    return;
  }
  if (v->null) {
    fputs("null", f);
    return;
  }
  if (v->boolean) {
    fputs(v->n && v->s[0] != '0' ? "true" : "false", f);
    return;
  }
  if (v->binary) {
    fputs("{\"$hex\":\"", f);
    for (size_t i = 0; i < v->n; i++)
      fprintf(f, "%02x", v->s[i]);
    fputs("\"}", f);
  } else if (v->numeric) {
    __int128 x;
    if (!numparse(v, &x)) { /* exact integer spelling; octal rendered decimal */
      char b[64], *p = b + 63;
      *p = 0;
      int neg = x < 0;
      unsigned __int128 n = neg ? -x : x;
      do {
        *--p = '0' + n % 10;
        n /= 10;
      } while (n);
      if (neg)
        *--p = '-';
      fputs(p, f);
    } else
      SQLi_json(f, v->s, v->n);
  } else
    SQLi_json(f, v->s, v->n);
}
void sql_output_value(FILE *f, Value *v) { outputval(f, v); }
Expr *sql_expr_ident(Env *e, const char *name) {
  return node(e, IDENT, name, NULL, NULL);
}
int sql_expr_is_star(Expr *x) { return x->kind == IDENT && !strcmp(x->text, "*"); }
int sql_query(Env *e, Parser *p, SQL_QueryResult *collect) {
  if (e->query_depth >= 16)
    return SQLi_fail(e, SQL_CONSTRAINT, "view/query nesting exceeds 16");
  e->query_depth++;
  int tokenstart = p->p, projectionend = 0, fromindex = -1;
  char *aliases[NODES] = {0};
  Expr *proj[NODES] = {0}, *where = NULL, *order = NULL;
  int np = 0, expand = -1, desc = 0, require = 0;
  char *path = NULL, *mode = "JSON";
  int explicit_output = 0;
  unsigned long limit = ULONG_MAX, offset = 0;
  Table t = {.fd = -1};
  OutputRow *rows = NULL;
  int nr = 0, rc = -1;
  do {
    if (np == NODES) {
      SQLi_fail(e, SQL_CONSTRAINT, "too many projections");
      goto done;
    }
    proj[np] = SQLi_expr_parse(e, p);
    if (!proj[np++])
      goto done;
    if (SQLi_eat(p, "AS")) {
      aliases[np - 1] = take(e, p);
      if (!aliases[np - 1] || !SQLi_component(aliases[np - 1]) ||
          strlen(aliases[np - 1]) >= 64) {
        SQLi_fail(e, SQL_SYNTAX, "invalid projection alias");
        goto done;
      }
    }
  } while (SQLi_eat(p, ","));
  projectionend = p->p;
  if (SQLi_eat(p, "FROM")) {
    fromindex = p->p;
    path = take(e, p);
    if (!path)
      goto done;
  }
  if (SQLi_eat(p, "WHERE")) {
    where = SQLi_expr_parse(e, p);
    if (!where)
      goto done;
  }
  if (SQLi_eat(p, "ORDER")) {
    if (SQLi_need(e, p, "BY"))
      goto done;
    order = SQLi_expr_parse(e, p);
    if (!order)
      goto done;
    desc = SQLi_eat(p, "DESC");
    if (!desc)
      SQLi_eat(p, "ASC");
  }
  if (SQLi_eat(p, "LIMIT")) {
    char *s = take(e, p), *z;
    if (!s)
      goto done;
    errno = 0;
    limit = strtoul(s, &z, 10);
    if (*s == '-' || *z || errno) {
      SQLi_fail(e, SQL_SYNTAX, "invalid LIMIT");
      goto done;
    }
  }
  if (SQLi_eat(p, "OFFSET")) {
    char *s = take(e, p), *z;
    if (!s)
      goto done;
    errno = 0;
    offset = strtoul(s, &z, 10);
    if (*s == '-' || *z || errno) {
      SQLi_fail(e, SQL_SYNTAX, "invalid OFFSET");
      goto done;
    }
  }
  if (SQLi_eat(p, "OUTPUT")) {
    explicit_output = 1;
    mode = take(e, p);
    if (!mode)
      goto done;
  }
  if (SQLi_eat(p, "REQUIRE")) {
    if (SQLi_need(e, p, "MATCH"))
      goto done;
    require = 1;
  }
  if (SQLi_end(e, p))
    goto done;
  if (strcasecmp(mode, "JSON") && strcasecmp(mode, "LINES") &&
      strcasecmp(mode, "NUL") && strcasecmp(mode, "RAW")) {
    SQLi_fail(e, SQL_SYNTAX, "invalid OUTPUT mode");
    goto done;
  }
  if (collect && explicit_output) {
    SQLi_fail(e, SQL_SYNTAX,
              "saved relation query cannot contain OUTPUT; apply it to the "
              "outer SELECT");
    goto done;
  }
  int prior_missing = e->missing_null;
  e->missing_null = 1;
  int opened = sql_relation_open(e, &t, path);
  e->missing_null = prior_missing;
  if (opened)
    goto done;
  if (!explicit_output) {
    const char *modes[] = {"JSON", "LINES", "NUL", "RAW"};
    mode = (char *)modes[sql_context_output(e)];
  }

  for (int i = 0; i < np; i++)
    if (proj[i]->kind == IDENT && !strcmp(proj[i]->text, "*")) {
      Expr *expanded[NODES] = {0};
      int ne = 0;
      for (int j = 0; j < t.schema.n; j++) {
        Node *n = &t.schema.node[j];
        if (!strcmp(n->type, "DIRECTORY")) {
          for (int k = 0; k < n->nc; k++) {
            if (ne == NODES) {
              for (int k = 0; k < ne; k++)
                SQLi_expr_free(expanded[k]);
              SQLi_fail(e, SQL_CONSTRAINT, "star exceeds projection bound");
              goto done;
            }
            expanded[ne++] = node(e, IDENT, n->cap[k], NULL, NULL);
          }
        } else {
          if (ne == NODES) {
            SQLi_fail(e, SQL_CONSTRAINT, "star exceeds projection bound");
            goto done;
          }
          expanded[ne++] = node(e, IDENT, n->name, NULL, NULL);
        }
      }
      if (!ne || np + ne - 1 > NODES) {
        for (int j = 0; j < ne; j++)
          SQLi_expr_free(expanded[j]);
        SQLi_fail(e, SQL_CONSTRAINT, "star expansion exceeds projection bound");
        goto done;
      }
      if (aliases[i]) {
        for (int j = 0; j < ne; j++)
          SQLi_expr_free(expanded[j]);
        SQLi_fail(e, SQL_SYNTAX, "star cannot have a single alias");
        goto done;
      }
      memmove(aliases + i + ne, aliases + i + 1,
              (np - i - 1) * sizeof(*aliases));
      memset(aliases + i, 0, ne * sizeof(*aliases));
      SQLi_expr_free(proj[i]);
      memmove(proj + i + ne, proj + i + 1, (np - i - 1) * sizeof(*proj));
      memcpy(proj + i, expanded, ne * sizeof(*proj));
      np += ne - 1;
      i += ne - 1;
    }
  for (int j = 0; j < np; j++) {
    int x = expand_field(proj[j], &t.schema);
    if (x >= 0) {
      if (expand >= 0 && expand != x) {
        SQLi_fail(
            e, SQL_CONSTRAINT,
            "only one expanded collection per SELECT; no implicit Cartesian "
            "product");
        goto done;
      }
      expand = x;
    }
  }
  for (int i = 0; i < np; i++)
    if (SQLi_expr_validate(e, proj[i], &t.schema, expand >= 0))
      goto done;
  if (SQLi_expr_validate(e, where, &t.schema, expand >= 0) ||
      SQLi_expr_validate(e, order, &t.schema, expand >= 0))
    goto done;
  for (int i = 0; i < t.nr; i++) {
    Record *r = &t.r[i];
    int iterations = expand < 0 ? 1 : r->nm;
    for (int mi = 0; mi < iterations; mi++) {
      Member *m = expand < 0 ? NULL : &r->m[mi];
      if (m && m->field != expand)
        continue;
      int yes = SQLi_predicate(e, where, &t, r, m);
      if (yes < 0)
        goto done;
      if (!yes)
        continue;
      if (nr >= 65536) {
        SQLi_fail(e, SQL_CONSTRAINT, "result exceeds 65536 rows");
        goto done;
      }
      OutputRow *newrows = realloc(rows, (nr + 1) * sizeof(*rows));
      if (!newrows) {
        SQLi_fail(e, SQL_IO, "out of memory");
        goto done;
      }
      rows = newrows;
      OutputRow *o = &rows[nr++];
      memset(o, 0, sizeof(*o));
      o->source = r;
      o->v = calloc(np, sizeof(Value));
      if (!o->v) {
        SQLi_fail(e, SQL_IO, "out of memory");
        goto done;
      }
      /* Only the single projection of a RAW SELECT may stream. */
      e->raw_stream = np == 1 && !strcasecmp(mode, "RAW") && !collect;
      for (int j = 0; j < np; j++)
        if (SQLi_expr_eval(e, proj[j], &t, r, m, &o->v[j])) {
          e->raw_stream = 0;
          goto done;
        }
      e->raw_stream = 0;
      if (order && SQLi_expr_eval(e, order, &t, r, m, &o->order))
        goto done;
    }
  }
  if (order)
    for (int i = 1; i < nr; i++) {
      OutputRow key = rows[i];
      int j = i - 1;
      for (; j >= 0; j--) {
        int cmp = 0;
        if (rows[j].order.null || key.order.null)
          cmp = rows[j].order.null - key.order.null;
        else if (compareval(e, &rows[j].order, &key.order, &cmp))
          goto done;
        if (desc)
          cmp = -cmp;
        if (cmp <= 0)
          break;
        rows[j + 1] = rows[j];
      }
      rows[j + 1] = key;
    }
  unsigned long first = offset < (unsigned long)nr ? offset : (unsigned long)nr,
                count = (unsigned long)nr - first;
  if (count > limit)
    count = limit;
  if (!count && require) {
    SQLi_fail(e, SQL_NO_MATCH, "no matching result");
    goto done;
  }
  if (collect) {
    collect->np = np;
    collect->nr = count;
    snprintf(collect->source, sizeof(collect->source), "%s", t.path);
    struct stat identity;
    if (fstat(t.fd, &identity)) {
      SQLi_fail(e, SQL_IO, "query source identity");
      goto done;
    }
    collect->device = identity.st_dev;
    collect->inode = identity.st_ino;
    if (sql_context_active(e))
      for (unsigned i = 0; i < e->session->map.Count; i++)
        if (!strcmp(t.path, e->session->map.Table[i].Path)) {
          collect->device = e->session->map.Table[i].Device;
          collect->inode = e->session->map.Table[i].Inode;
          break;
        }
    for (int i = 0; i < np; i++) {
      if (aliases[i])
        snprintf(collect->names[i], 64, "%s", aliases[i]);
      else if (proj[i]->kind == IDENT)
        snprintf(collect->names[i], 64, "%s", proj[i]->text);
      else
        snprintf(collect->names[i], 64, "column_%d", i + 1);
      for (int j = 0; j < i; j++)
        if (!strcmp(collect->names[j], collect->names[i])) {
          SQLi_fail(e, SQL_CONSTRAINT,
                    "duplicate view column %s; use AS aliases",
                    collect->names[i]);
          goto done;
        }
    }
    if (fromindex < 0) {
      if (p->n + 2 > TOKMAX) {
        SQLi_fail(e, SQL_CONSTRAINT, "query token bound");
        goto done;
      }
      memmove(p->t + projectionend + 2, p->t + projectionend,
              (p->n - projectionend) * sizeof(Tok));
      p->t[projectionend] = (Tok){.s = strdup("FROM")};
      p->t[projectionend + 1] = (Tok){.s = strdup(t.path), .quoted = 1};
      p->n += 2;
      p->p += 2;
      fromindex = projectionend + 1;
    } else {
      char *absolute = strdup(t.path);
      if (!absolute) {
        SQLi_fail(e, SQL_IO, "out of memory");
        goto done;
      }
      free(p->t[fromindex].s);
      p->t[fromindex].s = absolute;
      p->t[fromindex].quoted = 1;
    }
    if (!p->t[fromindex].s || !p->t[fromindex - 1].s ||
        sql_tokens_text(e, p, tokenstart, p->n, collect->query,
                        sizeof(collect->query)))
      goto done;
    if (collect->linked_fd) {
      int fields[NODES];
      if (t.schema.virtualrel || sql_context_active(e)) {
        SQLi_fail(e, SQL_UNSUPPORTED,
                  "LINKED views require one physical source table outside a "
                  "transaction");
        goto done;
      }
      for (int j = 0; j < np; j++) {
        fields[j] = proj[j]->kind == IDENT
                        ? SQLi_field_id(&t.schema, proj[j]->text)
                        : -1;
        if (fields[j] < 0 ||
            !strcmp(t.schema.node[fields[j]].type, "DIRECTORY") ||
            t.schema.node[fields[j]].max != 1) {
          SQLi_fail(e, SQL_UNSUPPORTED,
                    "LINKED projection requires scalar physical fields "
                    "(optional fields allowed), with optional AS aliases");
          goto done;
        }
      }
      if (collect->linked_fd > 0) {
        Record **selected = calloc(count ? count : 1, sizeof(*selected));
        if (!selected) {
          SQLi_fail(e, SQL_IO, "linked row allocation");
          goto done;
        }
        for (unsigned long i = 0; i < count; i++)
          selected[i] = rows[first + i].source;
        int failed =
            sql_linked_refresh(e, collect->linked_fd - 1, &t, selected, count,
                               fields, np, collect->names, collect->query);
        free(selected);
        if (failed)
          goto done;
      }
    }
    collect->rows = calloc(count ? count : 1, sizeof(Value *));
    if (!collect->rows) {
      SQLi_fail(e, SQL_IO, "out of memory");
      goto done;
    }
    for (unsigned long i = 0; i < count; i++) {
      collect->rows[i] = rows[first + i].v;
      rows[first + i].v = NULL;
    }
    rc = 0;
    goto done;
  }
  if (!strcasecmp(mode, "RAW") && (np != 1 || count != 1)) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "RAW requires exactly one projected value and one result");
    goto done;
  }
  if (strcasecmp(mode, "JSON")) {
    for (unsigned long i = first; i < first + count; i++)
      for (int j = 0; j < np; j++) {
        Value *v = &rows[i].v[j];
        if (v->null || v->collection) {
          SQLi_fail(e, SQL_CONSTRAINT,
                    "NULL/collection cannot be encoded in LINES/NUL/RAW");
          goto done;
        }
        if (strcasecmp(mode, "RAW") &&
            (v->binary || memchr(v->s, 0, v->n) ||
             (!strcasecmp(mode, "LINES") && memchr(v->s, '\n', v->n)))) {
          SQLi_fail(e, SQL_CONSTRAINT, "unsafe value for output framing");
          goto done;
        }
      }
  }
  if (!strcasecmp(mode, "JSON")) {
    fputc('[', e->stream);
    for (unsigned long i = first; i < first + count; i++) {
      if (i > first)
        fputc(',', e->stream);
      fputc('[', e->stream);
      for (int j = 0; j < np; j++) {
        if (j)
          fputc(',', e->stream);
        outputval(e->stream, &rows[i].v[j]);
      }
      fputc(']', e->stream);
    }
    fputs("]\n", e->stream);
  } else
    for (unsigned long i = first; i < first + count; i++)
      for (int j = 0; j < np; j++) {
        Value *v = &rows[i].v[j];
        if (v->stream_fd1) {
          if (SQLi_stream_out(e, v->stream_fd1 - 1, v->n, e->stream))
            goto done;
          continue;
        }
        fwrite(v->s, 1, v->n, e->stream);
        if (strcasecmp(mode, "RAW"))
          fputc(!strcasecmp(mode, "NUL") ? 0 : '\n', e->stream);
      }
  rc = 0;
done:
  for (int i = 0; i < np; i++)
    SQLi_expr_free(proj[i]);
  SQLi_expr_free(where);
  SQLi_expr_free(order);
  for (int i = 0; i < nr; i++) {
    if (rows[i].v)
      for (int j = 0; j < np; j++)
        SQLi_value_free(&rows[i].v[j]);
    free(rows[i].v);
    SQLi_value_free(&rows[i].order);
  }
  free(rows);
  SQLi_table_close(&t);
  if (rc && collect)
    sql_query_free(collect);
  e->query_depth--;
  return rc;
}
void sql_query_free(SQL_QueryResult *r) {
  if (r->rows) {
    for (int i = 0; i < r->nr; i++)
      if (r->rows[i]) {
        for (int j = 0; j < r->np; j++)
          SQLi_value_free(&r->rows[i][j]);
        free(r->rows[i]);
      }
    free(r->rows);
  }
  memset(r, 0, sizeof(*r));
}
int sql_select_cmd(Env *e, Parser *p) {
  if (SQLi_is(p, "BRANCH")) {
    int root = SQLi_open_dir(e, NULL);
    if (root < 0)
      return -1;
    struct stat st;
    int multi = 0;
    if (!fstatat(root, ".view", &st, AT_SYMLINK_NOFOLLOW))
      multi = sql_multiview_kind(e, root);
    close(root);
    if (multi < 0)
      return -1;
    if (multi) {
      SQLi_eat(p, "BRANCH");
      return sql_multiview_select(e, p);
    }
  }

  return sql_query(e, p, NULL);
}
