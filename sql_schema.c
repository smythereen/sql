/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
static int copystr(Env *e, char *d, size_t n, const char *s) {
  if (!s || strlen(s) >= n)
    return SQLi_fail(e, SQL_CONSTRAINT, "schema token exceeds bound");
  strcpy(d, s);
  return 0;
}
static int ident(const char *s) {
  if (!s || !isalpha((unsigned char)*s))
    return 0;
  for (; *s; s++)
    if (!isalnum((unsigned char)*s) && *s != '_')
      return 0;
  return 1;
}
static int format_check(Env *e, const char *s) {
  int conversions = 0;
  for (; *s; s++) {
    if (*s == '/')
      return SQLi_fail(e, SQL_CONSTRAINT, "FORMAT cannot contain slash");
    if (*s != '%')
      continue;
    s++;
    if (*s == '%')
      continue;
    int width = 0, precision = 0;
    while (isdigit((unsigned char)*s)) {
      width = width * 10 + (*s++ - '0');
      if (width > 64)
        return SQLi_fail(e, SQL_CONSTRAINT, "FORMAT width exceeds 64");
    }
    if (*s == '.') {
      s++;
      if (!isdigit((unsigned char)*s))
        return SQLi_fail(e, SQL_CONSTRAINT, "FORMAT precision required");
      while (isdigit((unsigned char)*s)) {
        precision = precision * 10 + (*s++ - '0');
        if (precision > 64)
          return SQLi_fail(e, SQL_CONSTRAINT, "FORMAT precision exceeds 64");
      }
    }
    if (*s != 'u' || ++conversions > CAPMAX)
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "FORMAT supports %%[width][.precision]u and %%%% only, at "
          "most 8 conversions");
  }
  return 0;
}
static int cardinality(Env *e, Parser *p, Node *n) {
  if (!SQLi_eat(p, "["))
    return 0;
  char *a = take(e, p);
  if (!a)
    return -1;
  /* lexer keeps 1-4 as a single token. */ char *x;
  errno = 0;
  long lo = strtol(a, &x, 10);
  if (errno || x == a || lo < 0 || lo > 1000000)
    return SQLi_fail(e, SQL_SYNTAX, "invalid minimum count");
  long hi = lo;
  if (*x == '-') {
    x++;
    if (*x) {
      char *z;
      hi = strtol(x, &z, 10);
      if (*z || hi < lo || hi > 1000000)
        return SQLi_fail(e, SQL_SYNTAX, "invalid maximum count");
    } else
      hi = -1;
  } else if (*x)
    return SQLi_fail(e, SQL_SYNTAX, "invalid cardinality");
  n->min = lo;
  n->max = hi;
  return SQLi_need(e, p, "]");
}
static int declarations(Env *e, Parser *p, Schema *s, int parent) {
  if (SQLi_need(e, p, "("))
    return -1;
  while (!SQLi_eat(p, ")")) {
    if (s->n >= NODES)
      return SQLi_fail(e, SQL_CONSTRAINT, "maximum 64 schema nodes");
    int id = s->n++;
    Node *n = &s->node[id];
    memset(n, 0, sizeof(*n));
    n->parent = parent;
    n->min = n->max = 1;
    char *name = take(e, p), *type = take(e, p);
    if (!name || !type || !ident(name))
      return SQLi_fail(e, SQL_SYNTAX, "invalid field identifier");
    for (int j = 0; j < id; j++)
      if (!strcmp(s->node[j].name, name))
        return SQLi_fail(
            e, SQL_CONSTRAINT,
            "logical identifiers must be unique throughout schema");
    if (copystr(e, n->name, sizeof(n->name), name) ||
        copystr(e, n->type, sizeof(n->type), type))
      return -1;
    for (char *x = n->type; *x; x++)
      *x = toupper((unsigned char)*x);
    const char *types[] = {"DIRECTORY", "TEXT", "INT64", "UINT64", "BOOL",
                           "OCTETS",    "JPG",  "MP4",   "SH",     NULL};
    int known = 0;
    for (int i = 0; types[i]; i++)
      known |= !strcmp(types[i], n->type);
    if (!known)
      return SQLi_fail(e, SQL_SYNTAX, "unknown type %s", type);
    if (!strcmp(n->type, "DIRECTORY")) {
      n->min = 0;
      n->max = -1;
    }
    for (;;) {
      if (SQLi_is(p, "[")) {
        if (cardinality(e, p, n))
          return -1;
      } else if (SQLi_eat(p, "RECORD"))
        n->record = 1;
      else if (SQLi_eat(p, "FORMAT")) {
        if (copystr(e, n->format, sizeof(n->format), take(e, p)) ||
            format_check(e, n->format))
          return -1;
      } else if (SQLi_eat(p, "MATCH")) {
        if (copystr(e, n->match, sizeof(n->match), take(e, p)))
          return -1;
      } else if (SQLi_eat(p, "CAPTURE")) {
        if (SQLi_need(e, p, "("))
          return -1;
        do {
          if (n->nc >= CAPMAX)
            return SQLi_fail(e, SQL_CONSTRAINT, "maximum 8 capture groups");
          char *c = take(e, p);
          if (!ident(c) || copystr(e, n->cap[n->nc], 64, c))
            return SQLi_fail(e, SQL_SYNTAX, "invalid capture name");
          strcpy(n->captype[n->nc], "TEXT");
          if (SQLi_is(p, "UINT64") || SQLi_is(p, "INT64") ||
              SQLi_is(p, "TEXT")) {
            char *t = take(e, p);
            copystr(e, n->captype[n->nc], 16, t);
          }
          n->nc++;
        } while (SQLi_eat(p, ","));
        if (SQLi_need(e, p, ")"))
          return -1;
      } else if (SQLi_eat(p, "STRICT")) {
        n->strict = 1;
      } else if (SQLi_eat(p, "NOT")) {
        if (SQLi_need(e, p, "NULL"))
          return -1;
        n->notnull = 1;
      } else if (SQLi_eat(p, "DEFAULT")) {
        n->hasdefault = 1;
        n->defnull = SQLi_is(p, "NULL");
        if (copystr(e, n->def, sizeof(n->def), take(e, p)))
          return -1;
      } else
        break;
    }
    if (n->record && strcmp(n->type, "DIRECTORY"))
      return SQLi_fail(e, SQL_CONSTRAINT, "RECORD must mark a directory");
    if (n->match[0]) {
      int rc = regcomp(&n->re, n->match, REG_EXTENDED);
      if (rc) {
        char b[256];
        regerror(rc, &n->re, b, sizeof(b));
        return SQLi_fail(e, SQL_CONSTRAINT, "bad MATCH: %s", b);
      }
      n->compiled = 1;
      if (n->nc > (int)n->re.re_nsub)
        return SQLi_fail(e, SQL_CONSTRAINT, "CAPTURE exceeds regex groups");
    } else if (n->nc)
      return SQLi_fail(e, SQL_CONSTRAINT, "CAPTURE requires MATCH");
    if (!strcmp(n->type, "DIRECTORY")) {
      if (declarations(e, p, s, id))
        return -1;
    }
    if (SQLi_eat(p, ","))
      continue;
    if (SQLi_is(p, ")"))
      continue;
    return SQLi_fail(e, SQL_SYNTAX, "expected comma or closing parenthesis");
  }
  return 0;
}
int SQLi_schema_parse(Env *e, Parser *p, Schema *s) {
  memset(s, 0, sizeof(*s));
  if (declarations(e, p, s, -1))
    return -1;
  int records = 0;
  for (int i = 0; i < s->n; i++) {
    Node *n = &s->node[i];
    if (n->record)
      records++;
    if (strcmp(n->type, "DIRECTORY")) {
      int par = n->parent;
      if (par < 0 || !s->node[par].record)
        return SQLi_fail(
            e, SQL_CONSTRAINT,
            "fields must be direct children of an explicit RECORD directory");
    } else if (n->parent >= 0 && s->node[n->parent].record)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "nested directories below RECORD not supported by v1");
  }
  for (int i = 0; i < s->n; i++) {
    Node *n = &s->node[i];
    if (n->hasdefault) {
      if (n->defnull && n->notnull)
        return SQLi_fail(e, SQL_CONSTRAINT,
                         "NULL default conflicts with NOT NULL");
      if (!n->defnull &&
          SQLi_value_check(e, n, (unsigned char *)n->def, strlen(n->def)))
        return -1;
    }
    for (int j = 0; j < n->nc; j++) {
      for (char *c = n->captype[j]; *c; c++)
        *c = toupper((unsigned char)*c);
      for (int k = 0; k < s->n; k++) {
        if (k != i && !strcmp(n->cap[j], s->node[k].name))
          return SQLi_fail(e, SQL_CONSTRAINT,
                           "capture collides with logical identifier");
        for (int m = 0; m < s->node[k].nc; m++)
          if ((k < i || (k == i && m < j)) &&
              !strcmp(n->cap[j], s->node[k].cap[m]))
            return SQLi_fail(e, SQL_CONSTRAINT, "duplicate capture name");
      }
    }
  }
  if (records != 1)
    return SQLi_fail(e, SQL_CONSTRAINT, "exactly one RECORD boundary required");
  return 0;
}
int SQLi_schema_text(Env *e, const char *text, Schema *s) {
  Parser p = {0};
  int rc = SQLi_lex(e, &p, text);
  if (!rc)
    rc = SQLi_schema_parse(e, &p, s);
  if (!rc && SQLi_eat(&p, "UNMATCHED")) {
    if (SQLi_eat(&p, "IGNORE"))
      s->unmatched = 1;
    else if (SQLi_need(e, &p, "ERROR"))
      rc = -1;
  }
  if (!rc && SQLi_eat(&p, "LINKS")) {
    if (SQLi_eat(&p, "INTERNAL"))
      s->links = 1;
    else if (SQLi_need(e, &p, "REJECT"))
      rc = -1;
  }
  if (!rc)
    rc = SQLi_end(e, &p);
  SQLi_parser_free(&p);
  return rc;
}
void SQLi_schema_free(Schema *s) {
  for (int i = 0; i < s->n; i++)
    if (s->node[i].compiled)
      regfree(&s->node[i].re);
  memset(s, 0, sizeof(*s));
}
int SQLi_field_id(Schema *s, const char *name) {
  for (int i = 0; i < s->n; i++)
    if (!strcmp(s->node[i].name, name))
      return i;
  return -1;
}
int SQLi_record_member(Record *r, int field, int ordinal) {
  for (int i = 0; i < r->nm; i++)
    if (r->m[i].field == field && !--ordinal)
      return i;
  return -1;
}
int sql_utf8(const unsigned char *b, size_t n) {
  for (size_t i = 0; i < n;) {
    unsigned x = b[i++];
    if (x < 128) {
      if (!x)
        return 0;
      continue;
    }
    int k;
    unsigned cp;
    if (x >= 0xc2 && x <= 0xdf) {
      k = 1;
      cp = x & 31;
    } else if (x >= 0xe0 && x <= 0xef) {
      k = 2;
      cp = x & 15;
    } else if (x >= 0xf0 && x <= 0xf4) {
      k = 3;
      cp = x & 7;
    } else
      return 0;
    int orig = k;
    while (k--) {
      if (i >= n || (b[i] & 0xc0) != 0x80)
        return 0;
      cp = cp * 64 + (b[i++] & 63);
    }
    if ((orig == 2 && cp < 0x800) || (orig == 3 && cp < 0x10000) ||
        cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      return 0;
  }
  return 1;
}
int SQLi_value_check(Env *e, Node *n, const unsigned char *b, size_t z) {
  if (!strcmp(n->type, "JPG") || !strcmp(n->type, "MP4"))
    return SQLi_media_check(e, n, b, z);
  return SQLi_value_check_bytes(e, n, b, z);
}
int SQLi_value_check_bytes(Env *e, Node *n, const unsigned char *b, size_t z) {
  const char *t = n->type;
  int valid = 1;
  if (!strcmp(t, "TEXT") || !strcmp(t, "SH"))
    valid = sql_utf8(b, z);
  else if (!strcmp(t, "INT64") || !strcmp(t, "UINT64")) {
    char *s = strndup((const char *)b, z), *x;
    errno = 0;
    if (!s)
      return SQLi_fail(e, SQL_IO, "out of memory");
    if (!strcmp(t, "UINT64")) {
      strtoull(s, &x, 10);
      valid = z && *s != '-' && isdigit((unsigned char)*s) && !errno && !*x;
    } else {
      strtoll(s, &x, 10);
      valid = z && (*s == '-' || isdigit((unsigned char)*s)) && !errno && !*x;
    }
    valid &= strlen(s) == z;
    free(s);
  } else if (!strcmp(t, "BOOL"))
    valid =
        (z == 4 && !memcmp(b, "true", 4)) || (z == 5 && !memcmp(b, "false", 5));
  else if (!strcmp(t, "JPG"))
    valid = z >= 4 && b[0] == 255 && b[1] == 216 && b[z - 2] == 255 &&
            b[z - 1] == 217;
  else if (!strcmp(t, "MP4"))
    valid = z >= 12 && !memcmp(b + 4, "ftyp", 4);
  if (!valid)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid %s value for %s", t, n->name);
  return 0;
}
static void extname(Node *n, char *out, size_t z) {
  if (!strcmp(n->type, "JPG"))
    snprintf(out, z, "jpg");
  else if (!strcmp(n->type, "MP4"))
    snprintf(out, z, "mp4");
  else if (!strcmp(n->type, "SH"))
    snprintf(out, z, "sh");
  else
    out[0] = 0;
}
static int matches(Node *n, const char *name, regmatch_t *m) {
  if (n->compiled)
    return !regexec(&n->re, name, CAPMAX + 1, m, 0) && m[0].rm_so == 0 &&
           (size_t)m[0].rm_eo == strlen(name);
  if (!strcmp(n->type, "DIRECTORY"))
    return SQLi_component(name);
  char ext[16], base[96];
  extname(n, ext, sizeof(ext));
  snprintf(base, sizeof(base), "%s%s%s", n->name, *ext ? "." : "", ext);
  if (n->max == 1)
    return !strcmp(name, base);
  size_t z = strlen(n->name);
  if (strncmp(name, n->name, z) || name[z] != '.')
    return 0;
  const char *s = name + z + 1;
  if (!isdigit((unsigned char)*s))
    return 0;
  while (isdigit((unsigned char)*s))
    s++;
  return *ext ? (*s == '.' && !strcmp(s + 1, ext)) : !*s;
}
int SQLi_member_target(Env *e, Table *t, Member *m, char *out) {
  if (!S_ISLNK(m->st.st_mode))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "target metadata requires a symbolic member");
  if (!t->schema.links)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "symbolic fields require LINKS INTERNAL");
  char target[PATH_MAX], expected[PATH_MAX] = "";
  char base[NAME_MAX + 1];
  int parent = sql_parentfd(e, t->fd, m->path, base);
  if (parent < 0)
    return -1;
  ssize_t n = readlinkat(parent, base, target, sizeof(target) - 1);
  close(parent);
  if (n < 0 || n == (ssize_t)sizeof(target) - 1)
    return SQLi_fail(e, SQL_CONSTRAINT, "bad symbolic field");
  target[n] = 0;
  if (target[0] == '/') {
    /* Cross-table shared field: <source table>/.sql/shared/<32 hex>. */
    char root[PATH_MAX], anchor[80];
    if (!sql_xshare_split(target, root, anchor))
      return SQLi_fail(e, SQL_CONSTRAINT, "forbidden symbolic target %s",
                       m->path);
    strcpy(out, target);
    return 0;
  }
  int depth = 0;
  for (char *s = m->path; *s; s++)
    if (*s == '/')
      depth++;
  for (int i = 0; i < depth; i++)
    strcat(expected, "../");
  strcat(expected, ".sql/shared/");
  size_t prefix = strlen(expected);
  if (strncmp(target, expected, prefix) || strlen(target + prefix) != 32)
    return SQLi_fail(e, SQL_CONSTRAINT, "forbidden symbolic target %s",
                     m->path);
  for (char *s = target + prefix; *s; s++)
    if (!isxdigit((unsigned char)*s))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid shared identifier");
  char path[80];
  snprintf(path, sizeof(path), ".sql/shared/%s", target + prefix);
  strcpy(out, path);
  return 0;
}
int SQLi_member_load(Env *e, Table *t, Member *m, unsigned char **buf,
                     size_t *len) {
  if (!S_ISLNK(m->st.st_mode))
    return SQLi_load_bytes(e, t->fd, m->path, buf, len);
  char target[PATH_MAX];
  if (SQLi_member_target(e, t, m, target))
    return -1;
  if (target[0] == '/')
    return sql_xshare_load(e, target, buf, len);
  return SQLi_load_bytes(e, t->fd, target, buf, len);
}
static int capture_add(Env *e, Capture *c, Node *n, const char *name,
                       regmatch_t *m) {
  for (int j = 0; j < n->nc; j++) {
    if (m[j + 1].rm_so < 0)
      return SQLi_fail(e, SQL_CONSTRAINT, "optional unmatched capture %s",
                       n->cap[j]);
    c[j].name = strdup(n->cap[j]);
    c[j].value =
        strndup(name + m[j + 1].rm_so, m[j + 1].rm_eo - m[j + 1].rm_so);
    c[j].numeric = strcasecmp(n->captype[j], "TEXT") != 0;
    Node tmp = {0};
    strcpy(tmp.type, n->captype[j]);
    strcpy(tmp.name, n->cap[j]);
    if (!c[j].name || !c[j].value ||
        SQLi_value_check(e, &tmp, (unsigned char *)c[j].value,
                         strlen(c[j].value)))
      return -1;
  }
  return 0;
}
static int walk(Env *e, Table *t, int fd, int parent, const char *path,
                Capture *in, int nc, Record *rec, int deep) {
  DIR *d = fdopendir(openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!d)
    return SQLi_fail(e, SQL_IO, "scan directory: %s", strerror(errno));
  int counts[NODES] = {0}, rc = 0;
  struct dirent *ent;
  while ((ent = readdir(d))) {
    char *name = ent->d_name;
    if (!strcmp(name, ".") || !strcmp(name, ".."))
      continue;
    if (!parent && 0) {
    } /* parent -1 denotes table root. */
    if (parent == -1 &&
        (!strcmp(name, ".sql-root") || !strcmp(name, ".context") ||
         !strncmp(name, ".context_", 9) ||
         !strncmp(name, ".sql-context.", 13) ||
         !strncmp(name, ".sql-coord.", 11) ||
         !strncmp(name, ".sql-clean.", 11) || !strcmp(name, ".table") ||
         !strcmp(name, ".view") || !strcmp(name, ".sql") ||
         !strncmp(name, ".sql-map.", 9) || !strncmp(name, ".sql-txn.", 9)))
      continue;
    if (rec && !strcmp(name, ".sql-id"))
      continue;
    if (rec && !strncmp(name, ".sql-null.", 10)) {
      struct stat ns;
      if (fstatat(fd, name + 10, &ns, AT_SYMLINK_NOFOLLOW)) {
        if (e->missing_null && errno == ENOENT)
          continue;
        rc = SQLi_fail(e, SQL_CONSTRAINT, "orphan NULL marker");
        break;
      }
      continue;
    }
    struct stat st;
    if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = SQLi_fail(e, SQL_IO, "stat entry: %s", strerror(errno));
      break;
    }
    int found = -1;
    regmatch_t groups[CAPMAX + 1] = {{0}};
    for (int i = 0; i < t->schema.n; i++) {
      Node *n = &t->schema.node[i];
      if (n->parent != parent)
        continue;
      regmatch_t g[CAPMAX + 1] = {{0}};
      if (matches(n, name, g)) {
        if (found >= 0) {
          rc = SQLi_fail(e, SQL_CONSTRAINT, "ambiguous schema matches for %s",
                         name);
          break;
        }
        found = i;
        memcpy(groups, g, sizeof(g));
      }
    }
    if (rc)
      break;
    if (found < 0) {
      if (t->schema.unmatched)
        continue;
      rc = SQLi_fail(e, SQL_CONSTRAINT, "unmatched filesystem entry %s%s%s",
                     path, *path ? "/" : "", name);
      break;
    }
    counts[found]++;
    Node *n = &t->schema.node[found];
    char rel[PATH_MAX];
    if (SQLi_joinpath(e, rel, path, name)) {
      rc = -1;
      break;
    }
    if (!strcmp(n->type, "DIRECTORY")) {
      if (!S_ISDIR(st.st_mode)) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "expected real directory %s", rel);
        break;
      }
      int sub =
          openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (sub < 0) {
        rc = SQLi_fail(e, SQL_IO, "open directory %s", rel);
        break;
      }
      Capture caps[NODES] = {0};
      if (nc + n->nc > NODES) {
        close(sub);
        rc = SQLi_fail(e, SQL_CONSTRAINT, "too many inherited captures");
        break;
      }
      memcpy(caps, in, nc * sizeof(*caps));
      if (capture_add(e, caps + nc, n, name, groups)) {
        close(sub);
        rc = -1;
        break;
      }
      Record *next = rec;
      if (n->record) {
        Record *v = realloc(t->r, (t->nr + 1) * sizeof(*v));
        if (!v) {
          close(sub);
          rc = SQLi_fail(e, SQL_IO, "out of memory");
          break;
        }
        t->r = v;
        next = &t->r[t->nr++];
        memset(next, 0, sizeof(*next));
        next->path = strdup(rel);
        next->nc = nc + n->nc;
        for (int j = 0; j < next->nc; j++) {
          next->cap[j] = caps[j];
          next->cap[j].name = strdup(caps[j].name);
          next->cap[j].value = strdup(caps[j].value);
        }
      }
      rc = walk(e, t, sub, found, rel, caps, nc + n->nc, next, deep);
      close(sub);
      for (int j = nc; j < nc + n->nc; j++) {
        free(caps[j].name);
        free(caps[j].value);
      }
      if (rc)
        break;
    } else {
      if (!rec) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "field outside record");
        break;
      }
      Member *v = realloc(rec->m, (rec->nm + 1) * sizeof(*v));
      if (!v) {
        rc = SQLi_fail(e, SQL_IO, "out of memory");
        break;
      }
      rec->m = v;
      Member *m = &v[rec->nm++];
      memset(m, 0, sizeof(*m));
      m->field = found;
      m->path = strdup(rel);
      m->st = st;
      char nullname[NAME_MAX + 16];
      snprintf(nullname, sizeof(nullname), ".sql-null.%s", name);
      struct stat ns;
      if (!fstatat(fd, nullname, &ns, AT_SYMLINK_NOFOLLOW)) {
        if (!S_ISREG(ns.st_mode) || ns.st_size || !S_ISREG(st.st_mode) ||
            st.st_size || (n->notnull && !e->deferred)) {
          rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid/disallowed NULL marker");
          break;
        }
        m->isnull = 1;
      }
      m->nc = n->nc;
      if (capture_add(e, m->cap, n, name, groups)) {
        rc = -1;
        break;
      }
      /* Metadata-only querying permits all entry types. Deep/type checks refuse
       * non-regular data without ever opening a FIFO/socket/device. */
      if (deep && !m->isnull && !S_ISLNK(m->st.st_mode) &&
          (unsigned long long)m->st.st_size > VALMAX) {
        int fd;
        size_t z;
        if (SQLi_open_payload(e, t->fd, m->path, &fd, &z, STREAMMAX)) {
          rc = -1;
          break;
        }
        rc = SQLi_value_check_fd(e, n, fd, z);
        close(fd);
        if (rc)
          break;
      } else if (deep && !m->isnull) {
        unsigned char *b;
        size_t z;
        if (SQLi_member_load(e, t, m, &b, &z)) {
          rc = -1;
          break;
        }
        rc = SQLi_value_check(e, n, b, z);
        free(b);
        if (rc)
          break;
      }
    }
  }
  if (!rc && !e->deferred)
    for (int i = 0; i < t->schema.n; i++) {
      Node *n = &t->schema.node[i];
      if (n->parent == parent &&
          ((counts[i] < n->min &&
            !(e->missing_null && strcmp(n->type, "DIRECTORY"))) ||
           (n->max >= 0 && counts[i] > n->max))) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "%s: %s count %d outside [%d-%d]",
                       path, n->name, counts[i], n->min, n->max);
        break;
      }
    }
  closedir(d);
  return rc;
}
static int member_order(const void *a, const void *b) {
  const Member *x = a, *y = b;
  return x->field != y->field ? (x->field > y->field ? 1 : -1)
                              : strcmp(x->path, y->path);
}
int SQLi_scan_table(Env *e, Table *t, int deep) {
  Capture caps[NODES] = {0};
  int rc = walk(e, t, t->fd, -1, "", caps, 0, NULL, deep);
  if (!rc)
    for (int i = 0; i < t->nr; i++)
      if (t->r[i].nm > 1)
        qsort(t->r[i].m, t->r[i].nm, sizeof(Member), member_order);
  return rc;
}
int sql_tokens_text(Env *e, Parser *p, int start, int stop, char *out,
                    size_t z) {
  char *b = NULL;
  size_t len = 0;
  FILE *f = open_memstream(&b, &len);
  if (!f)
    return SQLi_fail(e, SQL_IO, "out of memory");
  for (int i = start; i < stop; i++) {
    if (i > start)
      fputc(' ', f);
    if (p->t[i].quoted) {
      fputc('\'', f);
      for (char *s = p->t[i].s; *s; s++) {
        fputc(*s, f);
        if (*s == '\'')
          fputc(*s, f);
      }
      fputc('\'', f);
    } else
      fputs(p->t[i].s, f);
  }
  fclose(f);
  if (len >= z) {
    free(b);
    return SQLi_fail(e, SQL_CONSTRAINT, "schema exceeds 16KiB");
  }
  memcpy(out, b, len + 1);
  free(b);
  return 0;
}
int sql_schema_cmd(Env *e, const char *cmd, Parser *p) {
  if (strcasecmp(cmd, "describe")) {
    if (sql_session_load(e, NULL, NULL, 0))
      return -1;
  }
  int define = !strcasecmp(cmd, "define"),
      describe = !strcasecmp(cmd, "describe");
  int view = SQLi_eat(p, "VIEW");
  if (!view && SQLi_need(e, p, "TABLE"))
    return -1;
  char *path = NULL;
  if (p->p < p->n && !SQLi_is(p, "(") && !SQLi_is(p, "AS") &&
      !SQLi_is(p, "LINKED") && !SQLi_is(p, "FIELD") &&
      !SQLi_is(p, "INCLUDING") && !SQLi_is(p, ";"))
    path = take(e, p);
  if (view)
    return sql_view_cmd(e, cmd, p, path);
  Table t = {.fd = -1};
  int rc = -1;
  if (describe) {
    if (SQLi_table_open(e, &t, path, 0))
      goto done;
    int ddl = SQLi_eat(p, "AS");
    if (ddl && SQLi_need(e, p, "DDL"))
      goto done;
    if (SQLi_end(e, p))
      goto done;
    fprintf(e->stream, "%s%s\n", ddl ? "TABLE " : "", t.map.DDL);
    rc = 0;
    goto done;
  }
  int start = p->p;
  if (SQLi_schema_parse(e, p, &t.schema))
    goto done;
  int stop = p->p;
  int validate = 0;
  while (p->p < p->n && !SQLi_is(p, ";")) {
    if (SQLi_eat(p, "VALIDATE")) {
      if (SQLi_need(e, p, "ONLY"))
        goto done;
      validate = 1;
    } else if (SQLi_eat(p, "UNMATCHED")) {
      if (SQLi_eat(p, "IGNORE"))
        t.schema.unmatched = 1;
      else if (SQLi_need(e, p, "ERROR"))
        goto done;
    } else if (SQLi_eat(p, "LINKS")) {
      if (SQLi_eat(p, "INTERNAL"))
        t.schema.links = 1;
      else if (SQLi_need(e, p, "REJECT"))
        goto done;
    } else {
      SQLi_fail(e, SQL_SYNTAX, "unexpected definition clause");
      goto done;
    }
  }
  if (SQLi_end(e, p))
    goto done;
  if (!define && path) {
    char absolute[PATH_MAX];
    if (*path == '/') {
      if (strlen(path) >= sizeof(absolute)) {
        SQLi_fail(e, SQL_CONSTRAINT, "table path too long");
        goto done;
      }
      strcpy(absolute, path);
    } else if (SQLi_joinpath(e, absolute, e->cwd, path))
      goto done;
    char *last = strrchr(absolute, '/');
    if (!last || !SQLi_component(last + 1)) {
      SQLi_fail(e, SQL_CONSTRAINT, "invalid CREATE table basename");
      goto done;
    }
    char base[NAME_MAX + 1];
    strcpy(base, last + 1);
    *last = 0;
    int parent = SQLi_open_dir(e, *absolute ? absolute : "/");
    if (parent < 0)
      goto done;
    struct stat existing;
    if (fstatat(parent, base, &existing, AT_SYMLINK_NOFOLLOW)) {
      if (errno != ENOENT || mkdirat(parent, base, 0700) || fsync(parent)) {
        close(parent);
        SQLi_fail(e, SQL_IO, "create table directory: %s", strerror(errno));
        goto done;
      }
    }
    close(parent);
  }
  t.fd = SQLi_open_dir(e, path);
  if (t.fd < 0)
    goto done;
  if (SQLi_lockdir(e, t.fd, 1))
    goto done;
  struct stat st;
  if (!fstatat(t.fd, ".table", &st, AT_SYMLINK_NOFOLLOW) ||
      !fstatat(t.fd, ".view", &st, AT_SYMLINK_NOFOLLOW)) {
    SQLi_fail(e, SQL_CONSTRAINT, "definition already exists");
    goto done;
  }
  if (define) {
    if (SQLi_scan_table(e, &t, 1))
      goto done;
  } else {
    DIR *d = fdopendir(openat(t.fd, ".", O_RDONLY | O_DIRECTORY));
    struct dirent *de;
    int nonempty = 0;
    if (!d) {
      SQLi_fail(e, SQL_IO, "scan new table");
      goto done;
    }
    while ((de = readdir(d)))
      if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") &&
          !sql_provisioned_metadata(e, t.fd, de->d_name))
        nonempty = 1;
    closedir(d);
    if (nonempty) {
      SQLi_fail(
          e, SQL_CONSTRAINT,
          "CREATE requires an empty existing directory; use DEFINE to adopt");
      goto done;
    }
  }
  if (validate) {
    rc = 0;
    goto done;
  }
  if (sql_context_active(e)) {
    /* Transactional CREATE/DEFINE: the definition is written into the
     * private snapshot (generation-0 participant) and published by COMMIT;
     * ROLLBACK discards it.  A directory CREATE had to make stays empty. */
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", t.fd);
    ssize_t n = readlink(proc, t.path, sizeof(t.path) - 1);
    if (n < 0) {
      SQLi_fail(e, SQL_IO, "resolve new table path");
      goto done;
    }
    t.path[n] = 0;
    e->route_new = 1;
    int routed = sql_session_route(e, &t, 1);
    e->route_new = 0;
    if (routed < 0)
      goto done;
  }
  t.map = (SQL_Map){.magic = MAGIC,
                    .version = SQL_VERSION,
                    .bytes = sizeof(SQL_Map),
                    .endian = 0x01020304,
                    .generation = 1};
  if (sql_tokens_text(e, p, start, stop, t.map.DDL, sizeof(t.map.DDL)))
    goto done;
  /* Persist policy in canonical DDL trailer, decoded separately by schema_text.
   */
  size_t len = strlen(t.map.DDL);
  snprintf(t.map.DDL + len, sizeof(t.map.DDL) - len, " UNMATCHED %s LINKS %s",
           t.schema.unmatched ? "IGNORE" : "ERROR",
           t.schema.links ? "INTERNAL" : "REJECT");
  rc = SQLi_map_write(e, t.fd, ".table", &t.map, 0);
  /* DEFINE adopts existing records into the immutable-ID registry (table
   * metadata only; record directories are not modified).  Inside a
   * transaction this is deferred to an explicit ADOPT IDS after COMMIT. */
  if (!rc && define && !sql_context_active(e))
    rc = sql_ids_adopt(e, &t, NULL, NULL, NULL);
done:
  SQLi_table_close(&t);
  return rc;
}

int SQLi_schema_record_path(Env *e, Schema *s, const char *path) {
  char *copy = strdup(path), *save = NULL;
  int parent = -1;
  for (char *x = strtok_r(copy, "/", &save); x;
       x = strtok_r(NULL, "/", &save)) {
    if (!SQLi_component(x)) {
      free(copy);
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid record component");
    }
    int found = -1;
    for (int i = 0; i < s->n; i++) {
      regmatch_t g[CAPMAX + 1] = {{0}};
      if (s->node[i].parent == parent &&
          !strcmp(s->node[i].type, "DIRECTORY") && matches(&s->node[i], x, g)) {
        if (found >= 0) {
          free(copy);
          return SQLi_fail(e, SQL_CONSTRAINT, "ambiguous record path");
        }
        found = i;
      }
    }
    if (found < 0) {
      free(copy);
      return SQLi_fail(e, SQL_CONSTRAINT, "record path does not match schema");
    }
    parent = found;
  }
  free(copy);
  if (parent < 0 || !s->node[parent].record)
    return SQLi_fail(e, SQL_CONSTRAINT, "path does not end at RECORD boundary");
  return parent;
}
/* FORMAT is a validated name template: literal text, %% and up to eight
 * %[width][.precision]u conversions.  It is interpreted here, never passed to
 * printf, and is invertible for decimal numbers (SQLi_format_parse). */
int SQLi_format_count(const char *f) {
  int k = 0;
  for (; *f; f++)
    if (*f == '%') {
      if (f[1] == '%')
        f++;
      else
        k++;
    }
  return k;
}
int SQLi_format_name(Env *e, const char *f, const unsigned long long *v, int k,
                     char *out, size_t z) {
  size_t o = 0;
  int used = 0;
  for (; *f; f++) {
    char piece[160];
    if (*f != '%' || f[1] == '%') {
      piece[0] = *f;
      piece[1] = 0;
      if (*f == '%')
        f++;
    } else {
      int width = 0, precision = -1, zero = 0;
      f++;
      if (*f == '0')
        zero = 1;
      while (isdigit((unsigned char)*f))
        width = width * 10 + (*f++ - '0');
      if (*f == '.')
        for (f++, precision = 0; isdigit((unsigned char)*f); f++)
          precision = precision * 10 + (*f - '0');
      if (used >= k)
        return SQLi_fail(e, SQL_CONSTRAINT,
                         "FORMAT has more conversions than supplied values");
      /* printf %u semantics: precision zero-pads; '0' flag zero-pads to
       * width unless a precision is given; otherwise spaces. */
      char digits[32], body[100];
      snprintf(digits, sizeof(digits), "%llu", v[used++]);
      if (precision == 0 && !strcmp(digits, "0"))
        digits[0] = 0;
      int len = strlen(digits), zeros = precision > len ? precision - len : 0;
      if (zero && precision < 0 && width > len)
        zeros = width - len;
      memset(body, '0', zeros);
      strcpy(body + zeros, digits);
      int blen = strlen(body), spaces = width > blen ? width - blen : 0;
      memset(piece, ' ', spaces);
      strcpy(piece + spaces, body);
    }
    size_t l = strlen(piece);
    if (o + l >= z)
      return SQLi_fail(e, SQL_CONSTRAINT, "generated name too long");
    memcpy(out + o, piece, l);
    o += l;
  }
  out[o] = 0;
  if (used != k)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "FORMAT has fewer conversions than supplied values");
  return 0;
}
/* Inverse of SQLi_format_name: 1 and the values when name has this form. */
int SQLi_format_parse(const char *f, const char *name, unsigned long long *v,
                      int *k) {
  *k = 0;
  for (; *f; f++) {
    if (*f != '%' || f[1] == '%') {
      if (*f == '%')
        f++;
      if (*name++ != *f)
        return 0;
      continue;
    }
    f++;
    while (isdigit((unsigned char)*f) || *f == '.')
      f++;
    while (*name == ' ')
      name++;
    if (!isdigit((unsigned char)*name) || *k >= CAPMAX)
      return 0;
    unsigned long long x = 0;
    while (isdigit((unsigned char)*name)) {
      if (x > (~0ULL - 9) / 10)
        return 0;
      x = x * 10 + (*name++ - '0');
    }
    v[(*k)++] = x;
  }
  return !*name;
}
int SQLi_node_matches(Node *n, const char *name) {
  regmatch_t g[CAPMAX + 1] = {{0}};
  return matches(n, name, g);
}
/* FORMAT values of every directory level on a record path, outermost first. */
int SQLi_path_values(Schema *s, const char *record, unsigned long long *v,
                     int *n) {
  char *copy = strdup(record ? record : ""), *save = NULL;
  int parent = -1;
  *n = 0;
  if (!copy)
    return -1;
  for (char *x = strtok_r(copy, "/", &save); x; x = strtok_r(NULL, "/", &save)) {
    int found = -1;
    for (int i = 0; i < s->n && found < 0; i++)
      if (s->node[i].parent == parent && !strcmp(s->node[i].type, "DIRECTORY") &&
          SQLi_node_matches(&s->node[i], x))
        found = i;
    if (found < 0)
      break;
    unsigned long long vals[CAPMAX];
    int k = 0;
    if (s->node[found].format[0] &&
        SQLi_format_parse(s->node[found].format, x, vals, &k))
      for (int j = 0; j < k && *n < 4 * CAPMAX; j++)
        v[(*n)++] = vals[j];
    parent = found;
  }
  free(copy);
  return 0;
}
static int field_filename(Env *e, Node *n, const unsigned long long *v, int nv,
                          char *out, size_t z);
int SQLi_field_filename(Env *e, Node *n, unsigned index, char *out, size_t z) {
  unsigned long long v = index;
  return field_filename(e, n, &v, 1, out, z);
}
/* Member FORMAT conversions take the LAST k values of: the record path's
 * FORMAT values (outermost first) followed by the member ordinal. */
int SQLi_field_filename_at(Env *e, Schema *s, Node *n, const char *record,
                           unsigned index, char *out, size_t z) {
  unsigned long long v[4 * CAPMAX + 1];
  int nv = 0;
  if (SQLi_path_values(s, record, v, &nv))
    return SQLi_fail(e, SQL_IO, "out of memory");
  v[nv++] = index;
  return field_filename(e, n, v, nv, out, z);
}
static int field_filename(Env *e, Node *n, const unsigned long long *v, int nv,
                          char *out, size_t z) {
  char ext[16];
  unsigned index = (unsigned)v[nv - 1];
  extname(n, ext, sizeof(ext));
  if (n->format[0]) {
    int k = SQLi_format_count(n->format);
    if (k > nv)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "member FORMAT needs %d values; record path supplies "
                       "%d plus the member ordinal",
                       k, nv - 1);
    if (SQLi_format_name(e, n->format, v + nv - k, k, out, z))
      return -1;
  } else if (n->max == 1)
    snprintf(out, z, "%s%s%s", n->name, *ext ? "." : "", ext);
  else
    snprintf(out, z, "%s.%u%s%s", n->name, index, *ext ? "." : "", ext);
  regmatch_t g[CAPMAX + 1] = {{0}};
  if (!SQLi_component(out) || !matches(n, out, g))
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "generated field filename fails MATCH; supply a compatible FORMAT");
  return 0;
}

int SQLi_field_name_check(Env *e, Node *n, const char *name) {
  regmatch_t g[CAPMAX + 1] = {{0}};
  if (!SQLi_component(name) || !matches(n, name, g))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "explicit member name does not match field schema");
  return 0;
}

int SQLi_field_name_unique(Env *e, Schema *s, int field, const char *name) {
  int count = 0;
  for (int i = 0; i < s->n; i++) {
    if (s->node[i].parent != s->node[field].parent)
      continue;
    regmatch_t g[CAPMAX + 1] = {{0}};
    if (matches(&s->node[i], name, g))
      count++;
  }
  return count == 1 ? 0
                    : SQLi_fail(e, SQL_CONSTRAINT,
                                "filename ambiguously matches multiple fields");
}
/* Schema DIRECTORY node matching a relative directory path, or -1. */
int SQLi_schema_dir_path(Schema *s, const char *path) {
  char *copy = strdup(path), *save = NULL;
  int parent = -1;
  if (!copy)
    return -1;
  for (char *x = strtok_r(copy, "/", &save); x;
       x = strtok_r(NULL, "/", &save)) {
    int found = -1;
    for (int i = 0; i < s->n; i++) {
      regmatch_t g[CAPMAX + 1] = {{0}};
      if (s->node[i].parent == parent &&
          !strcmp(s->node[i].type, "DIRECTORY") && matches(&s->node[i], x, g))
        found = i;
    }
    if (found < 0) {
      free(copy);
      return -1;
    }
    parent = found;
  }
  free(copy);
  return parent;
}

/* INSERT RECORD GENERATED [UNDER prefix] [USING (n, ...)]: every directory
 * level below prefix down to the unique RECORD node is named from its
 * FORMAT.  Conversions consume USING values in order.  A level whose FORMAT
 * has one conversion and no value left is numbered automatically: the record
 * level takes 1 + the highest existing number (names are never reused while
 * a higher one exists); a group level reuses the highest existing group
 * unless the RECORD below it is at its maximum cardinality, then rolls over
 * to the next number; the first number is 1. */
/* The schema has exactly one RECORD node; the child of parent on the path
 * to it (1), or 0 when parent is at or below the RECORD. */
static int children(Schema *s, int parent, int *only) {
  for (int i = 0; i < s->n; i++)
    if (s->node[i].record) {
      int c = i;
      while (c >= 0 && s->node[c].parent != parent)
        c = s->node[c].parent;
      if (c < 0)
        return 0;
      *only = c;
      return 1;
    }
  return 0;
}
static int highest(int dir, Node *n, unsigned long long *hi, int *count,
                   Schema *s, int self) {
  *hi = 0;
  *count = 0;
  int found = 0;
  DIR *d = dir >= 0 ? fdopendir(dup(dir)) : NULL;
  if (!d)
    return 0;
  rewinddir(d);
  struct dirent *de;
  while ((de = readdir(d))) {
    if (de->d_name[0] == '.')
      continue;
    struct stat st;
    if (fstatat(dir, de->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode))
      continue;
    /* The entry must belong to this node, not a sibling alternative. */
    int owner = -1;
    for (int i = 0; i < s->n && owner < 0; i++)
      if (s->node[i].parent == n->parent && !strcmp(s->node[i].type, "DIRECTORY") &&
          SQLi_node_matches(&s->node[i], de->d_name))
        owner = i;
    unsigned long long v[CAPMAX];
    int k;
    if (owner != self || !SQLi_format_parse(n->format, de->d_name, v, &k) || k != 1)
      continue;
    (*count)++;
    if (!found || v[0] > *hi)
      *hi = v[0];
    found = 1;
  }
  closedir(d);
  return found;
}
static int count_children(int dir, const char *name, Schema *s, int node) {
  int sub = openat(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (sub < 0)
    return 0;
  DIR *d = fdopendir(sub);
  if (!d) {
    close(sub);
    return 0;
  }
  struct dirent *de;
  int count = 0;
  while ((de = readdir(d)))
    if (de->d_name[0] != '.' && SQLi_node_matches(&s->node[node], de->d_name))
      count++;
  closedir(d);
  return count;
}
int SQLi_generate_record(Env *e, Table *t, const char *under,
                         const unsigned long long *use, int nuse, char *out,
                         size_t z) {
  Schema *s = &t->schema;
  int node = -1, used = 0;
  out[0] = 0;
  if (under && *under) {
    char *copy = strdup(under), *save = NULL;
    if (!copy)
      return SQLi_fail(e, SQL_IO, "out of memory");
    for (char *x = strtok_r(copy, "/", &save); x;
         x = strtok_r(NULL, "/", &save)) {
      int found = -1;
      if (!SQLi_component(x)) {
        free(copy);
        return SQLi_fail(e, SQL_CONSTRAINT, "invalid UNDER component");
      }
      for (int i = 0; i < s->n; i++)
        if (s->node[i].parent == node && !strcmp(s->node[i].type, "DIRECTORY") &&
            SQLi_node_matches(&s->node[i], x)) {
          if (found >= 0) {
            free(copy);
            return SQLi_fail(e, SQL_CONSTRAINT, "ambiguous UNDER path");
          }
          found = i;
        }
      if (found < 0 || s->node[found].record) {
        free(copy);
        return SQLi_fail(e, SQL_CONSTRAINT,
                         "UNDER must name group directories above a RECORD");
      }
      node = found;
    }
    free(copy);
    if (snprintf(out, z, "%s", under) >= (int)z)
      return SQLi_fail(e, SQL_CONSTRAINT, "generated path too long");
    while (*out && out[strlen(out) - 1] == '/')
      out[strlen(out) - 1] = 0;
  }
  for (;;) {
    int child;
    int n = children(s, node, &child);
    if (!n)
      return SQLi_fail(e, SQL_CONSTRAINT, "no RECORD below generated path");
    if (n > 1)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "ambiguous generated path below '%s'; name the level "
                       "with UNDER",
                       out);
    Node *c = &s->node[child];
    if (!c->format[0])
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "level %s has no FORMAT; name it with UNDER", c->name);
    int k = SQLi_format_count(c->format);
    unsigned long long v[CAPMAX];
    char name[NAME_MAX + 1];
    int dir = *out ? openat(t->fd, out, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                   : dup(t->fd);
    if (k <= nuse - used) {
      memcpy(v, use + used, k * sizeof(*v));
      used += k;
    } else if (k == 1 && used == nuse) {
      unsigned long long hi;
      int count;
      int any = highest(dir, c, &hi, &count, s, child);
      v[0] = any ? hi + 1 : 1;
      if (any && !c->record) {
        /* Reuse the latest group unless its RECORD level is full. */
        int rec;
        char cand[NAME_MAX + 1];
        unsigned long long h = hi;
        if (SQLi_format_name(e, c->format, &h, 1, cand, sizeof(cand))) {
          if (dir >= 0)
            close(dir);
          return -1;
        }
        int full = 0;
        if (children(s, child, &rec) == 1 && s->node[rec].record &&
            s->node[rec].max >= 0)
          full = count_children(dir, cand, s, rec) >= s->node[rec].max;
        if (!full)
          v[0] = hi;
      }
      if (v[0] > 0xffffffffULL) {
        if (dir >= 0)
          close(dir);
        return SQLi_fail(e, SQL_CONSTRAINT, "generated name space exhausted");
      }
    } else {
      if (dir >= 0)
        close(dir);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "level %s FORMAT needs %d USING value(s), %d left",
                       c->name, k, nuse - used);
    }
    if (dir >= 0)
      close(dir);
    if (SQLi_format_name(e, c->format, v, k, name, sizeof(name)))
      return -1;
    if (!SQLi_component(name) || !SQLi_node_matches(c, name))
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "generated name %s fails MATCH of %s", name, c->name);
    size_t l = strlen(out);
    if (snprintf(out + l, z - l, "%s%s", l ? "/" : "", name) >= (int)(z - l))
      return SQLi_fail(e, SQL_CONSTRAINT, "generated path too long");
    node = child;
    if (c->record)
      break;
  }
  if (used != nuse)
    return SQLi_fail(e, SQL_CONSTRAINT, "%d unused USING value(s)", nuse - used);
  return 0;
}
