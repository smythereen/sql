/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
#include "sql_trigger_meta.h"
static uint64_t hash(SQL_TriggerRecord *r) {
  uint64_t h = 1469598103934665603ULL;
  unsigned char *p = (void *)&r->Sequence;
  for (size_t i = 0; i < 8; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  p = (void *)&r->Value;
  for (size_t i = 0; i < sizeof(r->Value); i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}
static uint64_t fnv(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = data;
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}
static uint64_t ext_hash(const SQL_TriggerExt *x) {
  return fnv(1469598103934665603ULL, x, offsetof(SQL_TriggerExt, Hash));
}
static uint64_t nonce_hash(const SQL_TriggerDef *d) {
  return fnv(1469598103934665603ULL, d->Nonce, strnlen(d->Nonce, 33));
}
/* Counters valid for the given record and its current trigger nonces. */
static void ext_counters(SQL_TriggerRecord *r, const SQL_TriggerMap *m,
                         uint64_t out[SQL_TRG_MAX]) {
  SQL_TriggerExt *x = (void *)((unsigned char *)r + SQL_TRG_EXT_OFFSET);
  int ok = x->Magic == SQL_TRG_EXT_MAGIC && x->Version == 1 &&
           x->Sequence == r->Sequence && x->Hash == ext_hash(x);
  for (unsigned i = 0; i < SQL_TRG_MAX; i++)
    out[i] = ok && m->Trigger[i].Used &&
                     x->NonceHash[i] == nonce_hash(&m->Trigger[i])
                 ? x->Skipped[i]
                 : 0;
}
static int valid(Env *e, SQL_TriggerMap *m) {
  if (m->Magic != SQL_TRG_MAGIC || m->Version != 1 || m->Bytes != sizeof(*m) ||
      m->UID != getuid() || m->Count != SQL_TRG_MAX || m->reserved || !m->Inode)
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid trigger map version/bounds");
  for (unsigned i = 0; i < m->Count; i++) {
    SQL_TriggerDef *d = &m->Trigger[i];
    if (d->Used > 1 || d->Enabled > 1 || d->Kind > SQL_EVENT_ALL ||
        d->ArgCount > 8 || d->FieldCount > 16 || d->Retries > 8 ||
        d->Timeout > 60000 ||
        !memchr(d->Definition, 0, sizeof(d->Definition)) ||
        (strlen(d->Definition) + 1 < sizeof(d->Definition) &&
         !memchr(d->Definition + strlen(d->Definition) + 1, 0,
                 sizeof(d->Definition) - strlen(d->Definition) - 1)) ||
        !memchr(d->Name, 0, 64) || !memchr(d->Exec, 0, PATH_MAX) ||
        !memchr(d->Nonce, 0, 33) || !memchr(d->LastTransaction, 0, 33))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid trigger definition bounds");
    if (d->Used && (!SQLi_component(d->Name) || d->Exec[0] != '/' ||
                    !d->Timeout || !d->Kind || strlen(d->Nonce) != 32))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid active trigger definition");
    for (unsigned a = 0; a < d->ArgCount; a++)
      if (!memchr(d->Args[a], 0, 512))
        return SQLi_fail(e, SQL_CONSTRAINT, "invalid trigger argv");
    for (unsigned a = 0; a < d->FieldCount; a++)
      if (!memchr(d->Fields[a], 0, 64))
        return SQLi_fail(e, SQL_CONSTRAINT, "invalid trigger field list");
    for (unsigned j = 0; j < i; j++)
      if (d->Used && m->Trigger[j].Used && !strcmp(d->Name, m->Trigger[j].Name))
        return SQLi_fail(e, SQL_CONSTRAINT, "duplicate trigger name");
  }
  return 0;
}
static int image(Env *e, int fd, SQL_TriggerFile **out, int initial) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077) || st.st_size != sizeof(SQL_TriggerFile))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid private trigger map file");
  SQL_TriggerFile *p = sql_mapping(e, fd, sizeof(*p), PROT_WRITE);
  if (!p)
    return -1;
  if (!initial &&
      (p->Magic != SQL_TRG_MAGIC || p->Version != 1 || p->Bytes != sizeof(*p) ||
       p->UID != getuid() || p->TraceVersion != 1)) {
    sql_unmapping(p);
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid trigger file header");
  }
  *out = p;
  return 0;
}
static int newest(SQL_TriggerFile *p) {
  int best = -1;
  uint64_t seq = 0;
  for (int i = 0; i < 2; i++) {
    SQL_TriggerRecord *r = (void *)p->Slot[i];
    if (r->Sequence && r->Sequence > seq && r->Hash == hash(r)) {
      seq = r->Sequence;
      best = i;
    }
  }
  return best;
}
int sql_trg_read(Env *e, int fd, SQL_TriggerMap *m) {
  SQL_TriggerFile *p;
  if (image(e, fd, &p, 0))
    return -1;
  int n = newest(p);
  if (n >= 0)
    *m = ((SQL_TriggerRecord *)p->Slot[n])->Value;
  sql_unmapping(p);
  return n < 0 ? SQLi_fail(e, SQL_CONSTRAINT, "both trigger slots invalid")
               : valid(e, m);
}
static int save(Env *e, int fd, SQL_TriggerMap *m, int slot, uint64_t add);
int sql_trg_save(Env *e, int fd, SQL_TriggerMap *m) {
  return save(e, fd, m, -1, 0);
}
int sql_trg_save_skipped(Env *e, int fd, SQL_TriggerMap *m, unsigned slot,
                         uint64_t add) {
  return save(e, fd, m, (int)slot, add);
}
int sql_trg_skipped(Env *e, int fd, const SQL_TriggerMap *m,
                    uint64_t out[SQL_TRG_MAX]) {
  SQL_TriggerFile *p;
  if (image(e, fd, &p, 0))
    return -1;
  int n = newest(p);
  if (n < 0)
    memset(out, 0, sizeof(uint64_t) * SQL_TRG_MAX);
  else
    ext_counters((void *)p->Slot[n], m, out);
  sql_unmapping(p);
  return 0;
}
static int save(Env *e, int fd, SQL_TriggerMap *m, int slot, uint64_t add) {
  if (valid(e, m))
    return -1;
  SQL_TriggerFile *p;
  if (image(e, fd, &p, 0))
    return -1;
  int n = newest(p);
  SQL_TriggerRecord *old = n < 0 ? NULL : (void *)p->Slot[n];
  if (old && old->Sequence == UINT64_MAX) {
    sql_unmapping(p);
    return SQLi_fail(e, SQL_CONSTRAINT, "trigger sequence exhausted");
  }
  int next = n < 0 ? 0 : 1 - n;
  uint64_t counters[SQL_TRG_MAX] = {0};
  if (old)
    ext_counters(old, m, counters); /* carried forward per unchanged nonce */
  if (slot >= 0 && slot < SQL_TRG_MAX)
    counters[slot] += add;
  SQL_TriggerRecord *r = (void *)p->Slot[next];
  memset(p->Slot[next], 0, SQL_TRG_SLOT);
  r->Sequence = old ? old->Sequence + 1 : 1;
  r->Value = *m;
  r->Hash = hash(r);
  SQL_TriggerExt *x = (void *)(p->Slot[next] + SQL_TRG_EXT_OFFSET);
  x->Magic = SQL_TRG_EXT_MAGIC;
  x->Version = 1;
  x->Sequence = r->Sequence;
  for (unsigned i = 0; i < SQL_TRG_MAX; i++) {
    x->NonceHash[i] = m->Trigger[i].Used ? nonce_hash(&m->Trigger[i]) : 0;
    x->Skipped[i] = m->Trigger[i].Used ? counters[i] : 0;
  }
  x->Hash = ext_hash(x);
  UpdateMap(p->Slot[next], SQL_TRG_SLOT);
  int rc = msync(p->Slot[next], SQL_TRG_SLOT, MS_SYNC) || fsync(fd);
  sql_unmapping(p);
  return rc ? SQLi_fail(e, SQL_IO, "sync trigger slot") : 0;
}
int sql_trg_open(Env *e, int root, int create) {
  if (create && (mkdirat(root, ".sql", 0700) && errno != EEXIST))
    return SQLi_fail(e, SQL_IO, "create trigger metadata root");
  int meta =
      openat(root, ".sql", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (meta < 0)
    return SQLi_fail(e, SQL_IO, "open trigger metadata root");
  int fd = openat(meta, ".triggers", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    close(meta);
    SQL_TriggerMap *existing = malloc(sizeof(*existing));
    struct stat identity;
    if (!existing) {
      close(fd);
      return SQLi_fail(e, SQL_IO, "trigger scope allocation");
    }
    int bad = fstat(root, &identity) || sql_trg_read(e, fd, existing) ||
              existing->Device != identity.st_dev ||
              existing->Inode != identity.st_ino;
    free(existing);
    if (bad) {
      close(fd);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "trigger map source identity changed");
    }
    return fd;
  }
  if (errno != ENOENT || !create) {
    close(meta);
    return SQLi_fail(e, SQL_CONSTRAINT, "trigger map must be initialized");
  }
  char id[33], temp[80];
  if (sql_uuid(e, id)) {
    close(meta);
    return -1;
  }
  snprintf(temp, sizeof(temp), ".triggers.%s", id);
  fd = openat(meta, temp, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
              0600);
  SQL_TriggerFile *p = NULL;
  int bad = fd < 0 || ftruncate(fd, sizeof(SQL_TriggerFile));
  if (!bad)
    bad = image(e, fd, &p, 1);
  if (!bad) {
    p->Magic = SQL_TRG_MAGIC;
    p->Version = 1;
    p->Bytes = sizeof(*p);
    p->UID = getuid();
    p->TraceVersion = 1;
    UpdateMap(p, sizeof(*p));
    bad = msync(p, sizeof(*p), MS_SYNC) || fsync(fd);
    sql_unmapping(p);
  }
  SQL_TriggerMap *m = calloc(1, sizeof(*m));
  if (!m)
    bad = 1;
  if (!bad) {
    *m = (SQL_TriggerMap){.Magic = SQL_TRG_MAGIC,
                          .Version = 1,
                          .Bytes = sizeof(*m),
                          .UID = getuid(),
                          .Count = SQL_TRG_MAX};
    struct stat identity;
    if (fstat(root, &identity))
      bad = 1;
    else {
      m->Device = identity.st_dev;
      m->Inode = identity.st_ino;
      bad = sql_trg_save(e, fd, m);
    }
  }
  free(m);
  if (!bad)
    bad = renameat2(meta, temp, meta, ".triggers", RENAME_NOREPLACE) ||
          fsync(meta) || fsync(root);
  unlinkat(meta, temp, 0);
  close(meta);
  if (bad) {
    if (fd >= 0)
      close(fd);
    return SQLi_fail(e, e->status ? e->status : SQL_IO,
                     "provision trigger map");
  }
  return fd;
}
int sql_trg_exec_pin(Env *e, SQL_TriggerDef *d, int configure) {
  int path = open(d->Exec, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (path < 0 || fstat(path, &st) || !S_ISREG(st.st_mode) ||
      !(st.st_mode & 0111)) {
    if (path >= 0)
      close(path);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "trigger executable must be an explicit regular "
                     "executable, not a symlink/device");
  }
  if (configure) {
    d->ExecDevice = st.st_dev;
    d->ExecInode = st.st_ino;
  } else if (d->ExecDevice != st.st_dev || d->ExecInode != st.st_ino) {
    close(path);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "trigger executable identity changed; disable and "
                     "reconfigure explicitly");
  }
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", path);
  int fd = open(proc, O_RDONLY | O_CLOEXEC);
  close(path);
  return fd < 0 ? SQLi_fail(e, SQL_IO, "pin trigger executable") : fd;
}
static int number(Env *e, Parser *p, unsigned max, uint32_t *v) {
  char *s = take(e, p), *end;
  if (!s)
    return -1;
  errno = 0;
  unsigned long x = strtoul(s, &end, 10);
  if (!*s || *s == '-' || *end || errno || x > max)
    return SQLi_fail(e, SQL_CONSTRAINT, "trigger numeric bound");
  *v = x;
  return 0;
}
int sql_trg_parse(Env *e, Parser *p, SQL_TriggerDef *d, char **scope) {
  memset(d, 0, sizeof(*d));
  d->Used = 1;
  d->Timeout = 5000;
  char *name = take(e, p);
  if (!name || !SQLi_component(name) || strlen(name) >= 64)
    return SQLi_fail(e, SQL_SYNTAX, "invalid trigger name");
  strcpy(d->Name, name);
  if (SQLi_eat(p, "ON")) {
    *scope = take(e, p);
    if (!*scope)
      return -1;
  }
  if (SQLi_need(e, p, "AFTER"))
    return -1;
  do {
    char *event = take(e, p);
    unsigned kind = event && !strcasecmp(event, "INSERT")   ? 1
                    : event && !strcasecmp(event, "UPDATE") ? 2
                    : event && !strcasecmp(event, "DELETE") ? 4
                    : event && !strcasecmp(event, "LINK")   ? 8
                    : event && !strcasecmp(event, "UNLINK") ? 16
                    : event && !strcasecmp(event, "RENAME") ? 32
                    : event && !strcasecmp(event, "COMMIT") ? SQL_EVENT_ALL
                                                            : 0;
    if (!kind)
      return SQLi_fail(
          e, SQL_SYNTAX,
          "expected committed INSERT/UPDATE/DELETE/LINK/UNLINK/RENAME/COMMIT");
    d->Kind |= kind;
  } while (SQLi_eat(p, ","));
  if (SQLi_eat(p, "OF")) {
    int paren = SQLi_eat(p, "(");
    do {
      char *f = take(e, p);
      if (!f || !SQLi_component(f) || strlen(f) >= 64 || d->FieldCount == 16)
        return SQLi_fail(e, SQL_CONSTRAINT, "trigger field list bound");
      strcpy(d->Fields[d->FieldCount++], f);
    } while (SQLi_eat(p, ","));
    if (paren && SQLi_need(e, p, ")"))
      return -1;
  }
  if (SQLi_eat(p, "WHERE")) {
    /* The predicate source is kept after the canonical text's NUL so that
     * sql_trg_definition can regenerate "... WHERE <src> EXECUTE ...". */
    int start = p->p;
    Expr *x = SQLi_expr_parse(e, p);
    if (!x)
      return -1;
    SQLi_expr_free(x);
    char *where = d->Definition + 1;
    size_t used = 0, room = sizeof(d->Definition) / 2;
    d->Definition[0] = 0;
    for (int i = start; i < p->p; i++) {
      const char *s = p->t[i].s;
      size_t need = strlen(s) * 2 + 4;
      if (used + need >= room)
        return SQLi_fail(e, SQL_CONSTRAINT, "trigger WHERE length bound 4096");
      if (i > start)
        where[used++] = ' ';
      if (p->t[i].quoted) {
        where[used++] = '\'';
        for (; *s; s++) {
          if (*s == '\'')
            where[used++] = '\'';
          where[used++] = *s;
        }
        where[used++] = '\'';
      } else {
        memcpy(where + used, s, strlen(s));
        used += strlen(s);
      }
    }
    where[used] = 0;
    if (!used)
      return SQLi_fail(e, SQL_SYNTAX, "WHERE requires a predicate");
  }
  if (SQLi_need(e, p, "EXECUTE"))
    return -1;
  char *exe = take(e, p);
  if (!exe || exe[0] != '/' || strlen(exe) >= PATH_MAX)
    return SQLi_fail(e, SQL_SYNTAX,
                     "EXECUTE requires an absolute executable path");
  strcpy(d->Exec, exe);
  if (SQLi_need(e, p, "ARGUMENTS") || SQLi_need(e, p, "("))
    return -1;
  if (!SQLi_eat(p, ")")) {
    do {
      char *arg = take(e, p);
      if (!arg || strlen(arg) >= 512 || d->ArgCount == 8)
        return SQLi_fail(e, SQL_CONSTRAINT,
                         "trigger argv bound 8 arguments / 511 bytes each");
      strcpy(d->Args[d->ArgCount++], arg);
    } while (SQLi_eat(p, ","));
    if (SQLi_need(e, p, ")"))
      return -1;
  }
  while (p->p < p->n) {
    if (SQLi_eat(p, "TIMEOUT")) {
      if (number(e, p, 60000, &d->Timeout) || !d->Timeout)
        return SQLi_fail(e, SQL_CONSTRAINT, "TIMEOUT is 1..60000 milliseconds");
    } else if (SQLi_eat(p, "RETRIES")) {
      if (number(e, p, 8, &d->Retries))
        return -1;
    } else if (SQLi_eat(p, "ENABLE") || SQLi_eat(p, "ENABLED"))
      d->Enabled = 1;
    else if (SQLi_eat(p, "DISABLE") || SQLi_eat(p, "DISABLED"))
      d->Enabled = 0;
    else
      break;
  }
  if (SQLi_end(e, p))
    return -1;
  int fd = sql_trg_exec_pin(e, d, 1);
  if (fd < 0)
    return -1;
  close(fd);
  return sql_uuid(e, d->Nonce);
}

const char *sql_trg_where(const SQL_TriggerDef *d) {
  size_t n = strnlen(d->Definition, sizeof(d->Definition));
  return n + 1 < sizeof(d->Definition) ? d->Definition + n + 1 : "";
}
int sql_trg_fields(Env *e, int root, const SQL_TriggerDef *d) {
  if (!d->FieldCount && !*sql_trg_where(d))
    return 0;
  SQL_Map map;
  Schema *schema = calloc(1, sizeof(*schema));
  if (!schema)
    return SQLi_fail(e, SQL_IO, "trigger field schema allocation");
  int rc = -1;
  if (SQLi_map_read(e, root, ".table", &map) ||
      SQLi_schema_text(e, map.DDL, schema))
    goto done;
  for (unsigned i = 0; i < d->FieldCount; i++) {
    for (unsigned j = 0; j < i; j++)
      if (!strcmp(d->Fields[i], d->Fields[j])) {
        SQLi_fail(e, SQL_CONSTRAINT, "duplicate trigger field filter");
        goto done;
      }
    int found = 0;
    for (int j = 0; j < schema->n; j++)
      if (strcmp(schema->node[j].type, "DIRECTORY") &&
          !strcmp(schema->node[j].name, d->Fields[i]))
        found = 1;
    if (!found) {
      SQLi_fail(e, SQL_CONSTRAINT, "unknown trigger field filter");
      goto done;
    }
  }
  if (*sql_trg_where(d)) {
    Parser *q = calloc(1, sizeof(*q));
    if (!q) {
      SQLi_fail(e, SQL_IO, "trigger WHERE parser allocation");
      goto done;
    }
    int saved = e->event_scope;
    e->event_scope = 1;
    Expr *x = NULL;
    int bad = SQLi_lex(e, q, sql_trg_where(d)) || !(x = SQLi_expr_parse(e, q)) ||
              SQLi_end(e, q) || SQLi_expr_validate(e, x, schema, 0);
    e->event_scope = saved;
    SQLi_expr_free(x);
    SQLi_parser_free(q);
    free(q);
    if (bad)
      goto done;
  }
  rc = 0;
done:
  SQLi_schema_free(schema);
  free(schema);
  return rc;
}
