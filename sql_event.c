/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Durable AFTER events: prepared before decision, published only during redo.
 * Watchers additionally require the SQL recovery gate/global DONE to be clear.
 */
#include "sql_event.h"
#include "sql_local.h"
typedef struct {
  uint32_t magic, version;
  uint64_t owner;
} Header;
typedef struct {
  uint32_t type, a, b, slot;
} Entry;
typedef struct {
  char *record, *path;
  char field[64];
  uint32_t kind;
} Logical;
static uint64_t digest(const void *p, size_t n, uint64_t h) {
  const unsigned char *b = p;
  while (n--) {
    h ^= *b++;
    h *= 1099511628211ULL;
  }
  return h;
}
int sql_event_read(Env *e, int fd, SQL_EventHeader *h) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "event must be a private owned regular file");
  if (lseek(fd, 0, SEEK_SET) < 0)
    return SQLi_fail(e, SQL_IO, "event seek");
  if (st.st_size > 0 && st.st_size < 128) {
    char legacy[128] = {0};
    if (read(fd, legacy, st.st_size) == st.st_size && st.st_size == 51 &&
        !strncmp(legacy, "{\"transaction\":\"", 16) &&
        !strcmp(legacy + 48, "\"}\n")) {
      for (int i = 16; i < 48; i++)
        if (!isxdigit((unsigned char)legacy[i]))
          return SQLi_fail(e, SQL_CONSTRAINT, "invalid legacy event");
      memset(h, 0, sizeof(*h));
      return 0;
    }
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid legacy event framing");
  }
  if (sql_read_all(fd, h, sizeof(*h)) || h->Magic != SQL_EVENT_MAGIC ||
      h->Version != 1 || h->Bytes != sizeof(*h) || h->UID != getuid() ||
      h->Length > VALMAX || h->FieldCount > 64 || h->Kind > SQL_EVENT_ALL ||
      st.st_size != (off_t)(sizeof(*h) + h->Length) || h->Transaction[32])
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid event format/length/version");
  uint64_t expected = h->HeaderHash;
  h->HeaderHash = 0;
  uint64_t header_hash = digest(h, sizeof(*h), 1469598103934665603ULL);
  h->HeaderHash = expected;
  if (expected != header_hash)
    return SQLi_fail(e, SQL_CONSTRAINT, "event header checksum mismatch");
  for (int i = 0; i < 32; i++)
    if (!isxdigit((unsigned char)h->Transaction[i]))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid event transaction");
  for (unsigned i = 0; i < h->FieldCount; i++)
    if (!memchr(h->Fields[i], 0, 64))
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid event field");
  unsigned char buf[65536];
  uint64_t hash = 1469598103934665603ULL, remain = h->Length;
  while (remain) {
    size_t n = remain < sizeof(buf) ? remain : sizeof(buf);
    if (sql_read_all(fd, buf, n))
      return SQLi_fail(e, SQL_IO, "event bytes");
    hash = digest(buf, n, hash);
    remain -= n;
  }
  if (hash != h->Hash)
    return SQLi_fail(e, SQL_CONSTRAINT, "event checksum mismatch");
  if (lseek(fd, sizeof(*h), SEEK_SET) < 0)
    return SQLi_fail(e, SQL_IO, "event data seek");
  return 0;
}
static int add(Env *e, Logical **v, size_t *n, size_t *cap, const char *record,
               const char *field, const char *path, unsigned kind) {
  for (size_t i = 0; i < *n; i++)
    if (!strcmp((*v)[i].path, path) && !strcmp((*v)[i].field, field)) {
      (*v)[i].kind |= kind;
      return 0;
    }
  if (*n == 65536)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "logical event limit 65536 exceeded before decision");
  if (*n == *cap) {
    size_t z = *cap ? *cap * 2 : 32;
    Logical *p = realloc(*v, z * sizeof(**v));
    if (!p)
      return SQLi_fail(e, SQL_IO, "event allocation");
    *v = p;
    *cap = z;
  }
  Logical item = {.record = strdup(record), .path = strdup(path), .kind = kind};
  if (!item.record || !item.path) {
    free(item.record);
    free(item.path);
    return SQLi_fail(e, SQL_IO, "event path allocation");
  }
  strcpy(item.field, field);
  (*v)[(*n)++] = item;
  return 0;
}
static int order(const void *a, const void *b) {
  const Logical *x = a, *y = b;
  /* Record-level entries (field "") follow every field-level entry. */
  if (!x->field[0] != !y->field[0])
    return !x->field[0] ? 1 : -1;
  int n = strcmp(x->path, y->path);
  return n ? n : strcmp(x->field, y->field);
}
static int record_dir(Env *e, Table *t, const char *path) {
  Env probe = *e;
  SQL_Result ignored = {0};
  probe.out = &ignored;
  probe.status = 0;
  return SQLi_schema_record_path(&probe, &t->schema, path) == 0;
}
/* Record-level entries (field "") plus one entry per pre-image member. */
static int record_event(Env *e, Table *t, Logical **list, size_t *count,
                        size_t *cap, const char *path, const char *to,
                        unsigned kind) {
  if (add(e, list, count, cap, to ? to : path, "", to ? to : path, kind))
    return -1;
  for (int i = 0; i < t->nr; i++) {
    if (strcmp(t->r[i].path, path))
      continue;
    for (int j = 0; j < t->r[i].nm; j++) {
      Member *m = &t->r[i].m[j];
      char moved[PATH_MAX];
      const char *member = m->path;
      if (to) {
        if (snprintf(moved, sizeof(moved), "%s%s", to, m->path + strlen(path)) >=
            (int)sizeof(moved))
          return SQLi_fail(e, SQL_CONSTRAINT, "event path too long");
        member = moved;
      }
      if (add(e, list, count, cap, to ? to : path,
              t->schema.node[m->field].name, member, kind))
        return -1;
    }
  }
  return 0;
}
static int logical_path(Env *e, Table *t, Logical **list, size_t *count,
                        size_t *cap, const char *path, unsigned op,
                        const char *value) {
  if (path[0] != '.' && (op == 'R' || op == 'M' || op == 'T') &&
      record_dir(e, t, path)) {
    int present = 0;
    for (int i = 0; i < t->nr && !present; i++)
      present = !strcmp(t->r[i].path, path);
    if ((op == 'M') == present) /* re-made existing / removed absent record */
      return 0;
    if (op == 'T' && (!value || !record_dir(e, t, value)))
      return 0;
    return record_event(e, t, list, count, cap, path, op == 'T' ? value : NULL,
                        op == 'R'   ? SQL_EVENT_DELETE
                        : op == 'M' ? SQL_EVENT_INSERT
                                    : SQL_EVENT_RENAME);
  }
  if (op == 'R' || op == 'M')
    return 0;
  if (!strncmp(path, ".sql/shared/", 12)) {
    if (op != 'P' && op != 'H')
      return 0;
    for (int i = 0; i < t->nr; i++)
      for (int j = 0; j < t->r[i].nm; j++) {
        Member *m = &t->r[i].m[j];
        if (!S_ISLNK(m->st.st_mode))
          continue;
        char target[PATH_MAX];
        if (SQLi_member_target(e, t, m, target))
          return -1;
        if (!strcmp(target, path) &&
            add(e, list, count, cap, t->r[i].path,
                t->schema.node[m->field].name, m->path, SQL_EVENT_UPDATE))
          return -1;
      }
    return 0;
  }
  if (path[0] == '.')
    return 0;
  char *copy = strdup(path);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "event path allocation");
  char *slash = strrchr(copy, '/');
  if (!slash) {
    free(copy);
    return 0;
  }
  *slash++ = 0;
  if (slash[0] == '.') {
    free(copy);
    return 0;
  }
  for (int k = 0; k < t->schema.n; k++) {
    Node *node = &t->schema.node[k];
    if (!strcmp(node->type, "DIRECTORY"))
      continue;
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    if (SQLi_schema_record_path(&probe, &t->schema, copy) ||
        SQLi_field_name_check(&probe, node, slash))
      continue;
    Member *old = NULL;
    for (int i = 0; i < t->nr && !old; i++)
      for (int j = 0; j < t->r[i].nm; j++)
        if (!strcmp(t->r[i].m[j].path, path)) {
          old = &t->r[i].m[j];
          break;
        }
    unsigned kind =
        op == 'N'   ? SQL_EVENT_UPDATE /* cross-table shared-value notice */
        : op == 'T' ? SQL_EVENT_RENAME
        : op == 'L' ? SQL_EVENT_LINK
        : op == 'D' ? SQL_EVENT_DELETE
        : old ? (S_ISLNK(old->st.st_mode) ? SQL_EVENT_UNLINK : SQL_EVENT_UPDATE)
              : SQL_EVENT_INSERT;
    int rc = add(e, list, count, cap, copy, node->name, path, kind);
    free(copy);
    return rc;
  }
  free(copy);
  return 0;
}
int sql_event_prepare(Env *e, Batch *b) {
  Table *t = calloc(1, sizeof(*t));
  if (!t)
    return SQLi_fail(e, SQL_IO, "event table allocation");
  t->fd = dup(b->root);
  int rc = -1, mf = -1, out = -1;
  Logical *list = NULL;
  size_t count = 0, cap = 0;
  char *json = NULL;
  size_t length = 0;
  FILE *stream = NULL;
  SQL_EventHeader h = {.Magic = SQL_EVENT_MAGIC,
                       .Version = 1,
                       .Bytes = sizeof(h),
                       .UID = getuid()};
  struct stat identity, prior;
  /* Objects without a prior table definition (transactional CREATE TABLE,
   * view participants) publish the minimal physical commit event only. */
  if (t->fd >= 0 && fstatat(t->fd, ".table", &prior, AT_SYMLINK_NOFOLLOW) &&
      errno == ENOENT) {
    rc = 0;
    goto done;
  }
  if (t->fd < 0 || fstat(t->fd, &identity) ||
      SQLi_map_read(e, t->fd, ".table", &t->map) ||
      SQLi_schema_text(e, t->map.DDL, &t->schema) || SQLi_scan_table(e, t, 0))
    goto done;
  h.Generation = t->map.generation + 1;
  h.Device = identity.st_dev;
  h.Inode = identity.st_ino;
  strcpy(h.Transaction, b->name + 9);
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", b->root);
  ssize_t plen = readlink(proc, t->path, PATH_MAX - 1);
  if (plen < 0)
    goto io;
  t->path[plen] = 0;
  mf = openat(b->fd, "manifest", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  Header header;
  if (mf < 0 || sql_read_all(mf, &header, sizeof(header)))
    goto io;
  stream = open_memstream(&json, &length);
  if (!stream)
    goto io;
  fprintf(stream, "{\"transaction\":\"%s\",\"generation\":%llu,\"table\":",
          h.Transaction, (unsigned long long)h.Generation);
  SQLi_json(stream, (unsigned char *)t->path, strlen(t->path));
  fputs(",\"physical\":[", stream);
  int first = 1;
  for (;;) {
    Entry entry;
    ssize_t n = read(mf, &entry, sizeof(entry));
    if (!n)
      break;
    if (n != sizeof(entry) || entry.a >= PATH_MAX || entry.b >= PATH_MAX)
      goto io;
    char a[PATH_MAX], v[PATH_MAX];
    if (sql_read_all(mf, a, entry.a) || sql_read_all(mf, v, entry.b))
      goto io;
    a[entry.a] = 0;
    v[entry.b] = 0;
    if ((entry.type == 'P' || entry.type == 'H' || entry.type == 'L' ||
         entry.type == 'D' || entry.type == 'R' || entry.type == 'M' ||
         entry.type == 'T' || entry.type == 'N') &&
        logical_path(e, t, &list, &count, &cap, a, entry.type, v))
      goto done;
    if (!strcmp(a, ".table") || strstr(a, "/.sql-id") ||
        strstr(a, "/.sql-null."))
      continue;
    if (!first)
      fputc(',', stream);
    first = 0;
    fprintf(stream, "{\"operation\":\"%c\",\"path\":", (char)entry.type);
    SQLi_json(stream, (unsigned char *)a, strlen(a));
    fputc('}', stream);
  }
  fputs("],\"logical\":[", stream);
  if (count)
    qsort(list, count, sizeof(*list), order);
  for (size_t i = 0; i < count; i++) {
    Logical *l = &list[i];
    h.Kind |= l->kind;
    unsigned f;
    for (f = 0; f < h.FieldCount; f++)
      if (!strcmp(h.Fields[f], l->field))
        break;
    if (f == h.FieldCount && h.FieldCount < 64)
      strcpy(h.Fields[h.FieldCount++], l->field);
    if (i)
      fputc(',', stream);
    fprintf(stream, "{\"event\":%zu,\"kind\":%u,\"record\":", i, l->kind);
    SQLi_json(stream, (unsigned char *)l->record, strlen(l->record));
    fputs(",\"field\":", stream);
    SQLi_json(stream, (unsigned char *)l->field, strlen(l->field));
    fputs(",\"path\":", stream);
    SQLi_json(stream, (unsigned char *)l->path, strlen(l->path));
    fputc('}', stream);
  }
  fputs("]}\n", stream);
  if (fclose(stream)) {
    stream = NULL;
    goto io;
  }
  stream = NULL;
  if (length > VALMAX) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "event JSON limit 64 MiB exceeded before decision");
    goto done;
  }
  h.Length = length;
  h.Hash = digest(json, length, 1469598103934665603ULL);
  h.HeaderHash = digest(&h, sizeof(h), 1469598103934665603ULL);
  out = openat(b->fd, "event",
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (out < 0 || sql_write_all(out, &h, sizeof(h)) ||
      sql_write_all(out, json, length) || fsync(out) || fsync(b->fd))
    goto io;
  rc = 0;
  goto done;
io:
  SQLi_fail(e, SQL_IO, "prepare durable logical event: %s", strerror(errno));
done:
  if (stream)
    fclose(stream);
  free(json);
  if (mf >= 0)
    close(mf);
  if (out >= 0)
    close(out);
  for (size_t i = 0; i < count; i++) {
    free(list[i].record);
    free(list[i].path);
  }
  free(list);
  SQLi_table_close(t);
  free(t);
  return rc;
}
int sql_event_publish(Env *e, int root, int journal, const char *name) {
  int meta = -1, events = -1, event = -1, rc = -1;
  if (mkdirat(root, ".sql", 0700) && errno != EEXIST)
    goto done;
  meta = openat(root, ".sql", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (meta < 0 || (mkdirat(meta, "events", 0700) && errno != EEXIST))
    goto done;
  events =
      openat(meta, "events", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (events < 0)
    goto done;
  char temp[80];
  snprintf(temp, sizeof(temp), ".tmp.%s", name + 9);
  unlinkat(events, temp, 0);
  struct stat st;
  if (!fstatat(journal, "event", &st, AT_SYMLINK_NOFOLLOW)) {
    event = sql_regular_open(e, journal, "event", 0, NULL);
    SQL_EventHeader h;
    if (event < 0 || sql_event_read(e, event, &h))
      goto done;
    if (strcmp(h.Transaction, name + 9)) {
      SQLi_fail(e, SQL_CONSTRAINT, "event/journal transaction mismatch");
      goto done;
    }
    if (linkat(journal, "event", events, temp, 0))
      goto done;
  } else if (errno == ENOENT) {
    event = openat(events, temp,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    char text[128];
    int n =
        snprintf(text, sizeof(text), "{\"transaction\":\"%s\"}\n", name + 9);
    if (event < 0 || sql_write_all(event, text, n) || fsync(event))
      goto done;
  } else
    goto done;
  if (renameat(events, temp, events, name + 9) || fsync(events) ||
      fsync(meta) || fsync(root))
    goto done;
  rc = 0;
done:
  if (event >= 0)
    close(event);
  if (events >= 0)
    close(events);
  if (meta >= 0)
    close(meta);
  return rc ? SQLi_fail(e, e->status ? e->status : SQL_IO,
                        "publish durable event")
            : 0;
}
