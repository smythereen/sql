/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Explicit synchronous watcher. Real trigger-unit wakeups are hints only;
 * every wake/overflow/timeout rescans durable generation-ordered events. */
#include "sql_trigger_meta.h"
#include <signal.h>
#include <sys/inotify.h>
typedef struct {
  char Name[33];
  SQL_EventHeader Header;
} Event;
typedef struct {
  unsigned wakeups, overflows;
} Wake;
static void wake(s32 tag, char *path, u32 mask, void *arg) {
  (void)tag;
  (void)path;
  Wake *w = arg;
  w->wakeups++;
  if (mask & IN_Q_OVERFLOW)
    w->overflows++;
}
static int event_order(const void *a, const void *b) {
  const Event *x = a, *y = b;
  if (x->Header.Generation != y->Header.Generation)
    return x->Header.Generation < y->Header.Generation ? -1 : 1;
  return strcmp(x->Name, y->Name);
}
/* The event envelope aggregates kinds/fields for indexing only. Match both
 * against one canonical logical entry, never their Cartesian product. */
static int event_string(const char **cursor, const char *end,
                        const char **start, size_t *length) {
  const char *p = *cursor, *begin = p;
  if (p == end || *p++ != '"')
    return -1;
  while (p < end) {
    unsigned char c = *p++;
    if (c == '"') {
      *cursor = p;
      if (start)
        *start = begin;
      if (length)
        *length = p - begin;
      return 0;
    }
    if (c < 32)
      return -1;
    if (c == '\\') {
      if (p == end)
        return -1;
      c = *p++;
      if (c == 'u') {
        for (int i = 0; i < 4; i++)
          if (p == end || !isxdigit((unsigned char)*p++))
            return -1;
      } else if (!strchr("\"\\/bfnrt", c))
        return -1;
    }
  }
  return -1;
}
static int event_number(const char **cursor, const char *end,
                        unsigned long long *number) {
  const char *p = *cursor;
  if (p == end || !isdigit((unsigned char)*p))
    return -1;
  unsigned long long n = 0;
  while (p < end && isdigit((unsigned char)*p)) {
    unsigned d = *p++ - '0';
    if (n > (ULLONG_MAX - d) / 10)
      return -1;
    n = n * 10 + d;
  }
  *cursor = p;
  *number = n;
  return 0;
}
static int event_literal(const char **cursor, const char *end,
                         const char *text) {
  size_t n = strlen(text);
  if ((size_t)(end - *cursor) < n || memcmp(*cursor, text, n))
    return -1;
  *cursor += n;
  return 0;
}
/* Decodes one SQLi_json string (raw UTF-8 plus \\ \" and \u00XX bytes). */
static char *event_decode(const char *s, size_t n) {
  char *out = malloc(n + 1);
  size_t k = 0;
  if (!out)
    return NULL;
  for (size_t i = 1; i + 1 < n; i++) {
    if (s[i] != '\\') {
      out[k++] = s[i];
      continue;
    }
    char c = s[++i];
    if (c == 'u') {
      unsigned v = 0;
      if (i + 4 >= n || sscanf(s + i + 1, "%4x", &v) != 1 || v > 255) {
        free(out);
        return NULL;
      }
      out[k++] = (char)v;
      i += 4;
    } else
      out[k++] = c == 'n' ? '\n' : c == 't' ? '\t' : c == 'r' ? '\r'
                 : c == 'b' ? '\b' : c == 'f' ? '\f' : c;
  }
  out[k] = 0;
  if (memchr(out, 0, k)) {
    free(out);
    return NULL;
  }
  return out;
}
typedef struct {
  const char *table; /* absolute watched table root */
  Table t;
  int open;
  Expr *x;
} Where;
static const char *kind_name(unsigned long long kind) {
  return kind & SQL_EVENT_INSERT   ? "INSERT"
         : kind & SQL_EVENT_UPDATE ? "UPDATE"
         : kind & SQL_EVENT_DELETE ? "DELETE"
         : kind & SQL_EVENT_LINK   ? "LINK"
         : kind & SQL_EVENT_UNLINK ? "UNLINK"
                                   : "RENAME";
}
/* WHERE sees the committed post-image record (absent fields read NULL; a
 * deleted record reads all-NULL) plus event_kind/field/path/record. */
static int where_match(Env *e, Where *w, unsigned long long kind,
                       const char *record, const char *field,
                       const char *path) {
  if (!w->open) {
    if (SQLi_table_open(e, &w->t, w->table, 0))
      return -1;
    w->open = 1;
    if (SQLi_scan_table(e, &w->t, 0))
      return -1;
  }
  Record empty = {.path = (char *)record}, *r = &empty;
  for (int i = 0; i < w->t.nr; i++)
    if (!strcmp(w->t.r[i].path, record))
      r = &w->t.r[i];
  if (r == &empty) {
    empty.values = calloc(NODES, sizeof(*empty.values));
    if (!empty.values)
      return SQLi_fail(e, SQL_IO, "trigger WHERE allocation");
    for (int i = 0; i < NODES; i++)
      empty.values[i].null = 1;
  }
  int saved = e->missing_null, scope = e->event_scope;
  e->missing_null = 1;
  e->event_scope = 1;
  e->event_kind = kind_name(kind);
  e->event_field = field;
  e->event_path = path;
  e->event_record = record;
  int rc = SQLi_predicate(e, w->x, &w->t, r, NULL);
  e->missing_null = saved;
  e->event_scope = scope;
  e->event_kind = e->event_field = e->event_path = e->event_record = NULL;
  free(empty.values);
  return rc;
}
static int selected_entries(Env *e, SQL_TriggerDef *d, SQL_EventHeader *h,
                            int fd, Where *w);
static int selected(Env *e, SQL_TriggerDef *d, SQL_EventHeader *h, int fd,
                    const char *table) {
  if (!(d->Kind & h->Kind))
    return 0;
  if (!d->FieldCount && !*sql_trg_where(d))
    return 1;
  Where w = {.table = table};
  if (*sql_trg_where(d)) {
    Parser *q = calloc(1, sizeof(*q));
    if (!q)
      return SQLi_fail(e, SQL_IO, "trigger WHERE parser allocation");
    int bad = SQLi_lex(e, q, sql_trg_where(d)) ||
              !(w.x = SQLi_expr_parse(e, q)) || SQLi_end(e, q);
    SQLi_parser_free(q);
    free(q);
    if (bad) {
      SQLi_expr_free(w.x);
      return -1;
    }
  }
  int rc = selected_entries(e, d, h, fd, &w);
  if (w.open)
    SQLi_table_close(&w.t);
  SQLi_expr_free(w.x);
  return rc;
}
static int selected_entries(Env *e, SQL_TriggerDef *d, SQL_EventHeader *h,
                            int fd, Where *w) {
  char encoded[16][512];
  size_t sizes[16];
  for (unsigned i = 0; i < d->FieldCount; i++) {
    FILE *f = fmemopen(encoded[i], sizeof(encoded[i]), "w");
    if (!f)
      return SQLi_fail(e, SQL_IO, "event filter buffer");
    SQLi_json(f, (unsigned char *)d->Fields[i], strlen(d->Fields[i]));
    long n = ftell(f);
    int bad = ferror(f) || n < 0;
    if (fclose(f) || bad)
      return SQLi_fail(e, SQL_IO, "event filter encoding");
    sizes[i] = n;
  }
  char *body = malloc(h->Length + 1);
  if (!body)
    return SQLi_fail(e, SQL_IO, "event filter allocation");
  if (lseek(fd, sizeof(*h), SEEK_SET) < 0 ||
      sql_read_all(fd, body, h->Length)) {
    free(body);
    return SQLi_fail(e, SQL_IO, "event filter bytes");
  }
  body[h->Length] = 0;
  const char *p = strstr(body, ",\"logical\":["), *end = body + h->Length;
  int match = 0;
  if (!p || memchr(body, 0, h->Length))
    goto invalid;
  p += strlen(",\"logical\":[");
  while (p < end && *p != ']') {
    unsigned long long ordinal, kind;
    const char *field, *record, *path;
    size_t length, record_length, path_length;
    if (event_literal(&p, end, "{\"event\":") ||
        event_number(&p, end, &ordinal) ||
        event_literal(&p, end, ",\"kind\":") || event_number(&p, end, &kind) ||
        kind > SQL_EVENT_ALL || event_literal(&p, end, ",\"record\":") ||
        event_string(&p, end, &record, &record_length) ||
        event_literal(&p, end, ",\"field\":") ||
        event_string(&p, end, &field, &length) ||
        event_literal(&p, end, ",\"path\":") ||
        event_string(&p, end, &path, &path_length) ||
        event_literal(&p, end, "}"))
      goto invalid;
    int hit = 0;
    if (d->Kind & kind) {
      hit = !d->FieldCount;
      for (unsigned i = 0; i < d->FieldCount; i++)
        if (length == sizes[i] && !memcmp(field, encoded[i], length))
          hit = 1;
    }
    if (hit && !match && w->x) {
      char *r = event_decode(record, record_length),
           *f = event_decode(field, length), *q = event_decode(path, path_length);
      int ok = r && f && q ? where_match(e, w, kind & d->Kind, r, f, q) : -2;
      free(r);
      free(f);
      free(q);
      if (ok == -2)
        goto invalid;
      if (ok < 0) {
        free(body);
        return -1;
      }
      hit = ok;
    }
    if (hit)
      match = 1;
    if (p < end && *p == ',') {
      p++;
      if (p == end || *p != '{')
        goto invalid;
    } else
      break;
  }
  if (event_literal(&p, end, "]}\n") || p != end)
    goto invalid;
  free(body);
  return match;
invalid:
  free(body);
  return SQLi_fail(e, SQL_CONSTRAINT,
                   "noncanonical logical event body; checkpoint unchanged");
}
static int scan(Env *e, int root, int events, Event **list, size_t *count) {
  *list = NULL;
  *count = 0;
  if (SQLi_lockdir(e, root, 0))
    return -1;
  Env probe = *e;
  SQL_Result ignored = {0};
  probe.out = &ignored;
  probe.status = 0;
  if (SQLi_pending(&probe, root)) {
    flock(root, LOCK_UN);
    if (probe.status == SQL_COMMITTED_PENDING)
      return 1;
    return SQLi_fail(e, probe.status, "%s", ignored.diagnostic);
  }
  DIR *dir = fdopendir(openat(events, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!dir) {
    flock(root, LOCK_UN);
    return SQLi_fail(e, SQL_IO, "scan durable events");
  }
  struct stat identity;
  if (fstat(root, &identity)) {
    closedir(dir);
    flock(root, LOCK_UN);
    return SQLi_fail(e, SQL_IO, "watch source identity");
  }
  struct dirent *de;
  size_t cap = 0;
  int rc = 0;
  while ((de = readdir(dir))) {
    if (de->d_name[0] == '.')
      continue;
    if (strlen(de->d_name) != 32) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "unknown durable event filename");
      break;
    }
    for (int i = 0; i < 32; i++)
      if (!isxdigit((unsigned char)de->d_name[i])) {
        rc = SQLi_fail(e, SQL_CONSTRAINT, "invalid durable event id");
        break;
      }
    if (rc)
      break;
    int fd = sql_regular_open(e, events, de->d_name, 0, NULL);
    SQL_EventHeader h;
    if (fd < 0 || sql_event_read(e, fd, &h)) {
      if (fd >= 0)
        close(fd);
      rc = -1;
      break;
    }
    close(fd);
    if (!h.Generation)
      continue;
    if (strcmp(h.Transaction, de->d_name) || h.Device != identity.st_dev ||
        h.Inode != identity.st_ino) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "event belongs to another source/id");
      break;
    }
    if (*count == 65536) {
      rc = SQLi_fail(e, SQL_CONSTRAINT, "watch event scan limit 65536");
      break;
    }
    if (*count == cap) {
      cap = cap ? cap * 2 : 32;
      Event *next = realloc(*list, cap * sizeof(**list));
      if (!next) {
        rc = SQLi_fail(e, SQL_IO, "event scan allocation");
        break;
      }
      *list = next;
    }
    Event *entry = &(*list)[(*count)++];
    strcpy(entry->Name, de->d_name);
    entry->Header = h;
  }
  closedir(dir);
  flock(root, LOCK_UN);
  if (!rc) {
    if (*count)
      qsort(*list, *count, sizeof(**list), event_order);
  } else {
    free(*list);
    *list = NULL;
    *count = 0;
  }
  return rc;
}
static int run(Env *e, trig_w_t *watch, Wake *w, SQL_TriggerDef *d, int event) {
  int program = sql_trg_exec_pin(e, d, 0);
  if (program < 0)
    return -1;
  pid_t pid = fork();
  if (pid < 0) {
    close(program);
    return SQLi_fail(e, SQL_IO, "fork trigger");
  }
  if (!pid) {
    setpgid(0, 0);
    if (dup2(event, STDIN_FILENO) < 0)
      _exit(126);
    int null = open("/dev/null", O_WRONLY);
    if (null < 0)
      _exit(126);
    dup2(null, STDOUT_FILENO);
    dup2(null, STDERR_FILENO);
    if (null > 2)
      close(null);
    fcntl(program, F_SETFD, 0);
    char *argv[10];
    argv[0] = d->Exec;
    for (unsigned i = 0; i < d->ArgCount; i++)
      argv[i + 1] = d->Args[i];
    argv[d->ArgCount + 1] = NULL;
    char *env[] = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8", NULL};
    fexecve(program, argv, env);
    _exit(127);
  }
  close(program);
  setpgid(pid, pid);
  uint64_t until = Trig_Mono() + d->Timeout;
  int status = 0;
  for (;;) {
    siginfo_t exited = {0};
    int wait = waitid(P_PID, pid, &exited, WEXITED | WNOHANG | WNOWAIT);
    if (!wait && exited.si_pid == pid) {
      kill(-pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      return WIFEXITED(status)
                 ? WEXITSTATUS(status)
                 : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }
    if (wait < 0 && errno != EINTR)
      return SQLi_fail(e, SQL_IO, "wait trigger child");
    if (Trig_Mono() >= until) {
      kill(-pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      return 124;
    }
    if (Trig_Poll(watch, 20, wake, w) < 0 && errno != EINTR) {
      kill(-pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      return SQLi_fail(e, SQL_IO, "trigger-unit poll during child");
    }
  }
}
static int checkpoint(Env *e, int root, unsigned slot, SQL_TriggerDef *sent,
                      SQL_EventHeader *h, unsigned status, int success) {
  if (SQLi_lockdir(e, root, 0))
    return -1;
  int fd = sql_trg_open(e, root, 0), rc = -1;
  SQL_TriggerMap *m = malloc(sizeof(*m));
  if (!m) {
    SQLi_fail(e, SQL_IO, "checkpoint allocation");
    goto done;
  }
  if (fd < 0 || SQLi_lockdir(e, fd, 1) || sql_trg_read(e, fd, m))
    goto done;
  SQL_TriggerDef *d = &m->Trigger[slot];
  if (!d->Used || strcmp(d->Nonce, sent->Nonce)) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "trigger changed during delivery; event remains unacknowledged");
    goto done;
  }
  d->LastStatus = status;
  int advanced_skip = 0;
  if (success) {
    if (h->Generation > d->Checkpoint) {
      advanced_skip = success == 2;
      d->Checkpoint = h->Generation;
      strcpy(d->LastTransaction, h->Transaction);
      if (success == 1)
        d->Delivered++;
    }
  } else
    d->Failures++;
  rc = sql_trg_save_skipped(e, fd, m, slot, advanced_skip);
done:
  free(m);
  if (fd >= 0)
    close(fd);
  flock(root, LOCK_UN);
  return rc;
}
int sql_watch_engine(Env *e, Parser *p) {
  if (SQLi_eat(p, "VIEW"))
    return sql_view_watch(e, p);
  char *path = NULL, *only = NULL;
  if (SQLi_eat(p, "ON")) {
    path = take(e, p);
    if (!path)
      return -1;
  }
  if (SQLi_need(e, p, "FOR"))
    return -1;
  if (!SQLi_eat(p, "ALL")) {
    only = take(e, p);
    if (!only)
      return -1;
  }
  int once = SQLi_eat(p, "ONCE");
  if (!once)
    SQLi_eat(p, "CONTINUOUS");
  SQLi_eat(p, "RESUME");
  unsigned duration = 0;
  if (SQLi_eat(p, "DURATION")) {
    char *s = take(e, p), *end;
    if (!s)
      return -1;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || *end || !*s || *s == '-' || !n || n > 3600000)
      return SQLi_fail(e, SQL_CONSTRAINT, "DURATION 1..3600000 milliseconds");
    duration = n;
  }
  if (SQLi_end(e, p))
    return -1;
  if (sql_context_active(e))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "WATCH cannot run inside an active data transaction");
  int root = SQLi_open_dir(e, path), meta = -1, events = -1, rc = -1;
  trig_w_t *watch = NULL;
  SQL_TraceScope trace = {0};
  Event *list = NULL;
  SQL_Map table;
  SQL_TriggerMap *m = malloc(sizeof(*m));
  if (!m) {
    if (root >= 0)
      close(root);
    return SQLi_fail(e, SQL_IO, "watch metadata allocation");
  }
  if (root < 0 || SQLi_lockdir(e, root, 1) ||
      SQLi_map_read(e, root, ".table", &table))
    goto done;
  meta = openat(root, ".sql", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (meta < 0) {
    SQLi_fail(e, SQL_CONSTRAINT, "initialize trigger registrations first");
    goto done;
  }
  if ((mkdirat(meta, "events", 0700) && errno != EEXIST) || fsync(meta) ||
      fsync(root)) {
    SQLi_fail(e, SQL_IO, "initialize event stream");
    goto done;
  }
  events =
      openat(meta, "events", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (events < 0)
    goto io;
  int config = sql_trg_open(e, root, 0);
  if (config < 0)
    goto done;
  if (sql_trg_read(e, config, m) ||
      sql_trace_map(e, config, sizeof(SQL_TriggerFile),
                    offsetof(SQL_TriggerFile, LiveTraceLevel), PROT_WRITE,
                    &trace)) {
    close(config);
    goto done;
  }
  close(config);
  if (only) {
    int found = 0;
    for (unsigned i = 0; i < m->Count; i++)
      if (m->Trigger[i].Used && !strcmp(m->Trigger[i].Name, only))
        found = 1;
    if (!found) {
      SQLi_fail(e, SQL_CONSTRAINT, "unknown selected trigger");
      goto done;
    }
  }
  Trace(SQL_TRACE, "SQL watch initialized on durable event stream");
  char proc[64], absolute[PATH_MAX];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", events);
  ssize_t n = readlink(proc, absolute, sizeof(absolute) - 1);
  if (n < 0)
    goto io;
  absolute[n] = 0;
  char table_abs[PATH_MAX];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", root);
  ssize_t tn = readlink(proc, table_abs, sizeof(table_abs) - 1);
  if (tn < 0)
    goto io;
  table_abs[tn] = 0;
  if (n >= TRIG_PATH_LEN) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "trigger watch path exceeds actual trigger-unit bound 255 bytes");
    goto done;
  }
  watch = Trig_Open();
  if (!watch || Trig_Add(watch, absolute,
                         IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE |
                             IN_DELETE_SELF | IN_MOVE_SELF,
                         0, 0, 1) < 0)
    goto io;
  flock(root, LOCK_UN);
  { /* re-drive cross-table fanout intentions left by an interrupted owner */
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    probe.session = NULL;
    probe.no_context = 1;
    sql_fanout_drain_root(&probe, table_abs);
  }
  Wake w = {0};
  if (getenv("SQL_TEST_WATCH_OVERFLOW"))
    wake(1, absolute, IN_Q_OVERFLOW, &w);
  uint64_t until = duration ? Trig_Mono() + duration : 0;
  unsigned delivered = 0, skipped = 0;
  int blocked = 0;
  for (;;) {
    Trace(SQL_TRACE, "SQL watch rescan durable event stream");
    size_t count = 0;
    int scanned = scan(e, root, events, &list, &count);
    if (scanned < 0)
      goto done;
    blocked = scanned == 1;
    if (!blocked) {
      for (unsigned slot = 0; slot < SQL_TRG_MAX; slot++) {
        if (SQLi_lockdir(e, root, 0))
          goto done;
        config = sql_trg_open(e, root, 0);
        if (config < 0) {
          flock(root, LOCK_UN);
          goto done;
        }
        int bad = SQLi_lockdir(e, config, 0) || sql_trg_read(e, config, m);
        close(config);
        flock(root, LOCK_UN);
        if (bad)
          goto done;
        SQL_TriggerDef d = m->Trigger[slot];
        if (!d.Used || (only && strcmp(d.Name, only)) || !d.Enabled)
          continue;
        char lease[80];
        snprintf(lease, sizeof(lease), "watch.%s", d.Nonce);
        int lock = openat(meta, lease,
                          O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (lock < 0)
          goto io;
        struct stat owned;
        if (fstat(lock, &owned) || !S_ISREG(owned.st_mode) ||
            owned.st_uid != getuid() || (owned.st_mode & 0077)) {
          close(lock);
          SQLi_fail(e, SQL_CONSTRAINT, "invalid watch lease");
          goto done;
        }
        if (flock(lock, LOCK_EX | LOCK_NB)) {
          close(lock);
          continue;
        } /* Reload after lease acquisition: another drainer may have advanced
             it. */
        if (SQLi_lockdir(e, root, 0)) {
          close(lock);
          goto done;
        }
        config = sql_trg_open(e, root, 0);
        bad = config < 0 || SQLi_lockdir(e, config, 0) ||
              sql_trg_read(e, config, m);
        if (config >= 0)
          close(config);
        flock(root, LOCK_UN);
        if (bad) {
          close(lock);
          goto done;
        }
        if (!m->Trigger[slot].Used || strcmp(m->Trigger[slot].Nonce, d.Nonce) ||
            !m->Trigger[slot].Enabled) {
          close(lock);
          continue;
        }
        d = m->Trigger[slot];
        for (size_t i = 0; i < count; i++) {
          if (SQLi_lockdir(e, root, 0)) {
            close(lock);
            goto done;
          }
          config = sql_trg_open(e, root, 0);
          bad = config < 0 || SQLi_lockdir(e, config, 0) ||
                sql_trg_read(e, config, m);
          if (config >= 0)
            close(config);
          flock(root, LOCK_UN);
          if (bad) {
            close(lock);
            goto done;
          }
          if (!m->Trigger[slot].Used ||
              strcmp(m->Trigger[slot].Nonce, d.Nonce) ||
              !m->Trigger[slot].Enabled)
            break;
          d = m->Trigger[slot];
          SQL_EventHeader *h = &list[i].Header;
          if (h->Generation <= d.Checkpoint)
            continue;
          int input = sql_regular_open(e, events, list[i].Name, 0, NULL);
          SQL_EventHeader actual;
          if (input < 0 || sql_event_read(e, input, &actual)) {
            if (input >= 0)
              close(input);
            close(lock);
            goto done;
          }
          int matches = selected(e, &d, &actual, input, table_abs);
          if (matches < 0) {
            close(input);
            close(lock);
            goto done;
          }
          if (!matches) {
            close(input);
            if (checkpoint(e, root, slot, &d, h, 0, 2)) {
              close(lock);
              goto done;
            }
            d.Checkpoint = h->Generation;
            skipped++;
            continue;
          }
          int status = 1;
          for (unsigned retry = 0; retry <= d.Retries; retry++) {
            if (lseek(input, sizeof(actual), SEEK_SET) < 0) {
              status = -1;
              break;
            }
            status = run(e, watch, &w, &d, input);
            if (status <= 0)
              break;
          }
          close(input);
          if (status < 0) {
            close(lock);
            goto done;
          }
          if (getenv("SQL_TEST_CRASH") &&
              !strcmp(getenv("SQL_TEST_CRASH"), "watch-after-exec"))
            _exit(110);
          if (checkpoint(e, root, slot, &d, h, status, status == 0)) {
            close(lock);
            goto done;
          }
          if (status) {
            close(lock);
            SQLi_fail(e, SQL_IO,
                      "trigger %s failed after bounded retries (status %d); "
                      "checkpoint not advanced",
                      d.Name, status);
            goto done;
          }
          d.Checkpoint = h->Generation;
          delivered++;
        }
        close(lock);
      }
    }
    free(list);
    list = NULL;
    if (once) {
      if (blocked) {
        SQLi_fail(
            e, SQL_COMMITTED_PENDING,
            "committed source recovery gate is not clear; no events delivered");
        goto done;
      }
      break;
    }
    uint64_t now = Trig_Mono();
    if (until && now >= until)
      break;
    int wait = until && until - now < 1000 ? (int)(until - now) : 1000;
    if (Trig_Poll(watch, wait, wake, &w) < 0 && errno != EINTR)
      goto io;
  }
  fprintf(e->stream,
          "{\"delivered\":%u,\"skipped\":%u,\"wakeups\":%u,\"overflows\":%u}\n",
          delivered, skipped, w.wakeups, w.overflows);
  rc = 0;
  goto done;
io:
  SQLi_fail(e, SQL_IO, "watch/trigger-unit I/O: %s", strerror(errno));
done:
  free(list);
  sql_trace_unmap(&trace);
  if (watch)
    Trig_Close(watch);
  if (events >= 0)
    close(events);
  if (meta >= 0)
    close(meta);
  if (root >= 0)
    close(root);
  free(m);
  return rc;
}
