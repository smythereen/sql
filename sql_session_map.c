/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int sql_write_all(int fd, const void *data, size_t size) {
  const char *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    p += n;
    size -= n;
  }
  return 0;
}
int sql_read_all(int fd, void *data, size_t size) {
  char *p = data;
  while (size) {
    ssize_t n = read(fd, p, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    p += n;
    size -= n;
  }
  return 0;
}
int sql_uuid(Env *e, char *out) {
  unsigned char b[16];
  if (getrandom(b, 16, 0) != 16)
    return SQLi_fail(e, SQL_IO, "random identity unavailable");
  for (int i = 0; i < 16; i++)
    sprintf(out + 2 * i, "%02x", b[i]);
  return 0;
}
int sql_regular_open(Env *e, int dir, const char *name, int writeable,
                     struct stat *st) {
  int pin = openat(dir, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  struct stat local;
  if (!st)
    st = &local;
  if (pin < 0)
    return SQLi_fail(e, SQL_IO, "open regular %s: %s", name, strerror(errno));
  if (fstat(pin, st) || !S_ISREG(st->st_mode)) {
    close(pin);
    return SQLi_fail(e, SQL_CONSTRAINT, "not a regular file: %s", name);
  }
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", pin);
  int fd = open(proc, (writeable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
  close(pin);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open pinned regular %s: %s", name,
                     strerror(errno));
  return fd;
}
static int birth(pid_t pid, uint64_t *start, uid_t *owner) {
  SQL_Process p;
  if (sql_process_info(pid, &p))
    return -1;
  *start = p.birth;
  *owner = p.uid;
  return 0;
}
int sql_boot(char *out) {
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, out, 39);
  close(fd);
  if (n <= 0)
    return -1;
  out[n] = 0;
  out[strcspn(out, "\r\n")] = 0;
  return strlen(out) == 36 ? 0 : -1;
}
static int hexid(const char *s) {
  if (!memchr(s, 0, 33) || strlen(s) != 32)
    return 0;
  for (int i = 0; i < 32; i++)
    if (!isxdigit((unsigned char)s[i]))
      return 0;
  return 1;
}
int sql_ctx_valid(Env *e, SQL_ContextMap *m, int allow_dead) {
  if (m->magic != SQL_CTX_MAGIC || m->version != 3 || m->bytes != sizeof(*m) ||
      m->endian != 0x01020304 || m->UID != getuid() || m->State > 2 ||
      m->LineageCount > SQL_LINEAGE_MAX ||
      (m->LineageVersion == 2 && !m->LineageCount) || m->ReadOnly > 1 ||
      m->Count > SQL_TX_TABLES || m->Output > 3 || m->LineageVersion > 2 ||
      (!m->LineageVersion && m->LineageHash) || m->LockTimeout > 3600000 ||
      !memchr(m->Root, 0, sizeof(m->Root)) || *m->Root != '/' ||
      !memchr(m->Boot, 0, sizeof(m->Boot)) || !hexid(m->Nonce) ||
      (m->Txid[0] && !hexid(m->Txid)))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid context identity, bounds or map version");
  for (unsigned i = 0; i < m->Count; i++)
    if (!memchr(m->Table[i].Path, 0, PATH_MAX) || m->Table[i].Path[0] != '/')
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid context table entry");
  if (sql_command_valid(e, &m->Command))
    return -1;
  if (!allow_dead) {
    uint64_t start;
    uid_t uid;
    char current[40];
    if (sql_boot(current) || strcmp(current, m->Boot) ||
        birth(m->PID, &start, &uid) || uid != getuid() || start != m->Birth)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "stale/reused-PID context; inspect SHOW CONTEXTS and "
                       "RECOVER DATABASE; do not discard staged data");
  }
  return 0;
}
static uint64_t context_hash(SQL_ContextRecord *r) {
  uint64_t h = 1469598103934665603ULL;
  const unsigned char *p = (void *)&r->Sequence;
  for (size_t i = 0; i < sizeof(r->Sequence); i++) {
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
static int valid_slot(SQL_ContextRecord *r) {
  return r->Sequence && r->Hash == context_hash(r);
}
int sql_ctx_read(Env *e, int fd, SQL_ContextMap *m, int allow_dead) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
      st.st_size != sizeof(SQL_ContextFile) || st.st_uid != getuid() ||
      (st.st_mode & 0077) || st.st_nlink != 1)
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "context must be a private owned regular v4 dual-slot map");
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  SQL_ContextFile *p = sql_mapping(e, fd, sizeof(*p), PROT_WRITE);
  if (!p)
    return SQLi_fail(e, SQL_IO, "context Map failed");
  int rc = -1;
  if (p->magic != SQL_CTX_FILE_MAGIC || p->version != 4 ||
      p->bytes != sizeof(*p) || p->endian != 0x01020304 ||
      p->TraceVersion > 1) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "invalid context file magic/version/size/endian");
    goto done;
  }
  int a = valid_slot(&p->Slot[0].Record), b = valid_slot(&p->Slot[1].Record);
  if (!a && !b) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "neither context slot has a valid checksum; do not guess state");
    goto done;
  }
  int index = !a   ? 1
              : !b ? 0
                   : p->Slot[1].Record.Sequence > p->Slot[0].Record.Sequence;
  *m = p->Slot[index].Record.Value;
  if (p->TraceVersion == 1)
    m->TraceLevel = __atomic_load_n(&p->LiveTraceLevel, __ATOMIC_ACQUIRE);
  rc = sql_ctx_valid(e, m, allow_dead);
done:
  sql_unmapping(p);
  return rc;
}
int sql_ctx_save(Env *e, SQL_Session *s) {
  if (sql_ctx_valid(e, &s->map, s->admin_identity))
    return -1;
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", s->fd);
  SQL_ContextFile *p = sql_mapping(e, s->fd, sizeof(*p), PROT_WRITE);
  if (!p)
    return SQLi_fail(e, SQL_IO, "context writable Map failed");
  int rc = -1;
  if (!p->magic && !p->version && !p->bytes && !p->Slot[0].Record.Sequence &&
      !p->Slot[1].Record.Sequence) {
    p->magic = SQL_CTX_FILE_MAGIC;
    p->version = 4;
    p->bytes = sizeof(*p);
    p->endian = 0x01020304;
  }
  if (p->magic != SQL_CTX_FILE_MAGIC || p->version != 4 ||
      p->bytes != sizeof(*p) || p->endian != 0x01020304) {
    SQLi_fail(e, SQL_CONSTRAINT, "invalid context file identity during save");
    goto done;
  }
  if (!p->TraceVersion) {
    p->LiveTraceLevel = s->map.TraceLevel;
    p->TraceVersion = 1;
  }
  if (p->TraceVersion != 1) {
    SQLi_fail(e, SQL_CONSTRAINT, "invalid context live trace header");
    goto done;
  }
  s->map.TraceLevel = __atomic_load_n(&p->LiveTraceLevel, __ATOMIC_ACQUIRE);
  int a = valid_slot(&p->Slot[0].Record), b = valid_slot(&p->Slot[1].Record);
  uint64_t first = a ? p->Slot[0].Record.Sequence : 0,
           second = b ? p->Slot[1].Record.Sequence : 0;
  uint64_t current = first > second ? first : second;
  if (current == UINT64_MAX) {
    SQLi_fail(e, SQL_CONSTRAINT, "context sequence exhausted");
    goto done;
  }
  int index = !a ? 0 : !b ? 1 : first > second ? 1 : 0;
  SQL_ContextRecord record = {.Sequence = current + 1, .Value = s->map};
  record.Hash = context_hash(&record);
  memcpy(&p->Slot[index].Record, &record, sizeof(record));
  UpdateMap(p, sizeof(*p));
  rc = msync(p, sizeof(*p), MS_SYNC);
  if (!rc)
    rc = fsync(s->fd);
  if (!rc)
    rc = fsync(s->workspace);
  if (!rc)
    rc = fsync(s->root);
  if (rc)
    SQLi_fail(e, SQL_IO,
              "context synchronous update failed; inspect state before retry");
done:
  sql_unmapping(p);
  return rc;
}
int sql_root_check(Env *e, int root) {
  struct stat st;
  int fd = sql_regular_open(e, root, ".sql-root", 0, &st);
  if (fd < 0)
    return -1;
  char text[64] = {0};
  ssize_t n = read(fd, text, sizeof(text) - 1);
  close(fd);
  char expected[64];
  snprintf(expected, sizeof(expected), "SQL-COORDINATOR-2 uid=%u\n",
           (unsigned)getuid());
  return n == (ssize_t)strlen(expected) && !memcmp(text, expected, n) &&
                 st.st_uid == getuid() && !(st.st_mode & 0077)
             ? 0
             : SQLi_fail(e, SQL_CONSTRAINT,
                         "invalid/foreign coordinator marker");
}
static int root_create(Env *e, int root) {
  struct stat st;
  if (!fstatat(root, ".sql-root", &st, AT_SYMLINK_NOFOLLOW))
    return sql_root_check(e, root);
  if (errno != ENOENT)
    return SQLi_fail(e, SQL_IO, "inspect coordinator marker");
  char id[33], temporary[80];
  if (sql_uuid(e, id))
    return -1;
  snprintf(temporary, sizeof(temporary), ".sql-map.%s.root", id);
  int fd = openat(root, temporary,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create private coordinator marker");
  char text[64];
  int n = snprintf(text, sizeof(text), "SQL-COORDINATOR-2 uid=%u\n",
                   (unsigned)getuid());
  int rc = sql_write_all(fd, text, n) || fsync(fd);
  close(fd);
  int published = 0;
  if (!rc) {
    rc = renameat2(root, temporary, root, ".sql-root", RENAME_NOREPLACE);
    published = !rc;
  }
  if (!rc)
    rc = fsync(root);
  unlinkat(root, temporary, 0);
  return rc ? SQLi_fail(e, published ? SQL_COMMITTED_PENDING : SQL_IO,
                        "coordinator marker provisioning %s",
                        published ? "published; durability uncertain"
                                  : "failed before publication")
            : 0;
}
int sql_registry(Env *e, int root, int create) {
  if (create && mkdirat(root, ".context", 0700) && errno != EEXIST)
    return SQLi_fail(e, SQL_IO, "create context registry");
  int fd =
      openat(root, ".context", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "open context registry: %s", strerror(errno));
  if (fstat(fd, &st) || st.st_uid != getuid() || (st.st_mode & 0077)) {
    close(fd);
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "context registry must be private and owned");
  }
  if (create && (fsync(fd) || fsync(root))) {
    close(fd);
    return SQLi_fail(e, SQL_IO, "sync context registry");
  }
  return fd;
}
static int canonical_fd(Env *e, int fd, char *path) {
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, path, PATH_MAX - 1);
  if (n < 0 || n == PATH_MAX - 1)
    return SQLi_fail(e, SQL_IO, "resolve context directory");
  path[n] = 0;
  return 0;
}
void sql_workspace_close(SQL_Session *s) {
  sql_trace_unmap(&s->trace);
  if (s->fd >= 0)
    close(s->fd);
  if (s->workspace >= 0)
    close(s->workspace);
  if (s->registry >= 0)
    close(s->registry);
  if (s->root >= 0)
    close(s->root);
  s->fd = s->workspace = s->registry = s->root = -1;
}
int sql_workspace_open(Env *e, const char *path, SQL_Session *s, int allow_dead,
                       int nonblock) {
  *s = (SQL_Session){.fd = -1,
                     .workspace = -1,
                     .registry = -1,
                     .root = -1,
                     .admin_identity = allow_dead};
  s->workspace = SQLi_open_dir(e, path);
  if (s->workspace < 0)
    return -1;
  struct stat st;
  if (fstat(s->workspace, &st) || st.st_uid != getuid() || (st.st_mode & 0077))
    return SQLi_fail(e, SQL_CONSTRAINT, "workspace must be private and owned");
  if (canonical_fd(e, s->workspace, s->path))
    return -1;
  char parent[PATH_MAX];
  strcpy(parent, s->path);
  char *name = strrchr(parent, '/');
  if (!name || !name[1])
    return SQLi_fail(e, SQL_CONSTRAINT, "workspace path");
  strcpy(s->name, name + 1);
  *name = 0;
  char *registry = strrchr(parent, '/');
  if (!registry || strcmp(registry, "/.context"))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "handle must name database/.context/pid workspace; legacy "
                     "maps require MIGRATE");
  *registry = 0;
  s->root = SQLi_open_dir(e, *parent ? parent : "/");
  if (s->root < 0 || sql_root_check(e, s->root))
    return -1;
  s->registry = sql_registry(e, s->root, 0);
  if (s->registry < 0)
    return -1;
  s->fd = sql_regular_open(e, s->workspace, ".state", 1, NULL);
  if (s->fd < 0)
    return -1;
  if (nonblock) {
    if (flock(s->fd, LOCK_EX | LOCK_NB))
      return SQLi_fail(e, SQL_IO, "workspace busy");
  } else if (SQLi_lockdir(e, s->fd, 1))
    return -1;
  if (sql_ctx_read(e, s->fd, &s->map, allow_dead))
    return -1;
  char expected[80], actual[PATH_MAX];
  snprintf(expected, sizeof(expected), "%u", s->map.PID);
  if (canonical_fd(e, s->root, actual) || strcmp(actual, s->map.Root) ||
      (strcmp(expected, s->name) &&
       (!allow_dead || sql_rebind_pending(e, s) != 1)))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "workspace filename/owner/root mismatch");
  int pending = sql_rebind_pending(e, s);
  if (pending < 0)
    return -1;
  if (pending && !allow_dead)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "interrupted owner rebind; explicit RESUME required");
  if (!allow_dead && sql_lineage_state(&s->map))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "saved context lineage changed/dead/prior-boot; explicit "
                     "RESUME is required");
  return 0;
}
static int resolve_context(Env *e, const char *explicit_path, const char *hint,
                           char *path) {
  const char *environment = getenv("SQL_CONTEXT"), *option = e->opt.context;
  if (option && environment && *environment && strcmp(option, environment))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "conflicting option and environment contexts");
  const char *handle = explicit_path                 ? explicit_path
                       : option                      ? option
                       : environment && *environment ? environment
                                                     : NULL;
  if (explicit_path && option && strcmp(explicit_path, option))
    return SQLi_fail(e, SQL_CONSTRAINT, "conflicting context handles");
  if (handle) {
    if (*handle == '/') {
      if (strlen(handle) >= PATH_MAX)
        return SQLi_fail(e, SQL_CONSTRAINT, "context path bound");
      strcpy(path, handle);
    } else if (SQLi_joinpath(e, path, e->cwd, handle))
      return -1;
    return 1;
  }
  char name[80];
  snprintf(name, sizeof(name), ".context/%ld", (long)getppid());
  return SQLi_joinpath(e, path, hint ? hint : e->cwd, name) ? -1 : 0;
}
int sql_session_load(Env *e, const char *handle, const char *hint,
                     int required) {
  if (e->no_context)
    return required ? SQLi_fail(e, SQL_CONSTRAINT, "context unavailable here")
                    : 0;
  if (e->session)
    return 0;
  char path[PATH_MAX];
  int explicit = resolve_context(e, handle, hint, path);
  if (explicit < 0)
    return -1;
  struct stat exists;
  if (lstat(path, &exists)) {
    if (errno == ENOENT && !explicit && !required)
      return 0;
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "context is not explicitly provisioned");
  }
  if (!S_ISDIR(exists.st_mode))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "context handle must be a workspace directory; legacy "
                     "file requires explicit MIGRATE");
  SQL_Session *s = malloc(sizeof(*s));
  if (!s)
    return SQLi_fail(e, SQL_IO, "out of memory");
  if (sql_workspace_open(e, path, s, 0, 0)) {
    sql_workspace_close(s);
    free(s);
    return -1;
  }
  if (!explicit && sql_lineage_guard(e, &s->map)) {
    sql_workspace_close(s);
    free(s);
    return -1;
  }
  e->session = s;
  if (sql_trace_map(e, s->fd, sizeof(SQL_ContextFile),
                    offsetof(SQL_ContextFile, LiveTraceLevel), PROT_WRITE,
                    &s->trace))
    return -1;
  Trace(SQL_TRACE, "SQL context %s state %u", s->path, s->map.State);
  if (*s->map.Txid &&
      (s->map.State == SQL_CTX_ACTIVE || s->map.State == SQL_CTX_COMMITTING)) {
    int outcome = sql_coord_outcome(e, s->root, s->map.Txid);
    if (outcome < 0)
      return -1;
    if (outcome) {
      uint32_t old = s->map.State;
      s->map.State = outcome == 1   ? SQL_CTX_IDLE
                     : outcome == 2 ? SQL_CTX_ACTIVE
                                    : SQL_CTX_COMMITTING;
      s->map.Outcome = outcome == 1 ? SQL_OUTCOME_COMMITTED : SQL_OUTCOME_NONE;
      s->reconciled = outcome == 1;
      if (outcome == 1) {
        s->map.Command.Phase = SQL_CMD_APPLIED;
        s->map.Command.Status = 0;
      } else if (outcome == 2 && !strcmp(s->map.Command.Verb, "commit")) {
        s->map.Command.Phase = SQL_CMD_FAILED;
        s->map.Command.Status = SQL_IO;
      }
      if (old != s->map.State && sql_ctx_save(e, s))
        return -1;
    }
  }
  if (!e->opt.lock_timeout_ms && s->map.LockTimeout)
    e->opt.lock_timeout_ms = s->map.LockTimeout;
  e->deferred = s->map.State == SQL_CTX_ACTIVE;
  return sql_command_start(e);
}
void sql_session_close(Env *e) {
  if (e->session) {
    sql_workspace_close(e->session);
    free(e->session);
    e->session = NULL;
  }
}
int sql_context_active(Env *e) {
  return e->session && e->session->map.State == SQL_CTX_ACTIVE;
}
int sql_context_output(Env *e) {
  return e->session ? e->session->map.Output : 0;
}
static int create_context(Env *e, Parser *p) {
  const char *path;
  if (SQLi_eat(p, "ON")) {
    path = take(e, p);
    if (!path)
      return -1;
    if (!*path)
      return SQLi_fail(e, SQL_SYNTAX,
                       "CONTEXT CREATE ON requires a nonempty root");
  } else {
    path = getenv("DATABASE_DIR");
    if (!path || !*path)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "CONTEXT CREATE requires ON root or nonempty "
                       "DATABASE_DIR; no current-directory fallback");
  }
  pid_t owner = getppid();
  if (SQLi_eat(p, "OWNER")) {
    char *s = take(e, p), *end;
    if (!s)
      return -1;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno || *end || n <= 0 || n > INT_MAX)
      return SQLi_fail(e, SQL_SYNTAX, "invalid owner PID");
    owner = n;
  }
  if (SQLi_end(e, p))
    return -1;
  SQL_Session *s = calloc(1, sizeof(*s));
  if (!s)
    return SQLi_fail(e, SQL_IO, "out of memory");
  s->fd = s->workspace = s->registry = s->root = -1;
  int rc = -1, published = 0;
  s->root = SQLi_open_dir(e, path);
  if (s->root < 0 || SQLi_lockdir(e, s->root, 1) || root_create(e, s->root))
    goto done;
  s->registry = sql_registry(e, s->root, 1);
  if (s->registry < 0)
    goto done;
  s->map = (SQL_ContextMap){.magic = SQL_CTX_MAGIC,
                            .version = 3,
                            .bytes = sizeof(SQL_ContextMap),
                            .endian = 0x01020304,
                            .UID = getuid(),
                            .PID = owner,
                            .LockTimeout = 5000};
  uid_t uid;
  if (birth(owner, &s->map.Birth, &uid) || uid != getuid() ||
      sql_boot(s->map.Boot) || sql_uuid(e, s->map.Nonce) ||
      sql_lineage_capture(e, &s->map)) {
    SQLi_fail(e, SQL_CONSTRAINT, "owner identity/ancestry unavailable");
    goto done;
  }
  if (canonical_fd(e, s->root, s->map.Root))
    goto done;
  snprintf(s->name, sizeof(s->name), "%u", s->map.PID);
  struct stat old;
  if (!fstatat(s->registry, s->name, &old, AT_SYMLINK_NOFOLLOW) ||
      errno != ENOENT) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "PID workspace collision; preserve and explicitly "
              "RESUME/MIGRATE/archive prior work");
    goto done;
  }
  char temporary[80];
  snprintf(temporary, sizeof(temporary), ".pending.%s", s->map.Nonce);
  if (mkdirat(s->registry, temporary, 0700)) {
    SQLi_fail(e, SQL_IO, "create private workspace");
    goto done;
  }
  s->workspace = openat(s->registry, temporary,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (s->workspace < 0 || mkdirat(s->workspace, "tables", 0700)) {
    SQLi_fail(e, SQL_IO, "create workspace tables");
    goto cleanup;
  }
  s->fd = openat(s->workspace, ".state",
                 O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (s->fd < 0 || SQLi_lockdir(e, s->fd, 1) ||
      ftruncate(s->fd, sizeof(SQL_ContextFile)) || sql_ctx_save(e, s)) {
    if (!e->status)
      SQLi_fail(e, SQL_IO, "provision context map");
    goto cleanup;
  }
  char relpath[128];
  snprintf(relpath, sizeof(relpath), ".context/%s", s->name);
  if (SQLi_joinpath(e, s->path, s->map.Root, relpath))
    goto cleanup;
  e->session = s;
  if (!e->provisioning && sql_command_start(e)) {
    e->session = NULL;
    goto cleanup;
  }
  e->session = NULL;
  if (renameat2(s->registry, temporary, s->registry, s->name,
                RENAME_NOREPLACE)) {
    SQLi_fail(e, SQL_IO, "publish context workspace");
    goto cleanup;
  }
  published = 1;
  if (fsync(s->registry) || fsync(s->root)) {
    SQLi_fail(e, SQL_COMMITTED_PENDING, "workspace published; sync uncertain");
    goto done;
  }
  char relative[128];
  snprintf(relative, sizeof(relative), ".context/%s", s->name);
  if (SQLi_joinpath(e, s->path, s->map.Root, relative))
    goto done;
  e->session = s;
  if (!e->provisioning && sql_command_finish(e)) {
    e->session = NULL;
    goto done;
  }
  e->session = NULL;
  if (!e->provisioning)
    fprintf(e->stream, "%s\n", s->path);
  rc = 0;
  goto done;
cleanup:
  if (!published)
    sql_tree_remove(e, s->registry, temporary);
done:
  sql_workspace_close(s);
  free(s);
  return rc;
}
int sql_context_create(Env *e, Parser *p) { return create_context(e, p); }
int sql_context_trace_set(Env *e, const char *handle, uint32_t value) {
  char path[PATH_MAX];
  if (resolve_context(e, handle, NULL, path) < 0)
    return -1;
  /* Trace-only writes do not take the long-held context mutex; shared root lock
   * prevents close/rebind while the stable live header is updated in place. */
  int workspace = SQLi_open_dir(e, path);
  if (workspace < 0)
    return -1;
  int fd = sql_regular_open(e, workspace, ".state", 1, NULL);
  if (fd < 0) {
    close(workspace);
    return -1;
  }
  SQL_ContextMap *map = malloc(sizeof(*map));
  int root = -1, rc = -1;
  if (!map) {
    SQLi_fail(e, SQL_IO, "out of memory");
    goto done;
  }
  if (sql_ctx_read(e, fd, map, 0))
    goto done;
  if (sql_lineage_state(map)) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "RESUME stale lineage before Trace configuration");
    goto done;
  }
  root = SQLi_open_dir(e, map->Root);
  if (root < 0 || sql_root_check(e, root) || SQLi_lockdir(e, root, 0))
    goto done;
  char expected[PATH_MAX], rel[80], actual[PATH_MAX];
  snprintf(rel, sizeof(rel), ".context/%u", map->PID);
  if (SQLi_joinpath(e, expected, map->Root, rel) ||
      canonical_fd(e, workspace, actual) || strcmp(expected, actual)) {
    SQLi_fail(e, SQL_CONSTRAINT, "trace workspace identity mismatch");
    goto done;
  }
  rc = sql_trace_store(e, fd, sizeof(SQL_ContextFile),
                       offsetof(SQL_ContextFile, LiveTraceLevel), value);
done:
  if (root >= 0)
    close(root);
  free(map);
  close(fd);
  close(workspace);
  return rc;
}
