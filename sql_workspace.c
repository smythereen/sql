/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
typedef struct {
  uint32_t magic, version, bytes, UID, From, To;
  uint64_t Hash;
  SQL_ContextMap Next;
} Rebind;
static uint64_t checksum(const void *data, size_t size) {
  const unsigned char *p = data;
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < size; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}
static int rebind_read(Env *e, SQL_Session *s, Rebind *proof) {
  struct stat st;
  if (fstatat(s->workspace, ".rebind", &st, AT_SYMLINK_NOFOLLOW))
    return errno == ENOENT ? 0 : SQLi_fail(e, SQL_IO, "inspect rebind proof");
  int fd = sql_regular_open(e, s->workspace, ".rebind", 0, &st);
  if (fd < 0)
    return -1;
  int bad = st.st_size != sizeof(*proof) || st.st_uid != getuid() ||
            (st.st_mode & 0077) || sql_read_all(fd, proof, sizeof(*proof));
  close(fd);
  if (bad || proof->magic != SQL_CTX_MAGIC || proof->version != 1 ||
      proof->bytes != sizeof(*proof) || proof->UID != getuid() ||
      proof->To != proof->Next.PID ||
      proof->Hash != checksum(&proof->Next, sizeof(proof->Next)) ||
      strcmp(proof->Next.Root, s->map.Root) ||
      sql_ctx_valid(e, &proof->Next, 1))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid owner rebind proof; preserve workspace");
  char from[80], to[80];
  snprintf(from, sizeof(from), "%u", proof->From);
  snprintf(to, sizeof(to), "%u", proof->To);
  if (strcmp(s->name, from) && strcmp(s->name, to))
    return SQLi_fail(e, SQL_CONSTRAINT, "rebind proof/name mismatch");
  return 1;
}
int sql_rebind_pending(Env *e, SQL_Session *s) {
  Rebind *proof = malloc(sizeof(*proof));
  if (!proof)
    return SQLi_fail(e, SQL_IO, "out of memory");
  int rc = rebind_read(e, s, proof);
  free(proof);
  return rc;
}
static int rebind_write(Env *e, SQL_Session *s, Rebind *proof) {
  proof->magic = SQL_CTX_MAGIC;
  proof->version = 1;
  proof->bytes = sizeof(*proof);
  proof->UID = getuid();
  proof->Hash = checksum(&proof->Next, sizeof(proof->Next));
  int fd = openat(s->workspace, ".rebind.tmp",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return SQLi_fail(e, SQL_IO, "create rebind proof");
  int bad = sql_write_all(fd, proof, sizeof(*proof)) || fsync(fd);
  close(fd);
  if (!bad && (renameat(s->workspace, ".rebind.tmp", s->workspace, ".rebind") ||
               fsync(s->workspace)))
    bad = 1;
  return bad ? SQLi_fail(e, SQL_IO, "persist owner rebind proof") : 0;
}
static void fault(const char *name, int code) {
  if (getenv("SQL_TEST_CRASH") && !strcmp(getenv("SQL_TEST_CRASH"), name))
    _exit(code);
}
int sql_workspace_resume(Env *e, Parser *p) {
  char *handle = take(e, p);
  if (!handle)
    return -1;
  pid_t owner = getppid();
  if (SQLi_eat(p, "OWNER")) {
    char *text = take(e, p), *end;
    if (!text)
      return -1;
    errno = 0;
    long n = strtol(text, &end, 10);
    if (errno || *end || n <= 0 || n > INT_MAX)
      return SQLi_fail(e, SQL_SYNTAX, "invalid resume owner");
    owner = n;
  }
  if (SQLi_end(e, p))
    return -1;
  SQL_Process identity;
  if (sql_process_info(owner, &identity) || identity.uid != getuid())
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "new owner must be a live same-UID process");
  SQL_Session *s = malloc(sizeof(*s));
  Rebind *proof = calloc(1, sizeof(*proof));
  if (!s || !proof) {
    free(s);
    free(proof);
    return SQLi_fail(e, SQL_IO, "out of memory");
  }
  int rc = -1;
  int prior_quiet = e->quiet_recovery;
  e->quiet_recovery = 1;
  if (sql_workspace_open(e, handle, s, 1, 0))
    goto done;
  int pending = rebind_read(e, s, proof);
  if (pending < 0)
    goto done;
  if (pending &&
      (proof->To != (uint32_t)owner || proof->Next.Birth != identity.birth)) {
    int previous = sql_lineage_state(&proof->Next);
    if (previous == 2 || previous == 3) {
      pending = 0;
      memset(proof, 0, sizeof(*proof));
    }
  }
  if (!pending) {
    int state = sql_lineage_state(&s->map);
    if (state != 2 && state != 3 && s->map.PID != (uint32_t)owner) {
      SQLi_fail(
          e, SQL_CONSTRAINT,
          "live owner workspace cannot be stolen; use its existing handle");
      goto done;
    }
    if (SQLi_lockdir(e, s->root, 1))
      goto done;
    e->session = s;
    if (*s->map.Txid && s->map.State != SQL_CTX_IDLE) {
      int outcome = sql_coord_outcome(e, s->root, s->map.Txid);
      if (outcome < 0) {
        e->session = NULL;
        goto done;
      }
      if (s->map.State == SQL_CTX_COMMITTING || outcome == 3) {
        int resolved;
        if (sql_coord_recover(e, s->root, s->map.Root, 1, s->map.Txid,
                              &resolved)) {
          e->session = NULL;
          goto done;
        }
        if (resolved == SQL_OUTCOME_COMMITTED) {
          s->map.State = SQL_CTX_IDLE;
          s->map.Outcome = SQL_OUTCOME_COMMITTED;
          s->map.Command.Phase = SQL_CMD_APPLIED;
          s->map.Command.Status = 0;
        } else
          s->map.State = SQL_CTX_ACTIVE;
      } else if (outcome == 1) {
        s->map.State = SQL_CTX_IDLE;
        s->map.Outcome = SQL_OUTCOME_COMMITTED;
        s->map.Command.Phase = SQL_CMD_APPLIED;
        s->map.Command.Status = 0;
      }
    }
    if (sql_command_reconcile(e)) {
      e->session = NULL;
      goto done;
    }
    e->session = NULL;
    if (s->map.State == SQL_CTX_ACTIVE && sql_command_inputs_check(e, s))
      goto done;
    proof->From = s->map.PID;
    proof->To = owner;
    proof->Next = s->map;
    proof->Next.PriorPID = s->map.PID;
    proof->Next.PriorUID = s->map.UID;
    proof->Next.PriorBirth = s->map.Birth;
    strcpy(proof->Next.PriorBoot, s->map.Boot);
    strcpy(proof->Next.PriorNonce, s->map.Nonce);
    proof->Next.PID = owner;
    proof->Next.UID = getuid();
    proof->Next.Birth = identity.birth;
    if (sql_boot(proof->Next.Boot) || sql_uuid(e, proof->Next.Nonce) ||
        sql_lineage_capture(e, &proof->Next) || rebind_write(e, s, proof))
      goto done;
  } else if (proof->To != (uint32_t)owner ||
             proof->Next.Birth != identity.birth) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "pending rebind belongs to another owner identity; preserve and "
              "inspect");
    goto done;
  }
  if (SQLi_lockdir(e, s->root, 1))
    goto done;
  char target[80];
  snprintf(target, sizeof(target), "%u", proof->To);
  fault("rebind-before-move", 96);
  if (strcmp(s->name, target)) {
    if (renameat2(s->registry, s->name, s->registry, target,
                  RENAME_NOREPLACE)) {
      SQLi_fail(e, SQL_CONSTRAINT,
                "target PID workspace collision; no overwrite");
      goto done;
    }
    if (fsync(s->registry)) {
      SQLi_fail(e, SQL_COMMITTED_PENDING,
                "rebind moved; registry sync uncertain");
      goto done;
    }
    strcpy(s->name, target);
  }
  fault("rebind-after-move", 97);
  s->map = proof->Next;
  if (sql_ctx_save(e, s))
    goto done;
  fault("rebind-after-state", 98);
  if (unlinkat(s->workspace, ".rebind", 0) || fsync(s->workspace)) {
    SQLi_fail(e, SQL_COMMITTED_PENDING,
              "owner rebound; proof cleanup uncertain");
    goto done;
  }
  char relative[128];
  snprintf(relative, sizeof(relative), ".context/%s", s->name);
  if (SQLi_joinpath(e, s->path, s->map.Root, relative))
    goto done;
  fprintf(e->stream, "%s\n", s->path);
  rc = 0;
done:
  e->quiet_recovery = prior_quiet;
  e->session = NULL;
  sql_workspace_close(s);
  free(s);
  free(proof);
  return rc;
}
/* Legacy v3 physical file, v2 payload. Never reinterpret it as the new map. */
#define LEGACY_BYTES offsetof(SQL_ContextMap, LineageCount)
#define LEGACY_SLOT_BYTES (((16 + LEGACY_BYTES + 4095) / 4096) * 4096)
#define LEGACY_FILE_BYTES (4096 + 2 * LEGACY_SLOT_BYTES)
int sql_legacy_read(Env *e, int fd, SQL_ContextMap *map) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
      st.st_size != LEGACY_FILE_BYTES || st.st_uid != getuid() ||
      (st.st_mode & 0077) || st.st_nlink != 1)
    return SQLi_fail(e, SQL_CONSTRAINT, "not a private legacy v3 context");
  unsigned char *data = sql_mapping(e, fd, LEGACY_FILE_BYTES, PROT_WRITE);
  if (!data)
    return -1;
  uint32_t header[6];
  memcpy(header, data, sizeof(header));
  int selected = -1;
  uint64_t seq = 0;
  if (header[0] != SQL_CTX_FILE_MAGIC || header[1] != 3 ||
      header[2] != LEGACY_FILE_BYTES || header[3] != 0x01020304 ||
      header[5] > 1) {
    sql_unmapping(data);
    return SQLi_fail(e, SQL_CONSTRAINT, "legacy context header/version");
  }
  for (int i = 0; i < 2; i++) {
    unsigned char *slot = data + 4096 + i * LEGACY_SLOT_BYTES;
    uint64_t n, h;
    memcpy(&n, slot, 8);
    memcpy(&h, slot + 8, 8);
    if (!n)
      continue;
    uint64_t calculated = 1469598103934665603ULL;
    for (size_t j = 0; j < 8 + LEGACY_BYTES; j++) {
      calculated ^= slot[j < 8 ? j : j + 8];
      calculated *= 1099511628211ULL;
    }
    if (h == calculated && (selected < 0 || n > seq)) {
      selected = i;
      seq = n;
    }
  }
  if (selected < 0) {
    sql_unmapping(data);
    return SQLi_fail(e, SQL_CONSTRAINT, "legacy slots invalid; preserve");
  }
  memset(map, 0, sizeof(*map));
  memcpy(map, data + 4096 + selected * LEGACY_SLOT_BYTES + 16, LEGACY_BYTES);
  if (map->magic != SQL_CTX_MAGIC || map->version != 2 ||
      map->bytes != LEGACY_BYTES) {
    sql_unmapping(data);
    return SQLi_fail(e, SQL_CONSTRAINT, "unsupported legacy payload");
  }
  if (header[5])
    map->TraceLevel = header[4];
  sql_unmapping(data);
  map->version = 3;
  map->bytes = sizeof(*map);
  return sql_ctx_valid(e, map, 1);
}
int sql_workspace_migrate(Env *e, Parser *p) {
  char *path = take(e, p);
  if (!path || SQLi_end(e, p))
    return -1;
  char absolute[PATH_MAX];
  if (*path == '/') {
    if (strlen(path) >= PATH_MAX)
      return SQLi_fail(e, SQL_CONSTRAINT, "legacy path bound");
    strcpy(absolute, path);
  } else if (SQLi_joinpath(e, absolute, e->cwd, path))
    return -1;
  char *last = strrchr(absolute, '/');
  if (!last || strncmp(last + 1, ".context_", 9))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "explicit legacy .context_PID file required");
  char legacy[80];
  if (strlen(last + 1) >= sizeof(legacy))
    return SQLi_fail(e, SQL_CONSTRAINT, "legacy filename bound");
  strcpy(legacy, last + 1);
  *last = 0;
  SQL_Session *s = calloc(1, sizeof(*s));
  if (!s)
    return SQLi_fail(e, SQL_IO, "out of memory");
  s->fd = s->workspace = s->registry = s->root = -1;
  s->admin_identity = 1;
  int source = -1, rc = -1, published = 0;
  char temporary[80] = {0};
  s->root = SQLi_open_dir(e, *absolute ? absolute : "/");
  if (s->root < 0 || sql_root_check(e, s->root) || SQLi_lockdir(e, s->root, 1))
    goto done;
  source = sql_regular_open(e, s->root, legacy, 1, NULL);
  if (source < 0 || SQLi_lockdir(e, source, 1) ||
      sql_legacy_read(e, source, &s->map))
    goto done;
  char canonical[PATH_MAX], proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", s->root);
  ssize_t n = readlink(proc, canonical, PATH_MAX - 1);
  if (n < 0) {
    SQLi_fail(e, SQL_IO, "legacy root");
    goto done;
  }
  canonical[n] = 0;
  char expected[80];
  snprintf(expected, sizeof(expected), ".context_%u", s->map.PID);
  if (strcmp(expected, legacy) || strcmp(canonical, s->map.Root)) {
    SQLi_fail(e, SQL_CONSTRAINT, "legacy owner/root mismatch");
    goto done;
  }
  s->registry = sql_registry(e, s->root, 1);
  if (s->registry < 0)
    goto done;
  snprintf(s->name, sizeof(s->name), "%u", s->map.PID);
  struct stat old;
  if (!fstatat(s->registry, s->name, &old, AT_SYMLINK_NOFOLLOW) ||
      errno != ENOENT) {
    SQLi_fail(e, SQL_CONSTRAINT,
              "migration workspace collision; source preserved");
    goto done;
  }
  char uuid[33];
  if (sql_uuid(e, uuid))
    goto done;
  snprintf(temporary, sizeof(temporary), ".migration.%s", uuid);
  if (mkdirat(s->registry, temporary, 0700)) {
    SQLi_fail(e, SQL_IO, "create migration workspace");
    goto done;
  }
  s->workspace = openat(s->registry, temporary,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (s->workspace < 0 || mkdirat(s->workspace, "tables", 0700)) {
    SQLi_fail(e, SQL_IO, "migration tables");
    goto done;
  }
  if (s->map.State != SQL_CTX_IDLE) {
    char stage[96];
    snprintf(stage, sizeof(stage), ".sql-context.%s.%s", s->map.Nonce,
             s->map.Txid);
    int in = openat(s->root, stage,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
        out = openat(s->workspace, "tables",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0 || out < 0 || sql_tree_copy(e, in, out, "legacy")) {
      if (in >= 0)
        close(in);
      if (out >= 0)
        close(out);
      if (!e->status)
        SQLi_fail(e, SQL_IO, "legacy pending data missing");
      goto done;
    }
    close(in);
    close(out);
  }
  SQL_Process current;
  char boot[40];
  if (!sql_boot(boot) && !strcmp(boot, s->map.Boot) &&
      !sql_process_info(s->map.PID, &current) &&
      current.birth == s->map.Birth && current.uid == s->map.UID) {
    if (sql_lineage_capture(e, &s->map))
      goto done;
  } else {
    s->map.LineageVersion = 0;
    s->map.LineageHash = 0;
    s->map.LineageCount = 0;
  }
  s->fd = openat(s->workspace, ".state",
                 O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (s->fd < 0 || ftruncate(s->fd, sizeof(SQL_ContextFile)) ||
      sql_ctx_save(e, s)) {
    if (!e->status)
      SQLi_fail(e, SQL_IO, "write upgraded state");
    goto done;
  }
  if (renameat2(s->registry, temporary, s->registry, s->name,
                RENAME_NOREPLACE) ||
      fsync(s->registry)) {
    SQLi_fail(e, SQL_COMMITTED_PENDING,
              "migration publish uncertain; preserve source");
    goto done;
  }
  published = 1;
  if (renameat2(s->root, legacy, s->workspace, ".legacy-state",
                RENAME_NOREPLACE) ||
      fsync(s->workspace) || fsync(s->root)) {
    SQLi_fail(e, SQL_COMMITTED_PENDING,
              "upgraded workspace exists; legacy archive uncertain");
    goto done;
  }
  char relative[128];
  snprintf(relative, sizeof(relative), ".context/%s", s->name);
  if (SQLi_joinpath(e, s->path, s->map.Root, relative))
    goto done;
  fprintf(e->stream, "%s\n", s->path);
  rc = 0;
done:
  if (source >= 0)
    close(source);
  if (rc && !published && s->registry >= 0 && *temporary)
    sql_tree_remove(e, s->registry, temporary);
  sql_workspace_close(s);
  free(s);
  return rc;
}
