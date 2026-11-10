/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
#include <signal.h>
/* sys/lineage.c compares a process-local cached ancestry; its first 1 is not
 * proof of a live owner. Its parser splits comm on spaces, and arrays have no
 * bounds checks. Never change that unit here or trust its result by itself. */
int sql_process_info(pid_t pid, SQL_Process *out) {
  if (pid <= 0) {
    errno = EINVAL;
    return -1;
  }
  char path[80], buf[4096];
  snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  struct stat st;
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int bad = fstat(fd, &st);
  close(fd);
  if (n <= 0 || n == (ssize_t)sizeof(buf) - 1 || bad)
    return -1;
  buf[n] = 0;
  char *first = strchr(buf, '('), *last = strrchr(buf, ')');
  if (!first || !last || last <= first || last[1] != ' ' ||
      (size_t)(last - first - 1) >= sizeof(out->comm)) {
    errno = EINVAL;
    return -1;
  }
  char *end;
  errno = 0;
  long number = strtol(buf, &end, 10);
  if (errno || end != first - 1 || number != pid) {
    errno = EINVAL;
    return -1;
  }
  SQL_Process p = {.pid = pid, .uid = st.st_uid};
  memcpy(p.comm, first + 1, last - first - 1);
  char *save = NULL;
  int field = 3, have = 0;
  for (char *x = strtok_r(last + 2, " \t\n", &save); x;
       x = strtok_r(NULL, " \t\n", &save), field++) {
    if (field == 3) {
      if (strlen(x) != 1)
        return -1;
      p.state = *x;
    } else if (field == 4) {
      errno = 0;
      long parent = strtol(x, &end, 10);
      if (errno || *end || parent < 0 || parent > INT_MAX)
        return -1;
      p.parent = parent;
      have |= 1;
    } else if (field == 22) {
      errno = 0;
      p.birth = strtoull(x, &end, 10);
      if (errno || *end || !p.birth)
        return -1;
      have |= 2;
      break;
    }
  }
  if (have != 3 || p.state == 'Z' || p.state == 'X' || p.state == 'x') {
    errno = ESRCH;
    return -1;
  }
  *out = p;
  return 0;
}
static uint64_t mix(uint64_t h, uint64_t n) {
  for (int i = 0; i < 8; i++) {
    h ^= (unsigned char)(n >> (i * 8));
    h *= 1099511628211ULL;
  }
  return h;
}
int sql_process_lineage(pid_t pid, uint64_t *hash, int *legacy_safe) {
  pid_t seen[128];
  int count = 0, safe = 1;
  uint64_t h = 1469598103934665603ULL;
  while (pid > 0) {
    if (count == 128) {
      errno = EOVERFLOW;
      return -1;
    }
    for (int i = 0; i < count; i++)
      if (seen[i] == pid) {
        errno = ELOOP;
        return -1;
      }
    SQL_Process p;
    if (sql_process_info(pid, &p))
      return -1;
    seen[count++] = pid;
    h = mix(mix(mix(mix(h, p.pid), p.parent), p.uid), p.birth);
    for (const unsigned char *s = (unsigned char *)p.comm; *s; s++)
      if (isspace(*s))
        safe = 0;
    if (pid == 1) {
      pid = 0;
      break;
    }
    pid = p.parent;
  }
  if (!count) {
    errno = ESRCH;
    return -1;
  }
  if (legacy_safe)
    *legacy_safe = safe && count <= 28;
  *hash = h;
  return 0;
}
extern pid_t The_Line[32], New_Line[32];
int sql_lineage_guard(Env *e, SQL_ContextMap *m) {
  uint64_t hash;
  int safe;
  if (sql_lineage_state(m))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "stored full owner lineage changed; RESUME required");
  if (!m->LineageVersion)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "legacy context requires explicit checked handle to "
                     "provision ancestry");
  if (sql_process_lineage(m->PID, &hash, &safe) || hash != m->LineageHash)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "context owner lineage changed; implicit inheritance "
                     "stopped; use an explicit checked handle or recovery");
  if (safe) {
    /* Isolate sys's cache and sticky no_lineage from the embedding caller.
     * Preflight above bounds every write and excludes its comm parser defect.
     * Positive PID avoids treating its initial return as applicability. */
    pid_t child = fork();
    if (child < 0)
      return SQLi_fail(e, SQL_IO, "lineage verification fork");
    if (!child) {
      struct sigaction action = {.sa_handler = SIG_DFL};
      sigemptyset(&action.sa_mask);
      sigaction(SIGALRM, &action, NULL);
      alarm(2);
      memset(The_Line, 0, sizeof(pid_t) * 32);
      memset(New_Line, 0, sizeof(pid_t) * 32);
      int first = lineage(m->PID), second = lineage(m->PID);
      _exit(first && second ? 0 : 1);
    }
    int status;
    pid_t done;
    do {
      done = waitpid(child, &status, 0);
    } while (done < 0 && errno == EINTR);
    if (done != child || !WIFEXITED(status) || WEXITSTATUS(status))
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "sys lineage changed during context applicability check");
  }
  /* An ancestry change during the sys probe must not be accepted either. */
  if (sql_process_lineage(m->PID, &hash, NULL) || hash != m->LineageHash)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "context ancestry changed during verification");
  return 0;
}
int sql_lineage_capture(Env *e, SQL_ContextMap *m) {
  pid_t pid = m->PID;
  uint64_t h = 1469598103934665603ULL;
  m->LineageCount = 0;
  memset(m->Lineage, 0, sizeof(m->Lineage));
  while (pid > 0) {
    if (m->LineageCount == SQL_LINEAGE_MAX)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "owner ancestry exceeds 128; not truncated");
    SQL_Process p;
    if (sql_process_info(pid, &p))
      return SQLi_fail(e, SQL_CONSTRAINT, "owner ancestry disappeared");
    for (unsigned i = 0; i < m->LineageCount; i++)
      if (m->Lineage[i].PID == (uint32_t)pid)
        return SQLi_fail(e, SQL_CONSTRAINT, "ancestry cycle");
    m->Lineage[m->LineageCount++] =
        (SQL_Ancestor){p.pid, p.parent, p.uid, 0, p.birth};
    h = mix(mix(mix(mix(h, p.pid), p.parent), p.uid), p.birth);
    if (pid == 1)
      break;
    pid = p.parent;
  }
  if (!m->LineageCount)
    return SQLi_fail(e, SQL_CONSTRAINT, "empty owner lineage");
  m->LineageHash = h;
  m->LineageVersion = 2;
  return 0;
}
/* 0 live, 1 changed, 2 dead/reused, 3 prior boot, 4 unverified legacy. */
int sql_lineage_state(SQL_ContextMap *m) {
  char current[40];
  if (sql_boot(current) || strcmp(current, m->Boot))
    return 3;
  SQL_Process owner;
  if (sql_process_info(m->PID, &owner) || owner.uid != m->UID ||
      owner.birth != m->Birth)
    return 2;
  if (m->LineageVersion != 2 || !m->LineageCount ||
      m->LineageCount > SQL_LINEAGE_MAX)
    return 4;
  for (unsigned i = 0; i < m->LineageCount; i++) {
    SQL_Ancestor *a = &m->Lineage[i];
    SQL_Process p;
    if (sql_process_info(a->PID, &p) || p.pid != (pid_t)a->PID ||
        p.uid != a->UID || p.birth != a->Birth || p.parent != (pid_t)a->Parent)
      return 1;
    if (i == 0 && a->PID != m->PID)
      return 1;
    if (i + 1 < m->LineageCount && a->Parent != m->Lineage[i + 1].PID)
      return 1;
  }
  SQL_Ancestor *last = &m->Lineage[m->LineageCount - 1];
  return last->PID != 1 && last->Parent ? 1 : 0;
}
