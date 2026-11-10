/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Durable command-to-journal binding survives a torn context slot. Ordinary
 * private redo metadata, not a mapped format; never interpreted as executable
 * SQL. */
#include "sql_local.h"
typedef struct {
  uint32_t Magic, Version, UID, Bytes;
  uint64_t Hash;
  SQL_Command Command;
} CommandProof;
static uint64_t checksum(SQL_Command *c) {
  uint64_t h = 1469598103934665603ULL;
  unsigned char *p = (void *)c;
  for (size_t i = 0; i < sizeof(*c); i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}
static int read_proof(Env *e, SQL_Session *s, CommandProof *p) {
  struct stat st;
  if (fstatat(s->workspace, ".command-local", &st, AT_SYMLINK_NOFOLLOW)) {
    if (errno == ENOENT)
      return 0;
    return SQLi_fail(e, SQL_IO, "stat command journal proof");
  }
  if (!S_ISREG(st.st_mode) || st.st_size != sizeof(*p) ||
      st.st_uid != getuid() || (st.st_mode & 0077) || st.st_nlink != 1)
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid private command journal proof");
  int fd = sql_regular_open(e, s->workspace, ".command-local", 0, NULL);
  if (fd < 0)
    return -1;
  int bad = sql_read_all(fd, p, sizeof(*p));
  close(fd);
  if (bad || p->Magic != 0x31504353 || p->Version != 1 || p->UID != getuid() ||
      p->Bytes != sizeof(*p) || p->Hash != checksum(&p->Command))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "invalid command journal proof checksum/version");
  if (sql_command_valid(e, &p->Command))
    return -1;
  return 1;
}
int sql_command_proof_store(Env *e, SQL_Session *s) {
  if (!*s->map.Command.LocalTransaction)
    return 0;
  CommandProof *p = calloc(1, sizeof(*p));
  if (!p)
    return SQLi_fail(e, SQL_IO, "command proof allocation");
  if (read_proof(e, s, p) < 0) {
    free(p);
    return -1;
  }
  *p = (CommandProof){.Magic = 0x31504353,
                      .Version = 1,
                      .UID = getuid(),
                      .Bytes = sizeof(*p),
                      .Command = s->map.Command};
  p->Hash = checksum(&p->Command);
  char id[33], temp[80];
  if (sql_uuid(e, id)) {
    free(p);
    return -1;
  }
  snprintf(temp, sizeof(temp), ".command-local.%s", id);
  int fd = openat(s->workspace, temp,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  int bad = fd < 0 || sql_write_all(fd, p, sizeof(*p)) || fsync(fd);
  if (fd >= 0)
    close(fd);
  free(p);
  if (!bad)
    bad = renameat(s->workspace, temp, s->workspace, ".command-local") ||
          fsync(s->workspace);
  if (bad) {
    unlinkat(s->workspace, temp, 0);
    return SQLi_fail(e, SQL_IO, "sync command journal proof");
  }
  return 0;
}
int sql_command_proof_restore(Env *e, SQL_Session *s) {
  SQL_Command *c = &s->map.Command;
  if (c->Phase == SQL_CMD_NONE || c->Phase == SQL_CMD_APPLIED || c->reserved)
    return 0;
  CommandProof *p = malloc(sizeof(*p));
  if (!p)
    return SQLi_fail(e, SQL_IO, "command proof allocation");
  int rc = read_proof(e, s, p);
  if (rc <= 0) {
    free(p);
    return rc;
  }
  SQL_Command *v = &p->Command;
  if (v->Sequence < c->Sequence) {
    free(p);
    return 0;
  }
  if (v->Sequence != c->Sequence || strcmp(v->Verb, c->Verb) ||
      strcmp(v->Text, c->Text) || strcmp(v->Cwd, c->Cwd) ||
      v->BindingCount != c->BindingCount || v->ValueLength != c->ValueLength ||
      v->LockTimeout != c->LockTimeout || v->Output != c->Output ||
      v->InputCount != c->InputCount ||
      memcmp(v->Input, c->Input, c->InputCount * sizeof(c->Input[0])) ||
      memcmp(v->Binding, c->Binding, c->BindingCount * sizeof(c->Binding[0])) ||
      memcmp(v->Values, c->Values, c->ValueLength) ||
      strcmp(v->Transaction, c->Transaction)) {
    free(p);
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "command proof does not match active command; preserve for inspection");
  }
  strcpy(c->LocalTransaction, v->LocalTransaction);
  strcpy(c->LocalRoot, v->LocalRoot);
  c->LocalDevice = v->LocalDevice;
  c->LocalInode = v->LocalInode;
  c->LocalTable = v->LocalTable;
  if (v->Phase == SQL_CMD_DECIDED)
    c->Phase = SQL_CMD_DECIDED;
  free(p);
  return 0;
}
