/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
static int text_ok(const char *s, size_t cap) {
  return memchr(s, 0, cap) != NULL;
}
int sql_command_valid(Env *e, SQL_Command *c) {
  if (c->Output > 3 || c->LockTimeout > 3600000)
    return SQLi_fail(e, SQL_CONSTRAINT, "command option bounds");
  if (c->Phase > SQL_CMD_FAILED || c->BindingCount > 64 ||
      c->ValueLength > SQL_COMMAND_VALUES || c->InputCount > 64 ||
      c->TextLength >= SQL_COMMAND_TEXT || !text_ok(c->Text, sizeof(c->Text)) ||
      strlen(c->Text) != c->TextLength || !text_ok(c->Verb, sizeof(c->Verb)) ||
      !text_ok(c->Cwd, sizeof(c->Cwd)) ||
      !text_ok(c->LocalRoot, sizeof(c->LocalRoot)) ||
      !text_ok(c->Transaction, 33) || !text_ok(c->LocalTransaction, 33))
    return SQLi_fail(e, SQL_CONSTRAINT, "invalid command format/bounds");
  for (unsigned i = 0; i < c->BindingCount; i++) {
    SQL_CommandBinding *b = &c->Binding[i];
    if (!text_ok(b->Name, 64) || !*b->Name || b->Type > SQL_BIND_NULL ||
        b->Offset > c->ValueLength || b->Length > c->ValueLength - b->Offset)
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid command binding bounds");
  }
  for (unsigned i = 0; i < c->InputCount; i++)
    if (!text_ok(c->Input[i].Name, 64) ||
        strncmp(c->Input[i].Name, "inputs/", 7) ||
        !sql_safe_relative(c->Input[i].Name) || c->Input[i].Size > STREAMMAX)
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid captured input name");
  return 0;
}

int sql_command_inputs_check(Env *e, SQL_Session *s) {
  for (unsigned i = 0; i < s->map.Command.InputCount; i++) {
    SQL_CommandInput *item = &s->map.Command.Input[i];
    char base[NAME_MAX + 1];
    int parent = sql_parentfd(e, s->workspace, item->Name, base);
    if (parent < 0)
      return -1;
    struct stat st;
    int fd = sql_regular_open(e, parent, base, 0, &st);
    close(parent);
    if (fd < 0)
      return -1;
    if (st.st_uid != getuid() || (st.st_mode & 0077) ||
        st.st_dev != item->Device || st.st_ino != item->Inode ||
        st.st_size < 0 || (uint64_t)st.st_size != item->Size) {
      close(fd);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "owned command input identity/size changed");
    }
    unsigned char buf[65536];
    uint64_t size = 0, h = 1469598103934665603ULL;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
      size += n;
      for (ssize_t k = 0; k < n; k++) {
        h ^= buf[k];
        h *= 1099511628211ULL;
      }
      if (size > item->Size)
        break;
    }
    close(fd);
    if (n < 0 || size != item->Size || h != item->Hash)
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "owned command input bytes changed; pending context preserved");
  }
  return 0;
}
static int administrative(Env *e) {
  if (!e->verb || !e->statement)
    return 1;
  if (!strcmp(e->verb, "show") || !strcmp(e->verb, "recover"))
    return 1;
  if (strcmp(e->verb, "context"))
    return 0;
  Parser *p = e->parser;
  if (!p || !p->n)
    return 1;
  return !strcasecmp(p->t[0].s, "SHOW") || !strcasecmp(p->t[0].s, "RESUME") ||
         !strcasecmp(p->t[0].s, "MIGRATE") || !strcasecmp(p->t[0].s, "CLEAN") ||
         !strcasecmp(p->t[0].s, "INSPECT");
}
static int capture_input(Env *e, SQL_Session *s, SQL_Command *c,
                         unsigned token) {
  if (c->InputCount == 64)
    return SQLi_fail(e, SQL_CONSTRAINT, "maximum 64 captured FILE inputs");
  const char *source = e->parser->t[token].s;
  char *copy = strdup(source);
  if (!copy)
    return SQLi_fail(e, SQL_IO, "out of memory");
  char *slash = strrchr(copy, '/'), *name = slash ? slash + 1 : copy;
  if (slash)
    *slash = 0;
  int dir = SQLi_open_dir(e, slash ? (*copy ? copy : "/") : NULL);
  int payload = -1;
  size_t size = 0;
  int rc = -1;
  if (dir < 0)
    goto done;
  if (SQLi_open_payload(e, dir, name, &payload, &size, STREAMMAX))
    goto done;
  if (mkdirat(s->workspace, "inputs", 0700) && errno != EEXIST) {
    SQLi_fail(e, SQL_IO, "create owned input directory");
    goto done;
  }
  int inputs = openat(s->workspace, "inputs",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (inputs < 0) {
    SQLi_fail(e, SQL_IO, "open owned inputs");
    goto done;
  }
  char seq[24];
  snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->Sequence);
  if (mkdirat(inputs, seq, 0700) && errno != EEXIST) {
    close(inputs);
    SQLi_fail(e, SQL_IO, "create command input sequence");
    goto done;
  }
  int sequence =
      openat(inputs, seq, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (sequence < 0) {
    close(inputs);
    SQLi_fail(e, SQL_IO, "open command input sequence");
    goto done;
  }
  char member[12];
  snprintf(member, sizeof(member), "%u", c->InputCount);
  int fd = openat(sequence, member,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  unsigned long long hash = 1469598103934665603ULL;
  int bad = fd < 0 || SQLi_copy_fd(e, payload, fd, size, &hash) || fsync(fd);
  struct stat identity;
  if (fd >= 0) {
    if (fstat(fd, &identity))
      bad = 1;
    close(fd);
  }
  if (!bad && (fsync(sequence) || fsync(inputs) || fsync(s->workspace)))
    bad = 1;
  close(sequence);
  close(inputs);
  if (bad) {
    SQLi_fail(e, SQL_IO, "persist complete command input");
    goto done;
  }
  SQL_CommandInput *item = &c->Input[c->InputCount++];
  item->Token = token;
  item->Size = size;
  item->Device = identity.st_dev;
  item->Inode = identity.st_ino;
  item->Hash = hash;
  snprintf(item->Name, sizeof(item->Name), "inputs/%s/%s", seq, member);
  char full[PATH_MAX];
  if (SQLi_joinpath(e, full, s->path, item->Name))
    goto done;
  char *replacement = strdup(full);
  if (!replacement) {
    SQLi_fail(e, SQL_IO, "out of memory");
    goto done;
  }
  free(e->parser->t[token].s);
  e->parser->t[token].s = replacement;
  e->parser->t[token].quoted = 1;
  rc = 0;
done:
  if (dir >= 0)
    close(dir);
  if (payload >= 0)
    close(payload);
  free(copy);
  return rc;
}
int sql_command_start(Env *e) {
  SQL_Session *s = e->session;
  if (!s || s->recording || administrative(e))
    return 0;
  if (!strcmp(e->verb, "commit") && s->map.State == SQL_CTX_ACTIVE &&
      sql_command_inputs_check(e, s))
    return -1;
  SQL_Command *old = &s->map.Command;
  if (!strcmp(e->verb, "commit") && !strcmp(old->Verb, "commit") &&
      (old->Phase == SQL_CMD_EXECUTING || old->Phase == SQL_CMD_DECIDED ||
       (old->Phase == SQL_CMD_FAILED &&
        old->Status == SQL_COMMITTED_PENDING))) {
    if (sql_command_reconcile(e))
      return -1;
    old = &s->map.Command;
  }
  int pending_read = !strcmp(old->Verb, "select") ||
                     !strcmp(old->Verb, "describe") ||
                     !strcmp(old->Verb, "check") || !strcmp(old->Verb, "show");
  if (old->Phase == SQL_CMD_ACCEPTED || old->Phase == SQL_CMD_EXECUTING ||
      old->Phase == SQL_CMD_DECIDED ||
      (old->Phase == SQL_CMD_FAILED && old->Status == SQL_COMMITTED_PENDING &&
       !pending_read))
    return SQLi_fail(e, SQL_COMMITTED_PENDING,
                     "interrupted active command retained; "
                     "inspect/RESUME/RECOVER before new execution");
  if (old->Sequence == UINT64_MAX)
    return SQLi_fail(e, SQL_CONSTRAINT, "command sequence exhausted");
  SQL_Command *c = calloc(1, sizeof(*c));
  if (!c)
    return SQLi_fail(e, SQL_IO, "out of memory");
  c->Sequence = old->Sequence + 1;
  c->Phase = SQL_CMD_ACCEPTED;
  c->Output = s->map.Output;
  c->LockTimeout = e->opt.lock_timeout_ms ? e->opt.lock_timeout_ms : 5000;
  c->LocalTable = UINT32_MAX;
  if (strlen(e->verb) >= sizeof(c->Verb) ||
      strlen(e->statement) >= sizeof(c->Text)) {
    free(c);
    return SQLi_fail(
        e, SQL_CONSTRAINT,
        "command text/verb exceeds durable bound (65535 SQL bytes)");
  }
  strcpy(c->Verb, e->verb);
  strcpy(c->Text, e->statement);
  c->TextLength = strlen(c->Text);
  strcpy(c->Cwd, e->cwd);
  strcpy(c->Transaction, s->map.Txid);
  for (size_t i = 0; i < e->opt.binding_count; i++) {
    const SQL_Binding *b = &e->opt.bindings[i];
    if (!b->name || !*b->name || strlen(b->name) >= 64 ||
        b->type > SQL_BIND_NULL ||
        b->size > SQL_COMMAND_VALUES - c->ValueLength ||
        (b->size && !b->data)) {
      free(c);
      return SQLi_fail(
          e, SQL_CONSTRAINT,
          "durable binding name/value bound (aggregate 65536 bytes)");
    }
    SQL_CommandBinding *entry = &c->Binding[c->BindingCount++];
    strcpy(entry->Name, b->name);
    entry->Type = b->type;
    entry->Offset = c->ValueLength;
    entry->Length = b->size;
    if (b->size)
      memcpy(c->Values + c->ValueLength, b->data, b->size);
    c->ValueLength += b->size;
  }
  s->map.Command = *c;
  free(c);
  s->recording = 1;
  if (sql_ctx_save(e, s))
    return -1;
  if (getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "command-accepted"))
    _exit(94);
  if (e->parser)
    for (int i = 0; i + 3 < e->parser->n; i++)
      if (!e->parser->t[i].quoted && !strcasecmp(e->parser->t[i].s, "FILE") &&
          !strcmp(e->parser->t[i + 1].s, "(") &&
          !strcmp(e->parser->t[i + 3].s, ")")) {
        if (capture_input(e, s, &s->map.Command, i + 2))
          return -1;
      }
  s->map.Command.Phase = SQL_CMD_EXECUTING;
  if (sql_ctx_save(e, s))
    return -1;
  if (getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "command-executing"))
    _exit(95);
  return 0;
}
int sql_command_local(Env *e, const char *id, int root) {
  SQL_Session *s = e->session;
  if (!s || !s->recording || !strcmp(e->verb, "commit"))
    return 0;
  struct stat st;
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", root);
  ssize_t n = readlink(proc, s->map.Command.LocalRoot, PATH_MAX - 1);
  if (n < 0 || n == PATH_MAX - 1 || fstat(root, &st))
    return SQLi_fail(e, SQL_IO, "capture command journal root");
  s->map.Command.LocalRoot[n] = 0;
  s->map.Command.LocalDevice = st.st_dev;
  s->map.Command.LocalInode = st.st_ino;
  strcpy(s->map.Command.LocalTransaction, id);
  s->map.Command.LocalTable = e->participant;
  if (sql_command_proof_store(e, s))
    return -1;
  return sql_ctx_save(e, s);
}
int sql_command_decided(Env *e) {
  SQL_Session *s = e->session;
  if (!s || !s->recording)
    return 0;
  s->map.Command.Phase = SQL_CMD_DECIDED;
  if (sql_command_proof_store(e, s))
    return -1;
  return sql_ctx_save(e, s);
}
int sql_command_finish(Env *e) {
  SQL_Session *s = e->session;
  if (!s || !s->recording || s->closed)
    return 0;
  int decided = s->map.Command.Phase == SQL_CMD_DECIDED;
  if (getenv("SQL_TEST_CRASH") &&
      !strcmp(getenv("SQL_TEST_CRASH"), "command-before-ack"))
    _exit(99);
  s->map.Command.Phase = e->status ? SQL_CMD_FAILED : SQL_CMD_APPLIED;
  s->map.Command.Status = e->status;
  strcpy(s->map.Command.Transaction, s->map.Txid);
  int rc = sql_ctx_save(e, s);
  if (rc && decided) {
    e->status = SQL_COMMITTED_PENDING;
    snprintf(e->out->diagnostic, sizeof(e->out->diagnostic),
             "command committed; context acknowledgment uncertain; "
             "inspect/RESUME, never replay blindly");
  }
  return rc;
}
int sql_command_reconcile(Env *e) {
  SQL_Session *s = e->session;
  if (!s)
    return 0;
  if (sql_command_proof_restore(e, s))
    return -1;
  SQL_Command *c = &s->map.Command;
  if (c->Phase != SQL_CMD_ACCEPTED && c->Phase != SQL_CMD_EXECUTING &&
      c->Phase != SQL_CMD_DECIDED &&
      !(c->Phase == SQL_CMD_FAILED && c->Status == SQL_COMMITTED_PENDING))
    return 0;
  if (s->map.State == SQL_CTX_COMMITTING) {
    int outcome;
    int prior_quiet = e->quiet_recovery;
    e->quiet_recovery = 1;
    int recovery =
        sql_coord_recover(e, s->root, s->map.Root, 1, s->map.Txid, &outcome);
    e->quiet_recovery = prior_quiet;
    if (recovery)
      return -1;
    if (outcome == SQL_OUTCOME_COMMITTED) {
      s->map.State = SQL_CTX_IDLE;
      s->map.Outcome = SQL_OUTCOME_COMMITTED;
      s->reconciled = 1;
      c->Phase = SQL_CMD_APPLIED;
      c->Status = 0;
      return sql_ctx_save(e, s);
    }
    s->map.State = SQL_CTX_ACTIVE;
    c->Phase = SQL_CMD_FAILED;
    c->Status = SQL_IO;
    return sql_ctx_save(e, s);
  }
  int decided = c->Phase == SQL_CMD_DECIDED;
  if (*c->LocalTransaction) {
    int root = -1;
    if (c->LocalTable < s->map.Count) {
      int tables = sql_stage_root(e, s, 0);
      if (tables < 0)
        return -1;
      char index[32];
      snprintf(index, sizeof(index), "%u", c->LocalTable);
      root = openat(tables, index,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      close(tables);
    } else if (*c->LocalRoot)
      root = SQLi_open_dir(e, c->LocalRoot);
    if (root < 0)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "interrupted command root missing; no replay attempted");
    struct stat held, opened;
    if (!fstat(s->root, &held) && !fstat(root, &opened) &&
        held.st_dev == opened.st_dev && held.st_ino == opened.st_ino) {
      close(root);
      root = dup(s->root);
      if (root < 0)
        return SQLi_fail(e, SQL_IO, "duplicate recovery root");
    }
    struct stat st;
    if (fstat(root, &st) || st.st_dev != c->LocalDevice ||
        st.st_ino != c->LocalInode) {
      close(root);
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "interrupted command root identity changed");
    }
    char journal[80];
    snprintf(journal, sizeof(journal), ".sql-txn.%s", c->LocalTransaction);
    int j =
        openat(root, journal, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (j >= 0) {
      if (!fstatat(j, "COMMIT", &st, AT_SYMLINK_NOFOLLOW))
        decided = 1;
      close(j);
    }
    int prior_quiet = e->quiet_recovery;
    e->quiet_recovery = 1;
    int recovery = SQLi_lockdir(e, root, 1) || SQLi_recover(e, root, 1);
    e->quiet_recovery = prior_quiet;
    if (recovery) {
      close(root);
      return -1;
    }
    close(root);
  }
  c->Phase = decided ? SQL_CMD_APPLIED : SQL_CMD_FAILED;
  c->Status = decided ? 0 : SQL_IO;
  return sql_ctx_save(e, s);
}
int sql_command_inspect(Env *e, SQL_Session *s) {
  SQL_Command *c = &s->map.Command;
  fprintf(e->stream, "{\"sequence\":%llu,\"phase\":%u,\"status\":%u,\"verb\":",
          (unsigned long long)c->Sequence, c->Phase, c->Status);
  SQLi_json(e->stream, (unsigned char *)c->Verb, strlen(c->Verb));
  fputs(",\"cwd\":", e->stream);
  SQLi_json(e->stream, (unsigned char *)c->Cwd, strlen(c->Cwd));
  fputs(",\"sql\":", e->stream);
  SQLi_json(e->stream, (unsigned char *)c->Text, c->TextLength);
  fprintf(e->stream, ",\"lock_timeout\":%u,\"output\":%u,\"bindings\":[",
          c->LockTimeout, c->Output);
  for (unsigned i = 0; i < c->BindingCount; i++) {
    SQL_CommandBinding *b = &c->Binding[i];
    if (i)
      fputc(',', e->stream);
    fputs("{\"name\":", e->stream);
    SQLi_json(e->stream, (unsigned char *)b->Name, strlen(b->Name));
    fprintf(e->stream, ",\"type\":%u,\"length\":%u,\"hex\":\"", b->Type,
            b->Length);
    for (unsigned j = 0; j < b->Length; j++)
      fprintf(e->stream, "%02x", c->Values[b->Offset + j]);
    fputs("\"}", e->stream);
  }
  fprintf(e->stream, "],\"inputs\":%u}\n", c->InputCount);
  return 0;
}
