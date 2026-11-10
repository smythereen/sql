/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
#define STRUCT SQL_ContextEntry
static Mitem entry_items[] = {
    String_(DISPLAY_ONLY, Path, "participant logical path"),
    U64_(DISPLAY_ONLY, Generation, "snapshot generation"),
    U64_(DISPLAY_ONLY, Device, "pinned device"),
    U64_(DISPLAY_ONLY, Inode, "pinned directory inode"),
    {0}};
#undef STRUCT
#define STRUCT SQL_Ancestor
static Mitem ancestor_items[] = {
    U32_(DISPLAY_ONLY, PID, "ancestor pid"),
    U32_(DISPLAY_ONLY, Parent, "recorded parent"),
    U32_(DISPLAY_ONLY, UID, "ancestor uid"),
    U64_(DISPLAY_ONLY, Birth, "ancestor start identity"),
    {0}};
#undef STRUCT
#define STRUCT SQL_CommandBinding
static Mitem binding_items[] = {String(Name, "parameter name"),
                                U32(Type, "SQL_BindType"),
                                U32(Offset, "value byte offset"),
                                U32(Length, "exact value byte length"),
                                {0}};
#undef STRUCT
#define STRUCT SQL_CommandInput
static Mitem input_items[] = {
    U32_(DISPLAY_ONLY, Token, "captured token index"),
    U64_(DISPLAY_ONLY, Size, "complete captured bytes"),
    U64_(DISPLAY_ONLY, Hash, "integrity fingerprint"),
    U64_(DISPLAY_ONLY, Device, "owned input device"),
    U64_(DISPLAY_ONLY, Inode, "owned input inode"),
    String_(DISPLAY_ONLY, Name, "workspace-relative immutable input"),
    {0}};
#undef STRUCT
#define STRUCT SQL_Command
static Mitem command_items[] = {
    U64_(DISPLAY_ONLY, Sequence, "command sequence"),
    U32_(DISPLAY_ONLY, Phase, "durable phase"),
    U32_(DISPLAY_ONLY, Status, "last status"),
    String(Verb, "operation"),
    String(Text, "exact SQL text"),
    String(Cwd, "original cwd"),
    U32(BindingCount, "active parameter count"),
    U32(ValueLength, "aggregate value bytes"),
    U32(LockTimeout, "captured effective lock timeout"),
    U16(Output, "captured default result mode"),
    Struct(SQL_CommandBinding, Binding, binding_items),
    Struct_(DISPLAY_ONLY, SQL_CommandInput, Input, input_items),
    U32_(DISPLAY_ONLY, InputCount, "owned input count"),
    U32_(DISPLAY_ONLY, LocalTable, "local participant slot"),
    String_(DISPLAY_ONLY, Transaction, "global transaction"),
    String_(DISPLAY_ONLY, LocalTransaction, "local journal identity"),
    String_(DISPLAY_ONLY, LocalRoot, "captured local root"),
    {UNSIGNED, INPUT_ONLY, offsetof(SQL_Command, Text), 1, SQL_COMMAND_TEXT,
     "TextByte", "checked long SQL bytes", 0, 0},
    {UNSIGNED, INPUT_ONLY, offsetof(SQL_Command, Cwd), 1, PATH_MAX, "CwdByte",
     "checked original cwd bytes", 0, 0},
    {UNSIGNED, INPUT_ONLY, offsetof(SQL_Command, Values), 1, SQL_COMMAND_VALUES,
     "ValueByte", "exact parameter bytes", 0, 0},
    {0}};
#undef STRUCT
#define STRUCT SQL_ContextMap
static Mitem context_items[] = {
    U32_(DISPLAY_ONLY, magic, "context magic"),
    U32_(DISPLAY_ONLY, version, "context version"),
    U32_(DISPLAY_ONLY, bytes, "exact size"),
    U32_(DISPLAY_ONLY, endian, "byte order"),
    U32(TraceLevel, "sys Trace mask"),
    U32(LockTimeout, "lock timeout milliseconds"),
    U32(Output, "JSON=0 LINES=1 NUL=2 RAW=3"),
    U32_(DISPLAY_ONLY, State, "transaction state"),
    U32_(DISPLAY_ONLY, UID, "owner UID"),
    U32_(DISPLAY_ONLY, PID, "owner PID"),
    U64_(DISPLAY_ONLY, Birth, "verified process start identity"),
    U32_(DISPLAY_ONLY, LineageVersion, "owner ancestry format"),
    U64_(DISPLAY_ONLY, LineageHash, "bounded ancestry identity fingerprint"),
    String_(DISPLAY_ONLY, Boot, "boot identity"),
    String_(DISPLAY_ONLY, Nonce, "session nonce"),
    String_(DISPLAY_ONLY, Txid, "transaction identity"),
    String_(DISPLAY_ONLY, Root, "coordinator root"),
    U32_(DISPLAY_ONLY, Count, "participant count"),
    U32_(DISPLAY_ONLY, ReadOnly, "read only"),
    U32_(DISPLAY_ONLY, Outcome, "durable last outcome"),
    Struct_(DISPLAY_ONLY, SQL_ContextEntry, Table, entry_items),
    U32_(DISPLAY_ONLY, LineageCount, "full saved ancestry count"),
    Struct_(DISPLAY_ONLY, SQL_Ancestor, Lineage, ancestor_items),
    Struct(SQL_Command, Command, command_items),
    U32_(DISPLAY_ONLY, PriorPID, "prior owner PID"),
    U64_(DISPLAY_ONLY, PriorBirth, "prior start identity"),
    String_(DISPLAY_ONLY, PriorBoot, "prior boot"),
    String_(DISPLAY_ONLY, PriorNonce, "prior session"),
    {0}};
#undef STRUCT
static int set_config(Env *e, SQL_Session *s, const char *name,
                      const char *value) {
  uint32_t n;
  char *end;
  errno = 0;
  unsigned long long x = strtoull(value, &end, 0);
  if (!strcmp(name, "Output") &&
      (!strcasecmp(value, "JSON") || !strcasecmp(value, "LINES") ||
       !strcasecmp(value, "NUL") || !strcasecmp(value, "RAW"))) {
    n = !strcasecmp(value, "JSON")    ? 0
        : !strcasecmp(value, "LINES") ? 1
        : !strcasecmp(value, "NUL")   ? 2
                                      : 3;
  } else {
    if (!*value || *value == '-' || *end || errno || x > UINT32_MAX)
      return SQLi_fail(e, SQL_SYNTAX,
                       "configuration requires a checked uint32");
    n = x;
  }
  if (!strcmp(name, "LockTimeout")) {
    if (!n || n > 3600000)
      return SQLi_fail(e, SQL_CONSTRAINT, "LockTimeout range is 1..3600000 ms");
  } else if (!strcmp(name, "Output")) {
    if (n > 3)
      return SQLi_fail(e, SQL_CONSTRAINT, "invalid Output value");
  } else if (strcmp(name, "TraceLevel"))
    return SQLi_fail(e, SQL_SYNTAX, "unknown or immutable context variable");
  SQL_ContextMap copy = s->map;
  char number[32];
  snprintf(number, sizeof(number), "%u", n);
  Input_Memory_Item(&copy, context_items, (char *)name, number);
  uint32_t result = !strcmp(name, "TraceLevel")    ? copy.TraceLevel
                    : !strcmp(name, "LockTimeout") ? copy.LockTimeout
                                                   : copy.Output;
  if (result != n)
    return SQLi_fail(e, SQL_CONSTRAINT, "mio context conversion failed");
  s->map = copy;
  if (!strcmp(name, "TraceLevel"))
    return sql_trace_store(e, s->fd, sizeof(SQL_ContextFile),
                           offsetof(SQL_ContextFile, LiveTraceLevel), n);
  return sql_ctx_save(e, s);
}
static int set_command(Env *e, SQL_Session *s, const char *var,
                       const char *value) {
  SQL_Command *c = &s->map.Command;
  if (s->map.State != SQL_CTX_IDLE || c->Phase == SQL_CMD_ACCEPTED ||
      c->Phase == SQL_CMD_EXECUTING || c->Phase == SQL_CMD_DECIDED ||
      (c->Phase == SQL_CMD_FAILED && c->Status == SQL_COMMITTED_PENDING))
    return SQLi_fail(e, SQL_CONSTRAINT,
                     "offline command edit requires resolved idle workspace; "
                     "identity/phase cannot be forged");
  SQL_Command *copy = malloc(sizeof(*copy));
  if (!copy)
    return SQLi_fail(e, SQL_IO, "out of memory");
  *copy = *c;
  int rc = -1;
  unsigned index = 0;
  int used = 0;
  const char *text = NULL;
  char field[32] = {0};
  if (!strcmp(var, "Text") || !strcmp(var, "Verb") || !strcmp(var, "Cwd"))
    text = var;
  else if (sscanf(var, "Binding[%u].%31s%n", &index, field, &used) == 2 &&
           used == (int)strlen(var) && index < 64 && !strcmp(field, "Name"))
    text = "Name";
  if (text) {
    size_t cap = !strcmp(text, "Text")   ? sizeof(copy->Text)
                 : !strcmp(text, "Verb") ? sizeof(copy->Verb)
                 : !strcmp(text, "Cwd")  ? sizeof(copy->Cwd)
                                         : sizeof(copy->Binding[index].Name);
    if (strlen(value) >= cap) {
      SQLi_fail(e, SQL_CONSTRAINT, "command string bound");
      goto done;
    }
    if (!strcmp(text, "Text") || !strcmp(text, "Cwd")) {
      char *target = !strcmp(text, "Text") ? copy->Text : copy->Cwd;
      const char *prefix = !strcmp(text, "Text") ? "TextByte" : "CwdByte";
      memset(target, 0, cap);
      for (size_t i = 0; i < strlen(value); i++) {
        char name[64], number[16];
        snprintf(name, sizeof(name), "%s[%zu]", prefix, i);
        snprintf(number, sizeof(number), "%u", (unsigned char)value[i]);
        Input_Memory_Item(copy, command_items, name, number);
      }
      if (strcmp(target, value)) {
        SQLi_fail(e, SQL_CONSTRAINT, "mio long command conversion");
        goto done;
      }
    } else {
      Input_Memory_Item(copy, command_items, (char *)var, (char *)value);
      const char *actual = !strcmp(text, "Verb")  ? copy->Verb
                           : !strcmp(text, "Cwd") ? copy->Cwd
                                                  : copy->Binding[index].Name;
      if (strcmp(actual, value)) {
        SQLi_fail(e, SQL_CONSTRAINT, "mio command string conversion");
        goto done;
      }
    }
  } else {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(value, &end, 0);
    if (!*value || *value == '-' || errno || *end || n > UINT32_MAX) {
      SQLi_fail(e, SQL_SYNTAX, "checked command numeric value required");
      goto done;
    }
    uint32_t *word = NULL;
    uint16_t *half = NULL;
    unsigned char *byte = NULL;
    if (!strcmp(var, "LockTimeout") && n <= 3600000)
      word = &copy->LockTimeout;
    else if (!strcmp(var, "Output") && n <= 3)
      half = &copy->Output;
    else if (!strcmp(var, "BindingCount") && n <= 64)
      word = &copy->BindingCount;
    else if (!strcmp(var, "ValueLength") && n <= SQL_COMMAND_VALUES)
      word = &copy->ValueLength;
    else if (sscanf(var, "Binding[%u].%31s%n", &index, field, &used) == 2 &&
             used == (int)strlen(var) && index < 64) {
      if (!strcmp(field, "Type") && n <= SQL_BIND_NULL)
        word = &copy->Binding[index].Type;
      else if (!strcmp(field, "Offset") && n <= SQL_COMMAND_VALUES)
        word = &copy->Binding[index].Offset;
      else if (!strcmp(field, "Length") && n <= SQL_COMMAND_VALUES)
        word = &copy->Binding[index].Length;
    } else if (sscanf(var, "ValueByte[%u]%n", &index, &used) == 1 &&
               used == (int)strlen(var) && index < SQL_COMMAND_VALUES &&
               n <= 255)
      byte = &copy->Values[index];
    if (!word && !byte && !half) {
      SQLi_fail(e, SQL_SYNTAX,
                "unknown/immutable command variable or numeric bound");
      goto done;
    }
    char number[32];
    snprintf(number, sizeof(number), "%u", (unsigned)n);
    Input_Memory_Item(copy, command_items, (char *)var, number);
    if ((word && *word != n) || (byte && *byte != n) || (half && *half != n)) {
      SQLi_fail(e, SQL_CONSTRAINT, "mio command numeric conversion");
      goto done;
    }
  }
  copy->TextLength = strlen(copy->Text);
  copy->Phase = SQL_CMD_NONE;
  copy->Status = 0;
  copy->InputCount = 0;
  copy->reserved = 1;
  if (sql_command_valid(e, copy))
    goto done;
  s->map.Command = *copy;
  rc = sql_ctx_save(e, s);
done:
  free(copy);
  return rc;
}
static void command_assignment(FILE *out, const char *path, const char *name,
                               const char *value) {
  fputs("sql_ctxmem ", out);
  SQLi_shellquote(out, path);
  fprintf(out, " --offline C.Command.%s ", name);
  SQLi_shellquote(out, value);
  fputc('\n', out);
}
static void command_dump(FILE *out, SQL_Session *s) {
  SQL_Command *c = &s->map.Command;
  fprintf(
      out,
      "# Command.Sequence=%llu Phase=%u Status=%u InputCount=%u (read-only)\n",
      (unsigned long long)c->Sequence, c->Phase, c->Status, c->InputCount);
  fprintf(out, "# C.LineageCount=%u\n", s->map.LineageCount);
  for (unsigned i = 0; i < s->map.LineageCount; i++) {
    SQL_Ancestor *a = &s->map.Lineage[i];
    fprintf(out, "# C.Lineage[%u].PID=%u Parent=%u UID=%u Birth=%llu\n", i,
            a->PID, a->Parent, a->UID, (unsigned long long)a->Birth);
  }
  fprintf(out, "# C.PriorPID=%u PriorBirth=%llu\n", s->map.PriorPID,
          (unsigned long long)s->map.PriorBirth);
  for (unsigned i = 0; i < c->InputCount; i++)
    fprintf(out,
            "# C.Command.Input[%u].Name=%s Size=%llu Hash=%llu Device=%llu "
            "Inode=%llu\n",
            i, c->Input[i].Name, (unsigned long long)c->Input[i].Size,
            (unsigned long long)c->Input[i].Hash,
            (unsigned long long)c->Input[i].Device,
            (unsigned long long)c->Input[i].Inode);
  fputs("# Command replay only edits an idle offline draft; it NEVER executes "
        "SQL or replays input identities.\n",
        out);
  command_assignment(out, s->path, "BindingCount", "0");
  char number[64], name[128];
  snprintf(number, sizeof(number), "%u", c->ValueLength);
  command_assignment(out, s->path, "ValueLength", number);
  for (unsigned i = 0; i < c->ValueLength; i++) {
    snprintf(name, sizeof(name), "ValueByte[%u]", i);
    snprintf(number, sizeof(number), "%u", c->Values[i]);
    command_assignment(out, s->path, name, number);
  }
  for (unsigned i = 0; i < c->BindingCount; i++) {
    SQL_CommandBinding *b = &c->Binding[i];
    snprintf(name, sizeof(name), "Binding[%u].Name", i);
    command_assignment(out, s->path, name, b->Name);
    const char *fields[] = {"Type", "Offset", "Length"};
    uint32_t values[] = {b->Type, b->Offset, b->Length};
    for (int j = 0; j < 3; j++) {
      snprintf(name, sizeof(name), "Binding[%u].%s", i, fields[j]);
      snprintf(number, sizeof(number), "%u", values[j]);
      command_assignment(out, s->path, name, number);
    }
  }
  snprintf(number, sizeof(number), "%u", c->BindingCount);
  command_assignment(out, s->path, "BindingCount", number);
  snprintf(number, sizeof(number), "%u", c->LockTimeout);
  command_assignment(out, s->path, "LockTimeout", number);
  snprintf(number, sizeof(number), "%u", c->Output);
  command_assignment(out, s->path, "Output", number);
  command_assignment(out, s->path, "Verb", c->Verb);
  command_assignment(out, s->path, "Cwd", c->Cwd);
  command_assignment(out, s->path, "Text", c->Text);
}
int sql_ctxmem_cli(int ac, char **av) {
  int offline = ac == 5 && !strcmp(av[2], "--offline");
  if (ac != 2 && ac != 4 && !offline) {
    fprintf(stderr, "usage: sql_ctxmem context "
                    "[C.TraceLevel|C.LockTimeout|C.Output value]\n");
    return SQL_SYNTAX;
  }
  SQL_Result out = {0};
  Env e = {.out = &out};
  if (!getcwd(e.cwd, sizeof(e.cwd)))
    return SQL_IO;
  int rc = SQL_OK;
  if (ac == 4 && !strcmp(av[2], "C.TraceLevel")) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(av[3], &end, 0);
    if (!*av[3] || *av[3] == '-' || *end || errno || n > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires uint32");
      rc = e.status;
      goto done;
    }
    SQL_ContextMap copy = {0};
    char value[32];
    snprintf(value, sizeof(value), "%u", (unsigned)n);
    Input_Memory_Item(&copy, context_items, "TraceLevel", value);
    if (copy.TraceLevel != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio conversion failed");
      rc = e.status;
      goto done;
    }
    if (sql_context_trace_set(&e, av[1], copy.TraceLevel))
      rc = e.status;
    goto done;
  }
  SQL_Session *opened = malloc(sizeof(*opened));
  if (!opened) {
    rc = SQL_IO;
    goto done;
  }
  if (sql_workspace_open(&e, av[1], opened, 1, 0)) {
    sql_workspace_close(opened);
    free(opened);
    rc = e.status;
    goto done;
  }
  e.session = opened;
  SQL_Session *s = e.session;
  if (offline) {
    if (sql_lineage_state(&s->map)) {
      rc = SQL_CONSTRAINT;
      SQLi_fail(&e, SQL_CONSTRAINT,
                "RESUME stale lineage before offline edits");
      goto done;
    }
    if (strncmp(av[3], "C.Command.", 10) ||
        set_command(&e, s, av[3] + 10, av[4]))
      rc = e.status ? e.status : SQL_SYNTAX;
    goto done;
  }
  if (ac == 4) {
    if (sql_lineage_state(&s->map)) {
      SQLi_fail(&e, SQL_CONSTRAINT,
                "RESUME stale lineage before configuration edits");
      rc = e.status;
      goto done;
    }
    if (strncmp(av[2], "C.", 2) || set_config(&e, s, av[2] + 2, av[3]))
      rc = e.status ? e.status : SQL_SYNTAX;
    goto done;
  }
  fputs("#!/bin/sh\n# Read-only identity/state fields are never replayed as "
        "configuration.\n",
        stdout);
  fprintf(stdout,
          "# C.magic=%u C.version=%u C.bytes=%u C.UID=%u C.PID=%u C.Birth=%llu "
          "C.State=%u C.Count=%u C.Outcome=%u\n",
          s->map.magic, s->map.version, s->map.bytes, s->map.UID, s->map.PID,
          (unsigned long long)s->map.Birth, s->map.State, s->map.Count,
          s->map.Outcome);
  fprintf(stdout, "# C.endian=%u C.ReadOnly=%u\n", s->map.endian,
          s->map.ReadOnly);
  fprintf(stdout, "# C.LineageVersion=%u C.LineageHash=%llu\n",
          s->map.LineageVersion, (unsigned long long)s->map.LineageHash);
  const char *identity_names[] = {"Boot", "Nonce", "Txid"};
  const char *identity_values[] = {s->map.Boot, s->map.Nonce, s->map.Txid};
  for (int i = 0; i < 3; i++) {
    fprintf(stdout, "# C.%s=", identity_names[i]);
    SQLi_json(stdout, (const unsigned char *)identity_values[i],
              strlen(identity_values[i]));
    fputc('\n', stdout);
  }
  fputs("# C.Root=", stdout);
  SQLi_json(stdout, (unsigned char *)s->map.Root, strlen(s->map.Root));
  fputc('\n', stdout);
  for (unsigned i = 0; i < s->map.Count; i++) {
    fprintf(stdout, "# C.Table[%u].Path=", i);
    SQLi_json(stdout, (unsigned char *)s->map.Table[i].Path,
              strlen(s->map.Table[i].Path));
    fprintf(stdout, " Generation=%llu Device=%llu Inode=%llu\n",
            (unsigned long long)s->map.Table[i].Generation,
            (unsigned long long)s->map.Table[i].Device,
            (unsigned long long)s->map.Table[i].Inode);
  }
  const char *names[] = {"TraceLevel", "LockTimeout", "Output"};
  uint32_t values[] = {s->map.TraceLevel, s->map.LockTimeout, s->map.Output};
  for (int i = 0; i < 3; i++) {
    fputs("sql_ctxmem ", stdout);
    SQLi_shellquote(stdout, av[1]);
    fprintf(stdout, " C.%s ", names[i]);
    char value[64];
    Mio_Int_Out(value, &values[i], 4, 0, 10);
    SQLi_shellquote(stdout, value);
    fputc('\n', stdout);
  }
  command_dump(stdout, s);
  if (ferror(stdout) || fflush(stdout))
    rc = SQL_IO;
done:
  if (e.status)
    fprintf(stderr, "%s: %s\n", av[0], out.diagnostic);
  sql_session_close(&e);
  return rc;
}
static int show(Env *e, SQL_Session *s) {
  fputs("{\"context\":", e->stream);
  SQLi_json(e->stream, (unsigned char *)s->path, strlen(s->path));
  fprintf(e->stream,
          ",\"state\":%u,\"read_only\":%s,\"outcome\":%u,\"transaction\":",
          s->map.State, s->map.ReadOnly ? "true" : "false", s->map.Outcome);
  SQLi_json(e->stream, (unsigned char *)s->map.Txid, strlen(s->map.Txid));
  fputs(",\"tables\":[", e->stream);
  for (unsigned i = 0; i < s->map.Count; i++) {
    if (i)
      fputc(',', e->stream);
    SQLi_json(e->stream, (unsigned char *)s->map.Table[i].Path,
              strlen(s->map.Table[i].Path));
  }
  fputs("]}\n", e->stream);
  return 0;
}
static int clean_stage(Env *e, SQL_Session *s) {
  if (sql_tree_remove(e, s->workspace, "tables") || fsync(s->workspace))
    return SQLi_fail(e, SQL_IO, "context staged image cleanup");
  return 0;
}
int sql_workspace_remove(Env *e, SQL_Session *s) {
  if (SQLi_lockdir(e, s->root, 1))
    return -1;
  struct stat held, current;
  if (fstat(s->workspace, &held) ||
      fstatat(s->registry, s->name, &current, AT_SYMLINK_NOFOLLOW) ||
      held.st_dev != current.st_dev || held.st_ino != current.st_ino)
    return SQLi_fail(e, SQL_CONSTRAINT, "workspace identity changed");
  if (sql_tree_remove(e, s->registry, s->name) || fsync(s->registry) ||
      fsync(s->root))
    return SQLi_fail(e, SQL_IO, "remove workspace");
  s->closed = 1;
  return 0;
}
static int stale_clean(Env *e, Parser *p) {
  if (SQLi_need(e, p, "STALE") || SQLi_need(e, p, "ON"))
    return -1;
  char *path = take(e, p);
  if (!path || SQLi_end(e, p))
    return -1;
  int root = SQLi_open_dir(e, path);
  if (root < 0)
    return -1;
  if (sql_root_check(e, root)) {
    close(root);
    return -1;
  }
  int registry = sql_registry(e, root, 0);
  if (registry < 0) {
    close(root);
    return -1;
  }
  DIR *d = fdopendir(openat(registry, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  int rc = 0;
  struct dirent *de;
  if (!d) {
    close(registry);
    close(root);
    return SQLi_fail(e, SQL_IO, "scan context registry");
  }
  while ((de = readdir(d))) {
    if (de->d_name[0] == '.')
      continue;
    char rel[NAME_MAX + 32], handle[PATH_MAX];
    snprintf(rel, sizeof(rel), ".context/%s", de->d_name);
    if (SQLi_joinpath(e, handle, path, rel)) {
      rc = -1;
      break;
    }
    SQL_Session *s = malloc(sizeof(*s));
    if (!s) {
      rc = SQLi_fail(e, SQL_IO, "out of memory");
      break;
    }
    Env probe = *e;
    SQL_Result ignored = {0};
    probe.out = &ignored;
    probe.status = 0;
    if (sql_workspace_open(&probe, handle, s, 1, 1)) {
      int busy = errno == EWOULDBLOCK || errno == EAGAIN;
      sql_workspace_close(s);
      free(s);
      if (busy) {
        fprintf(e->stream, "preserved busy context %s\n", de->d_name);
        continue;
      }
      rc = SQLi_fail(e, probe.status, "%s", ignored.diagnostic);
      break;
    }
    int state = sql_lineage_state(&s->map);
    if (state == 0 || state == 1) {
      sql_workspace_close(s);
      free(s);
      continue;
    }
    if (s->map.State != SQL_CTX_IDLE ||
        s->map.Command.Phase == SQL_CMD_ACCEPTED ||
        s->map.Command.Phase == SQL_CMD_EXECUTING ||
        s->map.Command.Phase == SQL_CMD_DECIDED ||
        (s->map.Command.Phase == SQL_CMD_FAILED &&
         (s->map.Command.Status == SQL_COMMITTED_PENDING ||
          s->map.Command.InputCount))) {
      fprintf(e->stream, "preserved recoverable context %s transaction %s\n",
              de->d_name, s->map.Txid);
      sql_workspace_close(s);
      free(s);
      continue;
    }
    rc = sql_workspace_remove(e, s);
    if (!rc)
      fprintf(e->stream, "removed verified stale context %s\n", de->d_name);
    sql_workspace_close(s);
    free(s);
    if (rc)
      break;
  }
  closedir(d);
  close(registry);
  close(root);
  return rc;
}
static int session_recover(Env *e, SQL_Session *s, int change, int *outcome) {
  int quiet = e->quiet_recovery;
  e->quiet_recovery = 1;
  int rc =
      sql_coord_recover(e, s->root, s->map.Root, change, s->map.Txid, outcome);
  e->quiet_recovery = quiet;
  return rc;
}
int sql_session_cmd(Env *e, const char *cmd, Parser *p) {
  if (!strcasecmp(cmd, "context")) {
    if (SQLi_eat(p, "INSPECT")) {
      char *path = take(e, p);
      if (!path || SQLi_end(e, p))
        return -1;
      SQL_Session *s = malloc(sizeof(*s));
      if (!s)
        return SQLi_fail(e, SQL_IO, "out of memory");
      int rc = sql_workspace_open(e, path, s, 1, 0);
      if (!rc)
        rc = sql_command_inspect(e, s);
      sql_workspace_close(s);
      free(s);
      return rc;
    }
    if (SQLi_eat(p, "RESUME"))
      return sql_workspace_resume(e, p);
    if (SQLi_eat(p, "MIGRATE"))
      return sql_workspace_migrate(e, p);
    if (SQLi_eat(p, "CREATE"))
      return sql_context_create(e, p);
    if (SQLi_eat(p, "CLEAN"))
      return stale_clean(e, p);
    int showing = SQLi_eat(p, "SHOW"), setting = 0, closing = 0;
    if (!showing) {
      setting = SQLi_eat(p, "SET");
      if (!setting)
        closing = SQLi_eat(p, "CLOSE");
    }
    if (!showing && !setting && !closing)
      return SQLi_fail(e, SQL_SYNTAX,
                       "CONTEXT requires CREATE,SHOW,SET,CLOSE or CLEAN STALE");
    char *handle = NULL, *option = NULL, *value = NULL;
    if (setting) {
      char *a = take(e, p);
      if (!a)
        return -1;
      if (!SQLi_is(p, "=")) {
        handle = a;
        option = take(e, p);
      } else
        option = a;
      if (!option || SQLi_need(e, p, "="))
        return -1;
      value = take(e, p);
      if (!value)
        return -1;
    } else if (p->p < p->n && !SQLi_is(p, ";"))
      handle = take(e, p);
    if (SQLi_end(e, p) || sql_session_load(e, handle, NULL, 1))
      return -1;
    SQL_Session *s = e->session;
    if (showing)
      return show(e, s);
    if (setting) {
      const char *canonical =
          !strcasecmp(option, "OUTPUT") ? "Output"
          : !strcasecmp(option, "LOCK_TIMEOUT") ||
                  !strcasecmp(option, "LockTimeout")
              ? "LockTimeout"
          : !strcasecmp(option, "TraceLevel") || !strcasecmp(option, "TRACE")
              ? "TraceLevel"
              : option;
      return set_config(e, s, canonical, value);
    }
    if (s->map.State != SQL_CTX_IDLE)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "cannot close a context with unresolved work");
    if (SQLi_lockdir(e, s->root, 1))
      return -1;
    if (sql_workspace_remove(e, s))
      return SQLi_fail(e, SQL_IO, "close context");
    return 0;
  }
  char *handle = NULL, *root = NULL;
  int readonly = 0, mode = 0, returning = 0;
  while (p->p < p->n && !SQLi_is(p, ";")) {
    if (!strcasecmp(cmd, "begin") && SQLi_eat(p, "READ")) {
      if (mode++)
        return SQLi_fail(e, SQL_SYNTAX, "duplicate transaction mode");
      if (SQLi_eat(p, "ONLY"))
        readonly = 1;
      else if (SQLi_need(e, p, "WRITE"))
        return -1;
    } else if (!strcasecmp(cmd, "begin") && SQLi_eat(p, "ON")) {
      if (root)
        return SQLi_fail(e, SQL_SYNTAX, "duplicate coordinator");
      root = take(e, p);
      if (!root)
        return -1;
    } else if (SQLi_eat(p, "CONTEXT")) {
      if (handle)
        return SQLi_fail(e, SQL_SYNTAX, "duplicate context");
      handle = take(e, p);
      if (!handle)
        return -1;
    } else if (!strcasecmp(cmd, "commit") && SQLi_eat(p, "RETURNING")) {
      if (SQLi_need(e, p, "TRANSACTION"))
        return -1;
      returning = 1;
    } else
      return SQLi_fail(e, SQL_SYNTAX, "unexpected transaction clause");
  }
  if (SQLi_end(e, p) || sql_session_load(e, handle, root, 1))
    return -1;
  SQL_Session *s = e->session;
  if (root) {
    int fd = SQLi_open_dir(e, root);
    if (fd < 0)
      return -1;
    struct stat a, b;
    int bad = fstat(fd, &a) || fstat(s->root, &b) || a.st_dev != b.st_dev ||
              a.st_ino != b.st_ino;
    close(fd);
    if (bad)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "BEGIN coordinator differs from the checked context");
  }
  if (!strcasecmp(cmd, "begin")) {
    if (s->map.State != SQL_CTX_IDLE)
      return SQLi_fail(e, SQL_CONSTRAINT, "nested BEGIN is not allowed");
    if (clean_stage(e, s) || sql_uuid(e, s->map.Txid))
      return -1;
    s->map.State = SQL_CTX_ACTIVE;
    s->map.ReadOnly = readonly;
    s->map.Count = 0;
    s->map.Outcome = SQL_OUTCOME_NONE;
    memset(s->map.Table, 0, sizeof(s->map.Table));
    int stage = sql_stage_root(e, s, 1);
    if (stage < 0)
      return -1;
    close(stage);
    e->deferred = 1;
    return sql_ctx_save(e, s);
  }
  if (!strcasecmp(cmd, "rollback")) {
    if (s->map.State == SQL_CTX_COMMITTING)
      return SQLi_fail(e, SQL_COMMITTED_PENDING,
                       "resolve COMMIT or coordinator recovery before "
                       "ROLLBACK; committed work cannot be discarded");
    if (s->map.State != SQL_CTX_ACTIVE)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "ROLLBACK requires an active uncommitted transaction");
    char global[80];
    snprintf(global, sizeof(global), ".sql-coord.%s", s->map.Txid);
    struct stat st;
    if (!fstatat(s->root, global, &st, AT_SYMLINK_NOFOLLOW)) {
      int outcome;
      if (session_recover(e, s, 0, &outcome))
        return -1;
      if (outcome == SQL_OUTCOME_COMMITTED)
        return SQLi_fail(e, SQL_COMMITTED_PENDING,
                         "durably committed transaction cannot be rolled back");
      if (session_recover(e, s, 1, &outcome))
        return -1;
    }
    s->map.State = SQL_CTX_IDLE;
    s->map.Outcome = SQL_OUTCOME_ROLLED_BACK;
    if (sql_ctx_save(e, s))
      return -1;
    return clean_stage(e, s);
  }
  if (!strcasecmp(cmd, "commit")) {
    if (s->map.State != SQL_CTX_ACTIVE && s->map.State != SQL_CTX_COMMITTING &&
        !s->reconciled)
      return SQLi_fail(e, SQL_CONSTRAINT,
                       "COMMIT requires an active transaction");
    if (!s->reconciled && sql_coord_commit(e, s))
      return -1;
    if (clean_stage(e, s)) {
      e->status = SQL_COMMITTED_PENDING;
      return -1;
    }
    if (returning) {
      fputs("{\"transaction\":", e->stream);
      SQLi_json(e->stream, (unsigned char *)s->map.Txid, strlen(s->map.Txid));
      fputs(",\"outcome\":\"committed\"}\n", e->stream);
    }
    return 0;
  }
  return SQLi_fail(e, SQL_SYNTAX, "unknown session command");
}

int sql_ctxmem_entry(int ac, char **av) { return sql_ctxmem_cli(ac, av); }
