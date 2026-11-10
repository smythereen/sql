/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2026 John R. Smythe Jr. */
/* Every trigger mmap is decoded through real mio descriptors; editable
 * definitions use checked byte conversion then the same logical parser. */
#include "sql_trigger_meta.h"
#define STRUCT SQL_TriggerDef
static Mitem def_items[] = {
    U32_(DISPLAY_ONLY, Used, "provisioned slot"),
    U32_(DISPLAY_ONLY, Enabled, "explicit enable state"),
    U32_(DISPLAY_ONLY, Kind, "committed event kinds"),
    U32_(DISPLAY_ONLY, Timeout, "child timeout milliseconds"),
    U32_(DISPLAY_ONLY, Retries, "bounded retries"),
    U32_(DISPLAY_ONLY, ArgCount, "fixed argv count"),
    U32_(DISPLAY_ONLY, FieldCount, "field filter count"),
    U32_(DISPLAY_ONLY, LastStatus, "last child status"),
    U64_(DISPLAY_ONLY, Checkpoint, "acknowledged generation"),
    U64_(DISPLAY_ONLY, Delivered, "acknowledged event counter"),
    U64_(DISPLAY_ONLY, Failures, "failed delivery counter"),
    U64_(DISPLAY_ONLY, ExecDevice, "pinned executable device"),
    U64_(DISPLAY_ONLY, ExecInode, "pinned executable inode"),
    String_(DISPLAY_ONLY, Name, "logical registration name"),
    String_(DISPLAY_ONLY, Nonce, "immutable registration identity"),
    String_(DISPLAY_ONLY, Exec, "literal executable path"),
    String_(DISPLAY_ONLY, LastTransaction, "last acknowledged transaction"),
    {STRING, DISPLAY_ONLY, offsetof(SQL_TriggerDef, Args), 512, 8, "Args",
     "literal argv", 0, 0},
    {STRING, DISPLAY_ONLY, offsetof(SQL_TriggerDef, Fields), 64, 16, "Fields",
     "logical field filters", 0, 0},
    String(Definition, "canonical registration"),
    {UNSIGNED, INPUT_ONLY, offsetof(SQL_TriggerDef, Definition), 1, 8192,
     "DefinitionByte", "bounded definition byte", 0, 0},
    {0}};
#undef STRUCT
#define STRUCT SQL_TriggerMap
static Mitem items[] = {U32_(DISPLAY_ONLY, Magic, "trigger map magic"),
                        U32_(DISPLAY_ONLY, Version, "trigger payload version"),
                        U32_(DISPLAY_ONLY, Bytes, "native payload bytes"),
                        U32_(DISPLAY_ONLY, UID, "owning uid"),
                        U32_(DISPLAY_ONLY, Count, "provisioned slot count"),
                        U64_(DISPLAY_ONLY, Device, "source device"),
                        U64_(DISPLAY_ONLY, Inode, "source inode"),
                        Struct(SQL_TriggerDef, Trigger, def_items),
                        {0}};
#undef STRUCT
static void comment(FILE *f, const char *name, const char *value) {
  fprintf(f, "# %s=", name);
  SQLi_json(f, (unsigned char *)value, strlen(value));
  fputc('\n', f);
}
int sql_trgmem_cli(int ac, char **av) {
  if (ac != 2 && ac != 4) {
    fprintf(stderr, "usage: sql_trgmem table [C.TraceLevel uint32 | "
                    "C.Trigger[index].Definition SQL]\n");
    return SQL_SYNTAX;
  }
  SQL_Result out = {0};
  Env e = {.out = &out};
  if (!getcwd(e.cwd, sizeof(e.cwd)))
    return SQL_IO;
  int root = SQLi_open_dir(&e, av[1]), fd = -1, rc = -1;
  SQL_TriggerMap *m = malloc(sizeof(*m));
  if (!m) {
    if (root >= 0)
      close(root);
    return SQL_IO;
  }
  if (ac == 4 && strcmp(av[2], "C.TraceLevel") &&
      (sql_session_load(&e, NULL, NULL, 0) || sql_context_active(&e))) {
    SQLi_fail(
        &e, SQL_CONSTRAINT,
        "trigger definition mem edits require no active data transaction");
    goto done;
  }
  if (root < 0 || SQLi_lockdir(&e, root, ac == 4))
    goto done;
  fd = sql_trg_open(&e, root, 0);
  if (fd < 0 || SQLi_lockdir(&e, fd, ac == 4) || sql_trg_read(&e, fd, m))
    goto done;
  if (ac == 4 && !strcmp(av[2], "C.TraceLevel")) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(av[3], &end, 0);
    if (!*av[3] || *av[3] == '-' || *end || errno || n > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires checked uint32");
      goto done;
    }
    uint32_t value = 0;
    Mitem trace_items[] = {{UNSIGNED, 0, 0, 4, 1, "TraceLevel",
                            "live shared sys Trace word", 0, 0},
                           {0}};
    char number[32];
    snprintf(number, sizeof(number), "%u", (unsigned)n);
    Input_Memory_Item(&value, trace_items, "TraceLevel", number);
    if (value != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio trace conversion failed");
      goto done;
    }
    rc = sql_trace_store(&e, fd, sizeof(SQL_TriggerFile),
                         offsetof(SQL_TriggerFile, LiveTraceLevel), value);
    goto done;
  }
  if (ac == 4) {
    unsigned slot;
    int used = 0;
    if (sscanf(av[2], "C.Trigger[%u].Definition%n", &slot, &used) != 1 ||
        used != (int)strlen(av[2]) || slot >= SQL_TRG_MAX ||
        strlen(av[3]) >= 8192) {
      SQLi_fail(&e, SQL_SYNTAX,
                "unknown/immutable trigger variable or definition bound");
      goto done;
    }
    SQL_TriggerDef *old = &m->Trigger[slot];
    if (old->Used && old->Enabled) {
      SQLi_fail(
          &e, SQL_CONSTRAINT,
          "disable registration before definition edits; checkpoint preserved");
      goto done;
    }
    SQL_TriggerDef *converted = calloc(1, sizeof(*converted));
    Parser *p = calloc(1, sizeof(*p));
    if (!converted || !p) {
      free(converted);
      free(p);
      SQLi_fail(&e, SQL_IO, "definition allocation");
      goto done;
    }
    for (size_t i = 0; i < strlen(av[3]); i++) {
      char variable[64], number[16];
      snprintf(variable, sizeof(variable), "DefinitionByte[%zu]", i);
      snprintf(number, sizeof(number), "%u", (unsigned char)av[3][i]);
      Input_Memory_Item(converted, def_items, variable, number);
    }
    SQL_TriggerDef replacement;
    char *scope = NULL;
    int bad = strcmp(converted->Definition, av[3]) ||
              SQLi_lex(&e, p, converted->Definition) ||
              SQLi_need(&e, p, "CREATE") ||
              sql_trg_parse(&e, p, &replacement, &scope);
    SQLi_parser_free(p);
    free(p);
    free(converted);
    if (bad || scope) {
      SQLi_fail(&e, SQL_CONSTRAINT,
                "invalid bounded trigger definition; ON scope cannot retarget "
                "mem edits");
      goto done;
    }
    if (sql_trg_fields(&e, root, &replacement))
      goto done;
    if (old->Used && strcmp(old->Name, replacement.Name)) {
      SQLi_fail(&e, SQL_CONSTRAINT,
                "registration name/identity cannot change through mem; "
                "DROP/CREATE explicitly");
      goto done;
    }
    if (old->Used) {
      replacement.Checkpoint = old->Checkpoint;
      replacement.Delivered = old->Delivered;
      replacement.Failures = old->Failures;
      replacement.LastStatus = old->LastStatus;
      strcpy(replacement.Nonce, old->Nonce);
      strcpy(replacement.LastTransaction, old->LastTransaction);
    } else {
      SQL_Map table;
      if (SQLi_map_read(&e, root, ".table", &table))
        goto done;
      replacement.Checkpoint = table.generation;
    }
    if (sql_trg_definition(&e, &replacement))
      goto done;
    *old = replacement;
    rc = sql_trg_save(&e, fd, m);
    goto done;
  }
  uint32_t level;
  SQL_TriggerFile *header = sql_mapping(&e, fd, sizeof(SQL_TriggerFile), 0);
  if (!header)
    goto done;
  level = header->LiveTraceLevel;
  sql_unmapping(header);
  fputs("#!/bin/sh\n# Trigger identities/checkpoints are read-only; disable "
        "live slots before replay.\n",
        stdout);
  char *statement = NULL;
  size_t length = 0;
  FILE *text = open_memstream(&statement, &length);
  if (!text) {
    SQLi_fail(&e, SQL_IO, "dump constructor buffer");
    goto done;
  }
  fputs("INIT ON '", text);
  for (const char *s = av[1]; *s; s++) {
    if (*s == '\'')
      fputc('\'', text);
    fputc(*s, text);
  }
  fputc('\'', text);
  if (fclose(text)) {
    free(statement);
    SQLi_fail(&e, SQL_IO, "dump constructor");
    goto done;
  }
  fputs("sql_trigger ", stdout);
  SQLi_shellquote(stdout, statement);
  fputc('\n', stdout);
  free(statement);
  fputs("sql_trgmem ", stdout);
  SQLi_shellquote(stdout, av[1]);
  fprintf(stdout, " C.TraceLevel '%u'\n", level);
  fprintf(stdout, "# C.Magic=%u C.Version=%u C.Bytes=%u C.UID=%u C.Count=%u\n",
          m->Magic, m->Version, m->Bytes, m->UID, m->Count);
  uint64_t skipped[SQL_TRG_MAX] = {0};
  if (sql_trg_skipped(&e, fd, m, skipped))
    memset(skipped, 0, sizeof(skipped));
  for (unsigned i = 0; i < m->Count; i++) {
    SQL_TriggerDef *d = &m->Trigger[i];
    if (!d->Used)
      continue;
    fprintf(stdout,
            "# C.Trigger[%u].Nonce=%s Checkpoint=%llu Delivered=%llu "
            "Skipped=%llu Failures=%llu LastStatus=%u\n",
            i, d->Nonce, (unsigned long long)d->Checkpoint,
            (unsigned long long)d->Delivered, (unsigned long long)skipped[i],
            (unsigned long long)d->Failures, d->LastStatus);
    char name[128];
    snprintf(name, sizeof(name), "C.Trigger[%u].LastTransaction", i);
    comment(stdout, name, d->LastTransaction);
    fputs("sql_trgmem ", stdout);
    SQLi_shellquote(stdout, av[1]);
    fprintf(stdout, " C.Trigger[%u].Definition ", i);
    SQLi_shellquote(stdout, d->Definition);
    fputc('\n', stdout);
  }
  rc = ferror(stdout) || fflush(stdout) ? SQL_IO : 0;
done:
  if (e.status)
    fprintf(stderr, "sql_trgmem: %s\n", out.diagnostic);
  (void)items;
  sql_session_close(&e);
  if (fd >= 0)
    close(fd);
  if (root >= 0)
    close(root);
  free(m);
  return e.status ? (int)e.status : rc < 0 ? (int)SQL_IO : rc;
}
