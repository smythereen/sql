/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
/* Only mutable logical/admin properties have input descriptors; immutable map
 * identity is validated before access, never rewritten by arbitrary offset. */
#define STRUCT SQL_Map
static Mitem items[] = {U32_(DISPLAY_ONLY, magic, "map identity"),
                        U32_(DISPLAY_ONLY, version, "format version"),
                        U32_(DISPLAY_ONLY, bytes, "exact map size"),
                        U32_(DISPLAY_ONLY, endian, "byte-order identity"),
                        U32_(DISPLAY_ONLY, kind, "object kind"),
                        U64_(DISPLAY_ONLY, generation, "committed generation"),
                        U32(TraceLevel, "sys Trace mask"),
                        String(DDL, "schema and link/unmatched policies"),
                        {UNSIGNED, 0, offsetof(SQL_Map, DDL), 1, DDL_SIZE,
                         "DDLByte", "checked DDL bytes", 0, 0},
                        {0}};
#undef STRUCT
int SQL_MemCLI(const char *kind, int ac, char **av) {
  if (strcmp(kind, "tblmem")) {
    fprintf(stderr, "unsupported map format\n");
    return SQL_UNSUPPORTED;
  }
  if (ac != 2 && ac != 4) {
    fprintf(stderr,
            "usage: sql_tblmem table [C.TraceLevel uint32 | C.DDL 'schema']\n");
    return SQL_SYNTAX;
  }
  SQL_Result result = {0};
  Env e = {.out = &result};
  Table t = {.fd = -1};
  if (!getcwd(e.cwd, sizeof(e.cwd)))
    return SQL_IO;
  int rc = SQL_IO;
  if (ac == 4 && !strcmp(av[2], "C.TraceLevel")) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(av[3], &end, 0);
    if (!*av[3] || *av[3] == '-' || *end || errno || n > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires uint32");
      goto done;
    }
    SQL_Map copy = {0};
    char value[32];
    snprintf(value, sizeof(value), "%u", (unsigned)n);
    Input_Memory_Item(&copy, items, "TraceLevel", value);
    if (copy.TraceLevel != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio conversion failed");
      goto done;
    }
    if (!sql_trace_object_set(&e, av[1], 0, copy.TraceLevel))
      rc = SQL_OK;
    goto done;
  }
  if (SQLi_table_open(&e, &t, av[1], ac == 4))
    goto done;
  if (ac == 2) {
    fputs("#!/bin/sh\n# Replay into an explicitly created/defined compatible "
          "table.\n",
          stdout);
    fprintf(stdout,
            "# C.magic=%u C.version=%u C.bytes=%u C.endian=%u C.kind=%u "
            "C.generation=%llu\n",
            t.map.magic, t.map.version, t.map.bytes, t.map.endian, t.map.kind,
            (unsigned long long)t.map.generation);
    fputs("sql_tblmem ", stdout);
    SQLi_shellquote(stdout, av[1]);
    fputs(" C.TraceLevel ", stdout);
    char num[64];
    Mio_Int_Out(num, &t.map.TraceLevel, 4, 0, 10);
    SQLi_shellquote(stdout, num);
    fputc('\n', stdout);
    fputs("sql_tblmem ", stdout);
    SQLi_shellquote(stdout, av[1]);
    fputs(" C.DDL ", stdout);
    SQLi_shellquote(stdout, t.map.DDL);
    fputc('\n', stdout);
    rc = SQL_OK;
    goto done;
  }
  SQL_Map copy = t.map;
  char *var = av[2];
  if (strncmp(var, "C.", 2)) {
    SQLi_fail(&e, SQL_SYNTAX, "expected C.Variable");
    goto done;
  }
  var += 2;
  if (!strcmp(var, "TraceLevel")) {
    uint32_t n;
    char *z;
    errno = 0;
    unsigned long long parsed = strtoull(av[3], &z, 0);
    if (*av[3] == '-' || !*av[3] || *z || errno || parsed > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires uint32");
      goto done;
    }
    n = parsed;
    char b[32];
    snprintf(b, sizeof(b), "%u", n);
    Input_Memory_Item(&copy, items, var, b);
    if (copy.TraceLevel != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio conversion failed");
      goto done;
    }
  } else if (!strcmp(var, "DDL")) {
    if (strlen(av[3]) >= sizeof(copy.DDL)) {
      SQLi_fail(&e, SQL_CONSTRAINT, "DDL exceeds bound");
      goto done;
    }
    Schema check = {0};
    if (SQLi_schema_text(&e, av[3], &check)) {
      SQLi_schema_free(&check);
      goto done;
    }
    SQLi_schema_free(&t.schema);
    t.schema = check;
    if (SQLi_scan_table(&e, &t, 1))
      goto done;
    /* mio's public Input_Memory_Item has a 512-byte value buffer. Use
     * bounded byte descriptors for long strings rather than overflow/truncate.
     */
    memset(copy.DDL, 0, sizeof(copy.DDL));
    for (size_t i = 0; i < strlen(av[3]); i++) {
      char variable[64], byte[16];
      snprintf(variable, sizeof(variable), "DDLByte[%zu]", i);
      snprintf(byte, sizeof(byte), "%u", (unsigned char)av[3][i]);
      Input_Memory_Item(&copy, items, variable, byte);
    }
    if (strcmp(copy.DDL, av[3])) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio string conversion failed");
      goto done;
    }
  } else {
    SQLi_fail(&e, SQL_SYNTAX, "unknown/immutable variable: %s", var);
    goto done;
  }
  if (copy.generation == UINT64_MAX) {
    SQLi_fail(&e, SQL_CONSTRAINT, "table generation exhausted");
    goto done;
  }
  copy.generation++;
  if (SQLi_map_write(&e, t.fd, ".table", &copy, 1))
    goto done;
  rc = SQL_OK;
done:
  if (e.status) {
    fprintf(stderr, "%s: %s\n", av[0], result.diagnostic);
    rc = e.status;
  }
  SQLi_table_close(&t);
  sql_session_close(&e);
  return rc;
}
