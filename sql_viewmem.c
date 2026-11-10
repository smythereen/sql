/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
#define STRUCT SQL_ViewMap
static Mitem view_items[] = {
    U32_(DISPLAY_ONLY, magic, "view magic"),
    U32_(DISPLAY_ONLY, version, "format version"),
    U32_(DISPLAY_ONLY, bytes, "exact size"),
    U32_(DISPLAY_ONLY, endian, "byte order"),
    U32_(DISPLAY_ONLY, reserved, "physical LINKED flag (version 2)"),
    U32(TraceLevel, "sys Trace mask"),
    U64_(DISPLAY_ONLY, generation, "definition generation"),
    U64_(DISPLAY_ONLY, Device, "source device"),
    U64_(DISPLAY_ONLY, Inode, "source directory inode"),
    String_(DISPLAY_ONLY, Source, "pinned canonical source"),
    String(Query, "saved SELECT clauses"),
    {UNSIGNED, 0, offsetof(SQL_ViewMap, Query), 1, DDL_SIZE, "QueryByte",
     "checked query bytes", 0, 0},
    {0}};
#undef STRUCT
int sql_viewmem_cli(int ac, char **av) {
  if (ac != 2 && ac != 4) {
    fprintf(stderr, "usage: sql_viewmem view [C.TraceLevel uint32 | C.Query "
                    "'SELECT clauses']\n");
    return SQL_SYNTAX;
  }
  Env e = {0};
  SQL_Result result = {0};
  e.out = &result;
  if (!getcwd(e.cwd, sizeof(e.cwd)))
    return SQL_IO;
  int fd = -1, rc = SQL_IO;
  SQL_ViewMap map;
  int probe = SQLi_open_dir(&e, av[1]);
  if (probe < 0)
    goto done;
  int multi = sql_multiview_kind(&e, probe);
  close(probe);
  if (multi < 0)
    goto done;
  if (multi)
    return sql_multiview_mem(ac, av);
  if (ac == 4 && !strcmp(av[2], "C.TraceLevel")) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(av[3], &end, 0);
    if (!*av[3] || *av[3] == '-' || *end || errno || n > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires uint32");
      goto done;
    }
    SQL_ViewMap copy = {0};
    char value[32];
    snprintf(value, sizeof(value), "%u", (unsigned)n);
    Input_Memory_Item(&copy, view_items, "TraceLevel", value);
    if (copy.TraceLevel != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio conversion failed");
      goto done;
    }
    if (!sql_trace_object_set(&e, av[1], 1, copy.TraceLevel))
      rc = SQL_OK;
    goto done;
  }
  if (sql_session_load(&e, NULL, NULL, 0))
    goto done;
  if (ac == 4 && sql_context_active(&e)) {
    SQLi_fail(&e, SQL_UNSUPPORTED,
              "view mem edits during transactions are not yet supported");
    goto done;
  }
  fd = SQLi_open_dir(&e, av[1]);
  if (fd < 0 || SQLi_lockdir(&e, fd, ac == 4) || sql_view_read(&e, fd, &map))
    goto done;
  if (ac == 2) {
    fputs("#!/bin/sh\n# Provision a compatible VIEW first. Pinned identity is "
          "read-only.\n",
          stdout);
    fprintf(stdout,
            "# C.magic=%u C.version=%u C.bytes=%u C.endian=%u "
            "C.generation=%llu C.Device=%llu C.Inode=%llu\n# C.Source=",
            map.magic, map.version, map.bytes, map.endian,
            (unsigned long long)map.generation, (unsigned long long)map.Device,
            (unsigned long long)map.Inode);
    SQLi_json(stdout, (unsigned char *)map.Source, strlen(map.Source));
    fputc('\n', stdout);
    fprintf(stdout,
            "# C.reserved=%u (LINKED flag); directory snapshot refreshes on "
            "SQL access\n",
            map.reserved);
    const char *names[] = {"TraceLevel", "Query"};
    char number[64];
    Mio_Int_Out(number, &map.TraceLevel, 4, 0, 10);
    const char *values[] = {number, map.Query};
    for (int i = 0; i < 2; i++) {
      fputs("sql_viewmem ", stdout);
      SQLi_shellquote(stdout, av[1]);
      fprintf(stdout, " C.%s ", names[i]);
      SQLi_shellquote(stdout, values[i]);
      fputc('\n', stdout);
    }
    rc = ferror(stdout) || fflush(stdout) ? SQL_IO : SQL_OK;
    goto done;
  }
  if (strncmp(av[2], "C.", 2)) {
    SQLi_fail(&e, SQL_SYNTAX, "expected C.Variable");
    goto done;
  }
  const char *name = av[2] + 2;
  SQL_ViewMap copy = map;
  if (!strcmp(name, "TraceLevel")) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(av[3], &end, 0);
    if (!*av[3] || *av[3] == '-' || *end || errno || n > UINT32_MAX) {
      SQLi_fail(&e, SQL_SYNTAX, "TraceLevel requires uint32");
      goto done;
    }
    char number[32];
    snprintf(number, sizeof(number), "%u", (unsigned)n);
    Input_Memory_Item(&copy, view_items, (char *)name, number);
    if (copy.TraceLevel != n) {
      SQLi_fail(&e, SQL_CONSTRAINT, "mio view conversion failed");
      goto done;
    }
  } else if (!strcmp(name, "Query")) {
    if (strlen(av[3]) >= DDL_SIZE) {
      SQLi_fail(&e, SQL_CONSTRAINT, "query bound");
      goto done;
    }
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, e.view_stack[0], PATH_MAX - 1);
    if (n < 0) {
      SQLi_fail(&e, SQL_IO, "view logical path");
      goto done;
    }
    e.view_stack[0][n] = 0;
    e.view_depth = 1;
    SQL_QueryResult *query = calloc(1, sizeof(*query));
    Parser *p = calloc(1, sizeof(*p));
    if (!query || !p) {
      free(query);
      free(p);
      SQLi_fail(&e, SQL_IO, "out of memory");
      goto done;
    }
    if (map.version == 2)
      query->linked_fd = -1;
    int failed = SQLi_lex(&e, p, av[3]) || sql_query(&e, p, query);
    SQLi_parser_free(p);
    free(p);
    if (!failed) {
      memset(copy.Query, 0, sizeof(copy.Query));
      for (size_t i = 0; i < strlen(query->query); i++) {
        char variable[64], value[16];
        snprintf(variable, sizeof(variable), "QueryByte[%zu]", i);
        snprintf(value, sizeof(value), "%u", (unsigned char)query->query[i]);
        Input_Memory_Item(&copy, view_items, variable, value);
      }
      if (strcmp(copy.Query, query->query)) {
        failed = SQLi_fail(&e, SQL_CONSTRAINT, "mio query conversion failed");
      }
      strcpy(copy.Source, query->source);
      copy.Device = query->device;
      copy.Inode = query->inode;
    }
    sql_query_free(query);
    free(query);
    if (failed)
      goto done;
  } else {
    SQLi_fail(&e, SQL_SYNTAX, "unknown/immutable view variable");
    goto done;
  }
  if (copy.generation == UINT64_MAX) {
    SQLi_fail(&e, SQL_CONSTRAINT, "view generation exhausted");
    goto done;
  }
  copy.generation++;
  if (sql_view_write(&e, fd, &copy, 1))
    goto done;
  rc = SQL_OK;
done:
  if (e.status) {
    fprintf(stderr, "%s: %s\n", av[0], result.diagnostic);
    rc = e.status;
  }
  if (fd >= 0)
    close(fd);
  sql_session_close(&e);
  return rc;
}
