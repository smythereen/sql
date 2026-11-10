/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "sql_local.h"
int SQL_CLI(const char *cmd, int ac, char **av) {
  if (ac == 2 && !strcmp(av[1], "--help")) {
    printf("%s — see sql(1) and MANUAL.md for full syntax\n",
           av[0]);
    return 0;
  }
  SQL_Options o = {0};
  SQL_Binding bindings[64];
  size_t nb = 0;
  int first = 1;
  while (first < ac && !strncmp(av[first], "--", 2)) {
    if (!strcmp(av[first], "--context") && first + 1 < ac) {
      o.context = av[first + 1];
      first += 2;
    } else if (!strcmp(av[first], "--cwd") && first + 1 < ac) {
      o.cwd = av[first + 1];
      first += 2;
    } else if (!strcmp(av[first], "--lock-timeout") && first + 1 < ac) {
      char *end;
      errno = 0;
      unsigned long n = strtoul(av[first + 1], &end, 10);
      if (errno || *end || !n || n > 3600000) {
        fprintf(stderr, "invalid lock timeout (1..3600000 ms)\n");
        return SQL_SYNTAX;
      }
      o.lock_timeout_ms = n;
      first += 2;
    } else if (!strcmp(av[first], "--bind") && first + 3 < ac && nb < 64) {
      SQL_Binding *b = &bindings[nb++];
      b->name = av[first + 1];
      b->data = av[first + 3];
      b->size = strlen(b->data);
      char *t = av[first + 2];
      if (!strcasecmp(t, "TEXT"))
        b->type = SQL_BIND_TEXT;
      else if (!strcasecmp(t, "INT64"))
        b->type = SQL_BIND_INT64;
      else if (!strcasecmp(t, "UINT64"))
        b->type = SQL_BIND_UINT64;
      else if (!strcasecmp(t, "BOOL"))
        b->type = SQL_BIND_BOOL;
      else if (!strcasecmp(t, "NULL"))
        b->type = SQL_BIND_NULL;
      else {
        fprintf(stderr, "invalid binding type\n");
        return SQL_SYNTAX;
      }
      first += 4;
    } else {
      fprintf(stderr, "unknown/incomplete execution option\n");
      return SQL_SYNTAX;
    }
  }
  o.bindings = bindings;
  o.binding_count = nb;
  /* One SQL text argument has exact, lossless semantics. Do not guess how
   * shell-separated arguments should be rejoined into SQL source. */
  if (ac - first > 1) {
    fprintf(stderr, "pass the SQL statement as one quoted argument\n");
    return SQL_SYNTAX;
  }
  char *s = strdup(first < ac ? av[first] : "");
  if (!s)
    return SQL_IO;
  SQL_Result r;
  SQL_Status rc = SQL_Execute(cmd, s, &o, &r);
  free(s);
  if (rc)
    fprintf(stderr, "%s: %s\n", av[0], r.diagnostic);
  else if (r.size && fwrite(r.data, 1, r.size, stdout) != r.size)
    rc = SQL_IO;
  if (fflush(stdout) && !rc)
    rc = SQL_IO;
  SQL_Free(&r);
  return rc;
}
